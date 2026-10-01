use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

/// A detection rule: one named regular expression.
pub struct Rule {
    /// Stable machine identifier, e.g. `aws-access-key-id`.
    pub id: String,
    /// Human-readable name, as reported in findings.
    pub name: &'static str,
    pub regex: Regex,
    /// Literal substrings, at least one of which a line must contain for the
    /// regex to be able to match. Empty means "always run the regex".
    pub keywords: &'static [&'static str],
}

/// The single source of truth for built-in rules: (name, regex, keywords).
///
/// Everything else — the name → regex maps, rule ids, SARIF rule metadata —
/// is derived from this table, so adding a rule is a one-line change.
const RULE_DEFS: &[(&str, &str, &[&str])] = &[
    // AWS Patterns
    // Contextual assignment form: aws-named variable = key (quoted or bare).
    ("AWS Access Key", r#"(?i)(aws[_\s\-]?access[_\s\-]?key[_\s\-]?(id)?)["']?\s*[:=]\s*[^"'\n]*?["']?(AKIA[0-9A-Z]{16})["']?"#, &[]),
    // Bare key format: AKIA + exactly 16 uppercase alphanumerics. AWS key IDs are
    // case-sensitive; the old (?i) version reported strings that cannot be live keys.
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}\b", &[]),
    // Secret keys: aws-prefixed names or the canonical secret_access_key, quoted or bare value.
    ("AWS Secret Key", r#"(?i)(aws[_\-]?secret[a-z0-9_\-]*|secret[_\-]?access[_\-]?key)["']?\s*[:=]\s*(?:[^"'\n]*["']([A-Za-z0-9/+=]{40})["']|([A-Za-z0-9/+=]{40}))"#, &[]),

    // GitHub Patterns
    ("GitHub Token", r"\bghp_[0-9A-Za-z]{36,}", &[]),
    // OAuth/user/server/refresh tokens. (Previously a bare 40-hex regex that matched
    // every git SHA in sight.)
    ("GitHub OAuth", r"\bgh[ousr]_[0-9A-Za-z]{36,}", &[]),

    // Google Patterns
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{33,}", &[]),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", &[]),

    // JWT
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", &[]),

    // Private Keys
    ("RSA Private Key", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", &[]),
    ("EC Private Key", r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", &[]),
    ("PGP Private Key", r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----", &[]),
    ("SSH Private Key", r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", &[]),
    ("Generic Private Key", r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----", &[]),
    ("Multi-line Private Key", r"(?s)-----BEGIN[^-]+PRIVATE[^-]+-----.*?-----END[^-]+PRIVATE[^-]+-----", &[]),

    // Database URLs
    ("PostgreSQL URL", r"postgres(ql)?://[a-z0-9]+:[^@\s]+@[^\s]+", &[]),
    ("MySQL URL", r"mysql://[a-z0-9]+:[^@\s]+@[^\s]+", &[]),
    ("MongoDB URL", r"mongodb(\+srv)?://[a-z0-9]+:[^@\s]+@[^\s]+", &[]),
    ("Redis URL", r"redis://(?:[a-z0-9]+:)?[^@\s]+@[^\s]+", &[]),

    // API Keys
    ("OpenAI API Key", r"sk-[0-9A-Za-z]{32,48}", &[]),
    ("Stripe API Key", r"(sk|pk)_(test|live)_[0-9A-Za-z]{24,}", &[]),
    ("SendGrid API Key", r"SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}", &[]),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z]{10,48}", &[]),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", &[]),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", &[]),
    ("Firebase API Key", r"AIza[0-9A-Za-z\-_]{35}", &[]),
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", &[]),
    ("Heroku API Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", &[]),
    ("Discord Token", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", &[]),
    ("Shopify Token", r"shppa_[a-fA-F0-9]{32}", &[]),
    ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20}", &[]),

    // OAuth Patterns
    ("Generic OAuth Secret", r#"(?i)(oauth|client)[_\s\-]?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{32,})["']?"#, &[]),
    ("Generic Client ID", r#"(?i)(client|app)[_\s\-]?id["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#, &[]),

    // Azure Patterns
    ("Azure Tenant ID", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", &[]),
    ("Azure Client Secret", r#"(?i)azure[_\s\-]?(client[_\s\-]?)?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9~._-]{34,})["']?"#, &[]),

    // PayPal Patterns
    ("PayPal Client ID", r#"(?i)paypal[_\s\-]?client[_\s\-]?id["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#, &[]),
    ("PayPal Secret", r#"(?i)paypal[_\s\-]?secret["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#, &[]),

    // Password Patterns
    ("Password in JSON", r#"["']password["']\s*:\s*["']([^"']{8,})["']"#, &[]),
    ("Password in YAML", r"(?m)^\s*password\s*:\s*(.+)$", &[]),
    ("Password Environment Variable", r#"(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"']{8,})["']?"#, &[]),
    ("Password in URL", r"://[^:]+:([^@]{8,})@", &[]),
    ("Generic Secret", r#"(?i)(api[_\s\-]?key|secret[_\s\-]?key|auth[_\s\-]?token|access[_\s\-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#, &[]),

    // Connection Strings
    ("Connection String", r#"(?i)(connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#, &[]),
    ("Database URL", r#"(?i)database[_\s\-]?url["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#, &[]),

    // Obfuscated/Encoded Patterns
    ("Base64 Variable Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(b64|base64|encoded|enc)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{16,}={0,2})["']?"#, &[]),
    ("Hex Variable Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(hex|encoded|enc)["']?\s*[:=]\s*["']?([a-fA-F0-9]{32,})["']?"#, &[]),
    ("Suspicious Base64", r#"["']([A-Za-z0-9+/]{40,}={0,2})["']"#, &[]),
    ("Suspicious Hex", r#"["']([a-fA-F0-9]{40,})["']"#, &[]),
    ("URL Encoded Pattern", r#"(?i)(database[_\s\-]?url|db[_\s\-]?url|connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]*%[0-9A-Fa-f]{2}[^"'\s]*)["']?"#, &[]),
    ("Character Array Pattern", r"\[(?:\s*\d+\s*,?\s*){16,}\]", &[]),
    ("Split Secret Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{8,})["']?\s*\+\s*["']?([A-Za-z0-9+/]{8,})["']?"#, &[]),

    // Modern provider tokens
    ("GitHub Fine-Grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{82}", &[]),
    ("Anthropic API Key", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,}", &[]),
    ("OpenAI Project Key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}", &[]),
    ("Hugging Face Token", r"\bhf_[A-Za-z0-9]{34,}", &[]),
    ("npm Access Token", r"\bnpm_[A-Za-z0-9]{36}\b", &[]),
    ("PyPI Upload Token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", &[]),
    ("Slack App Token", r"\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{32,}", &[]),
    ("Stripe Restricted Key", r"\b(?:rk_(?:test|live)_[0-9A-Za-z]{24,}|whsec_[0-9A-Za-z]{32,})", &[]),
];

lazy_static! {
    static ref RULES: Vec<Rule> = RULE_DEFS
        .iter()
        .map(|&(name, pattern, keywords)| Rule {
            id: crate::output::rule_id(name),
            name,
            regex: Regex::new(pattern)
                .unwrap_or_else(|e| panic!("invalid regex for rule {name}: {e}")),
            keywords,
        })
        .collect();
    static ref ALL_PATTERNS: HashMap<String, &'static Regex> = RULES
        .iter()
        .map(|rule| (rule.name.to_string(), &rule.regex))
        .collect();
}

/// All built-in rules, in definition order.
pub fn rules() -> &'static [Rule] {
    &RULES
}

pub fn get_all_patterns() -> &'static HashMap<String, &'static Regex> {
    &ALL_PATTERNS
}

pub fn get_all_patterns_owned() -> HashMap<String, Regex> {
    RULES
        .iter()
        .map(|rule| (rule.name.to_string(), rule.regex.clone()))
        .collect()
}

/// Analyze base64 strings to check if they decode to known secret patterns
pub fn analyze_base64_for_secrets(b64_string: &str) -> Vec<(String, String)> {
    let mut found_secrets = Vec::new();
    
    // Try to decode base64
    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(b64_string) {
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            // Check if decoded string matches any of our secret patterns
            let patterns = get_all_patterns();
            
            for (pattern_name, pattern) in patterns {
                // Skip the obfuscated patterns to avoid recursion
                if pattern_name.contains("Base64") || pattern_name.contains("Hex") || 
                   pattern_name.contains("Suspicious") || pattern_name.contains("Character Array") {
                    continue;
                }
                
                if let Some(mat) = pattern.find(&decoded_str) {
                    found_secrets.push((
                        format!("Base64 Encoded {}", pattern_name),
                        mat.as_str().to_string()
                    ));
                }
            }
        }
    }
    
    found_secrets
}

/// Analyze hex strings to check if they decode to known secret patterns
pub fn analyze_hex_for_secrets(hex_string: &str) -> Vec<(String, String)> {
    let mut found_secrets = Vec::new();
    
    // Try to decode hex
    if let Ok(decoded_bytes) = hex::decode(hex_string) {
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            // Check if decoded string matches any of our secret patterns
            let patterns = get_all_patterns();
            
            for (pattern_name, pattern) in patterns {
                // Skip the obfuscated patterns to avoid recursion
                if pattern_name.contains("Base64") || pattern_name.contains("Hex") || 
                   pattern_name.contains("Suspicious") || pattern_name.contains("Character Array") {
                    continue;
                }
                
                if let Some(mat) = pattern.find(&decoded_str) {
                    found_secrets.push((
                        format!("Hex Encoded {}", pattern_name),
                        mat.as_str().to_string()
                    ));
                }
            }
        }
    }
    
    found_secrets
}

/// Analyze URL encoded strings to check if they contain database credentials
pub fn analyze_url_encoded_for_secrets(url_encoded_string: &str) -> Vec<(String, String)> {
    let mut found_secrets = Vec::new();
    
    // Try to decode URL encoded string
    let decoded_str = url::form_urlencoded::parse(url_encoded_string.as_bytes())
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
        
    // Check if it looks like a database URL
    if decoded_str.contains("://") && decoded_str.contains("@") {
        found_secrets.push((
            "URL Encoded Database Connection".to_string(),
            decoded_str.clone()
        ));
    }
    
    // Also try simple URL decoding
    let simple_decoded = url_encoded_string
        .replace("%3A", ":")
        .replace("%2F", "/")
        .replace("%40", "@")
        .replace("%3F", "?")
        .replace("%3D", "=")
        .replace("%26", "&");
    
    if simple_decoded != url_encoded_string {
        // Check if decoded string matches database patterns
        let patterns = get_all_patterns();
        for (pattern_name, pattern) in patterns {
            if pattern_name.contains("URL") || pattern_name.contains("Database") {
                if let Some(mat) = pattern.find(&simple_decoded) {
                    found_secrets.push((
                        format!("URL Decoded {}", pattern_name),
                        mat.as_str().to_string()
                    ));
                }
            }
        }
    }
    
    found_secrets
}

/// Analyze character arrays to check if they decode to secrets
pub fn analyze_character_array_for_secrets(char_array_str: &str) -> Vec<(String, String)> {
    let mut found_secrets = Vec::new();
    
    // Extract numbers from array format [65, 73, 122, ...]
    let numbers: Vec<u8> = char_array_str
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect();
    
    if numbers.len() > 8 {
        // Try to convert to string
        if let Ok(decoded_str) = String::from_utf8(numbers) {
            // Check if decoded string matches any of our secret patterns
            let patterns = get_all_patterns();
            
            for (pattern_name, pattern) in patterns {
                // Skip the obfuscated patterns to avoid recursion
                if pattern_name.contains("Base64") || pattern_name.contains("Hex") || 
                   pattern_name.contains("Suspicious") || pattern_name.contains("Character Array") {
                    continue;
                }
                
                if let Some(mat) = pattern.find(&decoded_str) {
                    found_secrets.push((
                        format!("Character Array Encoded {}", pattern_name),
                        mat.as_str().to_string()
                    ));
                }
            }
        }
    }
    
    found_secrets
}

/// Check if a base64 string is suspicious enough to warrant further analysis
pub fn is_suspicious_base64(b64_string: &str, context: &str) -> bool {
    let context_lower = context.to_lowercase();
    
    // Higher suspicion if in suspicious context
    let suspicious_context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential",
        "aws", "github", "google", "stripe", "config", "env", "prod", "production"
    ];
    
    let has_suspicious_context = suspicious_context.iter()
        .any(|&keyword| context_lower.contains(keyword));
    
    // Base64 characteristics
    let has_good_length = b64_string.len() >= 16;
    let has_good_chars = b64_string.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let has_padding = b64_string.ends_with('=') || b64_string.ends_with("==");
    
    has_suspicious_context && has_good_length && has_good_chars && (has_padding || b64_string.len() % 4 == 0)
}

/// Check if a hex string is suspicious enough to warrant further analysis
pub fn is_suspicious_hex(hex_string: &str, context: &str) -> bool {
    let context_lower = context.to_lowercase();
    
    // Higher suspicion if in suspicious context
    let suspicious_context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential",
        "aws", "github", "google", "stripe", "config", "env", "prod", "production"
    ];
    
    let has_suspicious_context = suspicious_context.iter()
        .any(|&keyword| context_lower.contains(keyword));
    
    // Hex characteristics
    let has_good_length = hex_string.len() >= 32;
    let is_valid_hex = hex_string.chars().all(|c| c.is_ascii_hexdigit());
    let has_even_length = hex_string.len() % 2 == 0;
    
    has_suspicious_context && has_good_length && is_valid_hex && has_even_length
}
