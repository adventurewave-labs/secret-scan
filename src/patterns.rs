use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

/// How bad it is if a finding from a rule is real.
///
/// - `Critical`: key material that grants broad access on its own (private
///   keys, AWS secret keys).
/// - `High`: a credential in a provider's exact format, or a database URL
///   with an embedded password.
/// - `Medium`: a contextual or generic match (password assignments, generic
///   secrets, JWTs, API keys that are often public by design).
/// - `Low`: identifiers and heuristics (client IDs, tenant IDs, strings that
///   merely look encoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity name, case-insensitively.
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// SARIF result level.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High | Severity::Critical => "error",
        }
    }

    /// CVSS-style score used by GitHub code scanning (`security-severity`).
    pub fn security_severity(self) -> &'static str {
        match self {
            Severity::Low => "3.0",
            Severity::Medium => "5.5",
            Severity::High => "8.0",
            Severity::Critical => "9.5",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detection rule: one named regular expression.
pub struct Rule {
    /// Stable machine identifier, e.g. `aws-access-key-id`.
    pub id: String,
    /// Human-readable name, as reported in findings.
    pub name: &'static str,
    pub regex: Regex,
    pub severity: Severity,
}

/// Severity for a finding's pattern name.
///
/// Findings recovered from an encoding ("Base64 Encoded GitHub Token",
/// "Hex Encoded …", "URL Decoded …", "Character Array Encoded …") take the
/// severity of the underlying rule. Names that match no built-in rule (custom
/// patterns) are `Medium`.
pub fn severity_for(pattern_name: &str) -> Severity {
    let base = base_rule_name(pattern_name);
    if let Some(rule) = RULES.iter().find(|rule| rule.name == base) {
        return rule.severity;
    }
    CUSTOM_SEVERITIES
        .read()
        .ok()
        .and_then(|map| map.get(base).copied())
        .unwrap_or(Severity::Medium)
}

/// The rule a finding came from, with any "… Encoded"/"… Decoded" prefix
/// removed.
pub fn base_rule_name(pattern_name: &str) -> &str {
    const PREFIXES: [&str; 4] = [
        "Base64 Encoded ",
        "Hex Encoded ",
        "URL Decoded ",
        "Character Array Encoded ",
    ];
    PREFIXES
        .iter()
        .find_map(|prefix| pattern_name.strip_prefix(prefix))
        .unwrap_or(pattern_name)
}

/// Declare the severity of a custom rule, so that [`severity_for`] reports
/// it. Built-in rules cannot be overridden this way.
pub fn register_custom_severity(name: &str, severity: Severity) {
    if let Ok(mut map) = CUSTOM_SEVERITIES.write() {
        map.insert(name.to_string(), severity);
    }
}

/// Whether `name` is one of the built-in rules.
pub fn is_builtin_rule(name: &str) -> bool {
    RULES.iter().any(|rule| rule.name == name)
}

/// The single source of truth for built-in rules: (name, regex, severity).
///
/// Everything else — the name → regex maps, rule ids, SARIF rule metadata —
/// is derived from this table, so adding a rule is a one-line change.
const RULE_DEFS: &[(&str, &str, Severity)] = &[
    // AWS Patterns
    // Contextual assignment form: aws-named variable = key (quoted or bare).
    ("AWS Access Key", r#"(?i)(aws[_\s\-]?access[_\s\-]?key[_\s\-]?(id)?)["']?\s*[:=]\s*[^"'\n]*?["']?(AKIA[0-9A-Z]{16})["']?"#, Severity::High),
    // Bare key format: AKIA + exactly 16 uppercase alphanumerics. AWS key IDs are
    // case-sensitive; the old (?i) version reported strings that cannot be live keys.
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}\b", Severity::High),
    // Secret keys: aws-prefixed names or the canonical secret_access_key, quoted or bare value.
    ("AWS Secret Key", r#"(?i)(aws[_\-]?secret[a-z0-9_\-]*|secret[_\-]?access[_\-]?key)["']?\s*[:=]\s*(?:[^"'\n]*["']([A-Za-z0-9/+=]{40})["']|([A-Za-z0-9/+=]{40}))"#, Severity::Critical),

    // GitHub Patterns
    ("GitHub Token", r"\bghp_[0-9A-Za-z]{36,}", Severity::High),
    // OAuth/user/server/refresh tokens. (Previously a bare 40-hex regex that matched
    // every git SHA in sight.)
    ("GitHub OAuth", r"\bgh[ousr]_[0-9A-Za-z]{36,}", Severity::High),

    // Google Patterns
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{33,}", Severity::Medium),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", Severity::Low),

    // JWT
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", Severity::Medium),

    // Private Keys
    ("RSA Private Key", r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----", Severity::Critical),
    ("EC Private Key", r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", Severity::Critical),
    ("PGP Private Key", r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----", Severity::Critical),
    ("SSH Private Key", r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", Severity::Critical),
    // Any PEM private-key header, including unlabelled PKCS#8
    // ("BEGIN PRIVATE KEY"), DSA and ENCRYPTED. Shadowed by the specific
    // rules above when one of them matches the same line.
    ("Generic Private Key", r"-----BEGIN\s+(?:[A-Z]+\s+)*PRIVATE\s+KEY(?:\s+BLOCK)?-----", Severity::Critical),
    ("Multi-line Private Key", r"(?s)-----BEGIN[^-]+PRIVATE[^-]+-----.*?-----END[^-]+PRIVATE[^-]+-----", Severity::Critical),

    // Database URLs
    ("PostgreSQL URL", r"postgres(ql)?://[a-z0-9]+:[^@\s]+@[^\s]+", Severity::High),
    ("MySQL URL", r"mysql://[a-z0-9]+:[^@\s]+@[^\s]+", Severity::High),
    ("MongoDB URL", r"mongodb(\+srv)?://[a-z0-9]+:[^@\s]+@[^\s]+", Severity::High),
    ("Redis URL", r"redis://(?:[a-z0-9]+:)?[^@\s]+@[^\s]+", Severity::High),

    // API Keys
    ("OpenAI API Key", r"sk-[0-9A-Za-z]{32,48}", Severity::High),
    ("Stripe API Key", r"(sk|pk)_(test|live)_[0-9A-Za-z]{24,}", Severity::High),
    ("SendGrid API Key", r"SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}", Severity::High),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z]{10,48}", Severity::High),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", Severity::High),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", Severity::High),
    ("Firebase API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity::Medium),
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", Severity::High),
    ("Heroku API Key", r#"(?i)\bheroku[a-z0-9_.\-]{0,24}["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, Severity::High),
    ("Discord Token", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", Severity::High),
    ("Shopify Token", r"shppa_[a-fA-F0-9]{32}", Severity::High),
    ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20}", Severity::High),

    // OAuth Patterns
    ("Generic OAuth Secret", r#"(?i)(oauth|client)[_\s\-]?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{32,})["']?"#, Severity::Medium),
    ("Generic Client ID", r#"(?i)(client|app)[_\s\-]?id["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#, Severity::Low),

    // Azure Patterns
    // A bare UUID is not a credential. These two rules used to match every
    // UUID in a codebase; they now require the provider's name in the
    // variable being assigned.
    ("Azure Tenant ID", r#"(?i)\b(?:azure|aad|arm)[a-z0-9_.\-]{0,24}tenant[a-z0-9_.\-]{0,8}["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, Severity::Low),
    ("Azure Client Secret", r#"(?i)azure[_\s\-]?(client[_\s\-]?)?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9~._-]{34,})["']?"#, Severity::High),

    // PayPal Patterns
    ("PayPal Client ID", r#"(?i)paypal[_\s\-]?client[_\s\-]?id["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#, Severity::Low),
    ("PayPal Secret", r#"(?i)paypal[_\s\-]?secret["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#, Severity::High),

    // Password Patterns
    ("Password in JSON", r#"["']password["']\s*:\s*["']([^"']{8,})["']"#, Severity::Medium),
    ("Password in YAML", r"(?m)^\s*password\s*:\s*(.+)$", Severity::Medium),
    ("Password Environment Variable", r#"(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"']{8,})["']?"#, Severity::Medium),
    ("Password in URL", r"://[^:]+:([^@]{8,})@", Severity::Medium),
    ("Generic Secret", r#"(?i)(api[_\s\-]?key|secret[_\s\-]?key|auth[_\s\-]?token|access[_\s\-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#, Severity::Medium),

    // Connection Strings
    ("Connection String", r#"(?i)(connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#, Severity::Medium),
    ("Database URL", r#"(?i)database[_\s\-]?url["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#, Severity::Medium),

    // Obfuscated/Encoded Patterns
    ("Base64 Variable Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(b64|base64|encoded|enc)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{16,}={0,2})["']?"#, Severity::Medium),
    ("Hex Variable Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(hex|encoded|enc)["']?\s*[:=]\s*["']?([a-fA-F0-9]{32,})["']?"#, Severity::Medium),
    ("Suspicious Base64", r#"["']([A-Za-z0-9+/]{40,}={0,2})["']"#, Severity::Low),
    ("Suspicious Hex", r#"["']([a-fA-F0-9]{40,})["']"#, Severity::Low),
    ("URL Encoded Pattern", r#"(?i)(database[_\s\-]?url|db[_\s\-]?url|connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]*%[0-9A-Fa-f]{2}[^"'\s]*)["']?"#, Severity::Medium),
    ("Character Array Pattern", r"\[(?:\s*\d+\s*,?\s*){16,}\]", Severity::Low),
    ("Split Secret Pattern", r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{8,})["']?\s*\+\s*["']?([A-Za-z0-9+/]{8,})["']?"#, Severity::Medium),

    // Modern provider tokens
    ("GitHub Fine-Grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{82}", Severity::High),
    ("Anthropic API Key", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,}", Severity::High),
    ("OpenAI Project Key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}", Severity::High),
    ("Hugging Face Token", r"\bhf_[A-Za-z0-9]{34,}", Severity::High),
    ("npm Access Token", r"\bnpm_[A-Za-z0-9]{36}\b", Severity::High),
    ("PyPI Upload Token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", Severity::High),
    ("Slack App Token", r"\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{32,}", Severity::High),
    ("Stripe Restricted Key", r"\b(?:rk_(?:test|live)_[0-9A-Za-z]{24,}|whsec_[0-9A-Za-z]{32,})", Severity::High),

    // More providers. Prefix-anchored formats first; the last four have no
    // distinctive prefix and require the provider name in the variable.
    ("Azure Storage Account Key", r"\bAccountKey=[A-Za-z0-9+/]{86}==", Severity::High),
    ("Databricks Token", r"\bdapi[a-f0-9]{32}(?:-[0-9])?\b", Severity::High),
    ("Supabase Access Token", r"\bsbp_[a-f0-9]{40}\b", Severity::High),
    ("Telegram Bot Token", r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b", Severity::High),
    ("Postman API Key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", Severity::High),
    ("Linear API Key", r"\blin_api_[A-Za-z0-9]{40}\b", Severity::High),
    ("Notion Token", r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b", Severity::High),
    ("Doppler Token", r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b", Severity::High),
    ("Docker Hub Token", r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b", Severity::High),
    ("Grafana Service Account Token", r"\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b", Severity::High),
    ("Age Secret Key", r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b", Severity::Critical),
    // Marks a Google Cloud service-account credentials file; the key inside
    // it is reported separately by the private-key rules.
    ("GCP Service Account", r#""type"\s*:\s*"service_account""#, Severity::Medium),
    ("Datadog API Key", r#"(?i)\b(?:datadog|dd)[a-z0-9_.\-]{0,16}(?:api|app)[a-z0-9_.\-]{0,12}key["']?\s*[:=]\s*["']?[a-f0-9]{32}(?:[a-f0-9]{8})?\b"#, Severity::High),
    ("Cloudflare API Token", r#"(?i)\bcloudflare[a-z0-9_.\-]{0,24}["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{37,40}\b"#, Severity::High),
    ("Vercel Token", r#"(?i)\bvercel[a-z0-9_.\-]{0,24}token["']?\s*[:=]\s*["']?[A-Za-z0-9]{24}\b"#, Severity::High),
];

lazy_static! {
    static ref RULES: Vec<Rule> = RULE_DEFS
        .iter()
        .map(|&(name, pattern, severity)| Rule {
            id: crate::output::rule_id(name),
            name,
            regex: Regex::new(pattern)
                .unwrap_or_else(|e| panic!("invalid regex for rule {name}: {e}")),
            severity,
        })
        .collect();
    static ref CUSTOM_SEVERITIES: std::sync::RwLock<HashMap<String, Severity>> =
        std::sync::RwLock::new(HashMap::new());
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
