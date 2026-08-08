use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

lazy_static! {
    // AWS Patterns
    // Contextual assignment form: aws-named variable = key (quoted or bare).
    static ref AWS_ACCESS_KEY: Regex = Regex::new(r#"(?i)(aws[_\s\-]?access[_\s\-]?key[_\s\-]?(id)?)["']?\s*[:=]\s*[^"'\n]*?["']?(AKIA[0-9A-Z]{16})["']?"#).unwrap();
    // Secret keys: aws-prefixed names or the canonical secret_access_key, quoted or bare value.
    static ref AWS_SECRET_KEY: Regex = Regex::new(r#"(?i)(aws[_\-]?secret[a-z0-9_\-]*|secret[_\-]?access[_\-]?key)["']?\s*[:=]\s*(?:[^"'\n]*["']([A-Za-z0-9/+=]{40})["']|([A-Za-z0-9/+=]{40}))"#).unwrap();
    // Bare key format: AKIA + exactly 16 uppercase alphanumerics. AWS key IDs are
    // case-sensitive; the old (?i) version reported strings that cannot be live keys.
    static ref AWS_ACCESS_KEY_ID: Regex = Regex::new(r"AKIA[0-9A-Z]{16}\b").unwrap();
    
    // GitHub Patterns
    static ref GITHUB_TOKEN: Regex = Regex::new(r"\bghp_[0-9A-Za-z]{36,}").unwrap();
    // OAuth/user/server/refresh tokens. (Previously a bare 40-hex regex that matched
    // every git SHA in sight.)
    static ref GITHUB_OAUTH: Regex = Regex::new(r"\bgh[ousr]_[0-9A-Za-z]{36,}").unwrap();
    
    // Google Patterns
    static ref GOOGLE_API_KEY: Regex = Regex::new(r"\bAIza[0-9A-Za-z\-_]{33,}").unwrap();
    static ref GOOGLE_OAUTH: Regex = Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap();
    
    // JWT Pattern
    static ref JWT_TOKEN: Regex = Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap();
    
    // Private Key Patterns
    static ref RSA_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----").unwrap();
    static ref EC_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----").unwrap();
    static ref PGP_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----").unwrap();
    static ref SSH_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----").unwrap();
    static ref GENERIC_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----").unwrap();
    
    // Database URLs
    static ref POSTGRES_URL: Regex = Regex::new(r"postgres(ql)?://[a-z0-9]+:[^@\s]+@[^\s]+").unwrap();
    static ref MYSQL_URL: Regex = Regex::new(r"mysql://[a-z0-9]+:[^@\s]+@[^\s]+").unwrap();
    static ref MONGODB_URL: Regex = Regex::new(r"mongodb(\+srv)?://[a-z0-9]+:[^@\s]+@[^\s]+").unwrap();
    static ref REDIS_URL: Regex = Regex::new(r"redis://(?:[a-z0-9]+:)?[^@\s]+@[^\s]+").unwrap();
    
    // API Keys
    static ref OPENAI_API_KEY: Regex = Regex::new(r"sk-[0-9A-Za-z]{32,48}").unwrap();
    static ref STRIPE_API_KEY: Regex = Regex::new(r"(sk|pk)_(test|live)_[0-9A-Za-z]{24,}").unwrap();
    static ref SENDGRID_API_KEY: Regex = Regex::new(r"SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}").unwrap();
    static ref SLACK_TOKEN: Regex = Regex::new(r"xox[baprs]-[0-9A-Za-z]{10,48}").unwrap();
    static ref TWILIO_API_KEY: Regex = Regex::new(r"SK[0-9a-fA-F]{32}").unwrap();
    static ref MAILGUN_API_KEY: Regex = Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap();
    static ref FIREBASE_API_KEY: Regex = Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap();
    
    // OAuth Patterns
    static ref GENERIC_OAUTH_SECRET: Regex = Regex::new(r#"(?i)(oauth|client)[_\s\-]?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{32,})["']?"#).unwrap();
    static ref GENERIC_CLIENT_ID: Regex = Regex::new(r#"(?i)(client|app)[_\s\-]?id["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#).unwrap();
    
    // Azure Patterns
    static ref AZURE_TENANT_ID: Regex = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    static ref AZURE_CLIENT_SECRET: Regex = Regex::new(r#"(?i)azure[_\s\-]?(client[_\s\-]?)?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9~._-]{34,})["']?"#).unwrap();
    
    // PayPal Patterns
    static ref PAYPAL_CLIENT_ID: Regex = Regex::new(r#"(?i)paypal[_\s\-]?client[_\s\-]?id["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#).unwrap();
    static ref PAYPAL_SECRET: Regex = Regex::new(r#"(?i)paypal[_\s\-]?secret["']?\s*[:=]\s*["']?([A-Za-z0-9-_]{60,})["']?"#).unwrap();
    
    // Password Patterns (Context-Aware)
    static ref PASSWORD_IN_JSON: Regex = Regex::new(r#"["']password["']\s*:\s*["']([^"']{8,})["']"#).unwrap();
    static ref PASSWORD_IN_YAML: Regex = Regex::new(r"(?m)^\s*password\s*:\s*(.+)$").unwrap();
    static ref PASSWORD_ENV_VAR: Regex = Regex::new(r#"(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"']{8,})["']?"#).unwrap();
    static ref PASSWORD_IN_URL: Regex = Regex::new(r"://[^:]+:([^@]{8,})@").unwrap();
    static ref GENERIC_SECRET: Regex = Regex::new(r#"(?i)(api[_\s\-]?key|secret[_\s\-]?key|auth[_\s\-]?token|access[_\s\-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?"#).unwrap();
    
    // Connection String Patterns
    static ref CONNECTION_STRING: Regex = Regex::new(r#"(?i)(connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#).unwrap();
    static ref DATABASE_URL: Regex = Regex::new(r#"(?i)database[_\s\-]?url["']?\s*[:=]\s*["']?([^"'\s]+)["']?"#).unwrap();
    
    // Private Keys (Multi-line support)
    static ref MULTILINE_PRIVATE_KEY: Regex = Regex::new(r"(?s)-----BEGIN[^-]+PRIVATE[^-]+-----.*?-----END[^-]+PRIVATE[^-]+-----").unwrap();
    
    // API Tokens
    static ref DIGITALOCEAN_TOKEN: Regex = Regex::new(r"dop_v1_[a-f0-9]{64}").unwrap();
    static ref HEROKU_API_KEY: Regex = Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap();
    static ref DISCORD_TOKEN: Regex = Regex::new(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}").unwrap();
    static ref SHOPIFY_TOKEN: Regex = Regex::new(r"shppa_[a-fA-F0-9]{32}").unwrap();
    static ref GITLAB_TOKEN: Regex = Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap();
    
    // Obfuscated/Encoded Secret Patterns
    static ref BASE64_VARIABLE_PATTERN: Regex = Regex::new(r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(b64|base64|encoded|enc)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{16,}={0,2})["']?"#).unwrap();
    static ref HEX_VARIABLE_PATTERN: Regex = Regex::new(r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential|aws[_\s\-]?access|aws[_\s\-]?secret|github[_\s\-]?token|stripe[_\s\-]?key)[_\s\-]*(hex|encoded|enc)["']?\s*[:=]\s*["']?([a-fA-F0-9]{32,})["']?"#).unwrap();
    static ref SUSPICIOUS_BASE64: Regex = Regex::new(r#"["']([A-Za-z0-9+/]{40,}={0,2})["']"#).unwrap();
    static ref SUSPICIOUS_HEX: Regex = Regex::new(r#"["']([a-fA-F0-9]{40,})["']"#).unwrap();
    static ref URL_ENCODED_PATTERN: Regex = Regex::new(r#"(?i)(database[_\s\-]?url|db[_\s\-]?url|connection[_\s\-]?string|conn[_\s\-]?str)["']?\s*[:=]\s*["']?([^"'\s]*%[0-9A-Fa-f]{2}[^"'\s]*)["']?"#).unwrap();
    static ref CHARACTER_ARRAY_PATTERN: Regex = Regex::new(r"\[(?:\s*\d+\s*,?\s*){16,}\]").unwrap();
    static ref SPLIT_SECRET_PATTERN: Regex = Regex::new(r#"(?i)(api[_\s\-]?key|secret|token|password|pass|auth|credential)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{8,})["']?\s*\+\s*["']?([A-Za-z0-9+/]{8,})["']?"#).unwrap();
    static ref ALL_PATTERNS: HashMap<String, &'static Regex> = {
        let mut patterns = HashMap::new();
        // AWS Patterns
        patterns.insert("AWS Access Key".to_string(), &*AWS_ACCESS_KEY);
        patterns.insert("AWS Access Key ID".to_string(), &*AWS_ACCESS_KEY_ID);
        patterns.insert("AWS Secret Key".to_string(), &*AWS_SECRET_KEY);
        
        // GitHub Patterns
        patterns.insert("GitHub Token".to_string(), &*GITHUB_TOKEN);
        patterns.insert("GitHub OAuth".to_string(), &*GITHUB_OAUTH);
        
        // Google Patterns
        patterns.insert("Google API Key".to_string(), &*GOOGLE_API_KEY);
        patterns.insert("Google OAuth".to_string(), &*GOOGLE_OAUTH);
        
        // JWT
        patterns.insert("JWT Token".to_string(), &*JWT_TOKEN);
        
        // Private Keys
        patterns.insert("RSA Private Key".to_string(), &*RSA_PRIVATE_KEY);
        patterns.insert("EC Private Key".to_string(), &*EC_PRIVATE_KEY);
        patterns.insert("PGP Private Key".to_string(), &*PGP_PRIVATE_KEY);
        patterns.insert("SSH Private Key".to_string(), &*SSH_PRIVATE_KEY);
        patterns.insert("Generic Private Key".to_string(), &*GENERIC_PRIVATE_KEY);
        patterns.insert("Multi-line Private Key".to_string(), &*MULTILINE_PRIVATE_KEY);
        
        // Database URLs
        patterns.insert("PostgreSQL URL".to_string(), &*POSTGRES_URL);
        patterns.insert("MySQL URL".to_string(), &*MYSQL_URL);
        patterns.insert("MongoDB URL".to_string(), &*MONGODB_URL);
        patterns.insert("Redis URL".to_string(), &*REDIS_URL);
        
        // API Keys
        patterns.insert("OpenAI API Key".to_string(), &*OPENAI_API_KEY);
        patterns.insert("Stripe API Key".to_string(), &*STRIPE_API_KEY);
        patterns.insert("SendGrid API Key".to_string(), &*SENDGRID_API_KEY);
        patterns.insert("Slack Token".to_string(), &*SLACK_TOKEN);
        patterns.insert("Twilio API Key".to_string(), &*TWILIO_API_KEY);
        patterns.insert("Mailgun API Key".to_string(), &*MAILGUN_API_KEY);
        patterns.insert("Firebase API Key".to_string(), &*FIREBASE_API_KEY);
        patterns.insert("DigitalOcean Token".to_string(), &*DIGITALOCEAN_TOKEN);
        patterns.insert("Heroku API Key".to_string(), &*HEROKU_API_KEY);
        patterns.insert("Discord Token".to_string(), &*DISCORD_TOKEN);
        patterns.insert("Shopify Token".to_string(), &*SHOPIFY_TOKEN);
        patterns.insert("GitLab Token".to_string(), &*GITLAB_TOKEN);
        
        // OAuth Patterns
        patterns.insert("Generic OAuth Secret".to_string(), &*GENERIC_OAUTH_SECRET);
        patterns.insert("Generic Client ID".to_string(), &*GENERIC_CLIENT_ID);
        
        // Azure Patterns
        patterns.insert("Azure Tenant ID".to_string(), &*AZURE_TENANT_ID);
        patterns.insert("Azure Client Secret".to_string(), &*AZURE_CLIENT_SECRET);
        
        // PayPal Patterns
        patterns.insert("PayPal Client ID".to_string(), &*PAYPAL_CLIENT_ID);
        patterns.insert("PayPal Secret".to_string(), &*PAYPAL_SECRET);
        
        // Password Patterns
        patterns.insert("Password in JSON".to_string(), &*PASSWORD_IN_JSON);
        patterns.insert("Password in YAML".to_string(), &*PASSWORD_IN_YAML);
        patterns.insert("Password Environment Variable".to_string(), &*PASSWORD_ENV_VAR);
        patterns.insert("Password in URL".to_string(), &*PASSWORD_IN_URL);
        patterns.insert("Generic Secret".to_string(), &*GENERIC_SECRET);
        
        // Connection Strings
        patterns.insert("Connection String".to_string(), &*CONNECTION_STRING);
        patterns.insert("Database URL".to_string(), &*DATABASE_URL);
        
        // Obfuscated/Encoded Patterns
        patterns.insert("Base64 Variable Pattern".to_string(), &*BASE64_VARIABLE_PATTERN);
        patterns.insert("Hex Variable Pattern".to_string(), &*HEX_VARIABLE_PATTERN);
        patterns.insert("Suspicious Base64".to_string(), &*SUSPICIOUS_BASE64);
        patterns.insert("Suspicious Hex".to_string(), &*SUSPICIOUS_HEX);
        patterns.insert("URL Encoded Pattern".to_string(), &*URL_ENCODED_PATTERN);
        patterns.insert("Character Array Pattern".to_string(), &*CHARACTER_ARRAY_PATTERN);
        patterns.insert("Split Secret Pattern".to_string(), &*SPLIT_SECRET_PATTERN);
        
        patterns
    };
}

pub fn get_all_patterns() -> &'static HashMap<String, &'static Regex> {
    &ALL_PATTERNS
}

pub fn get_all_patterns_owned() -> HashMap<String, Regex> {
    let mut patterns = HashMap::new();
    // AWS Patterns
    patterns.insert("AWS Access Key".to_string(), AWS_ACCESS_KEY.clone());
    patterns.insert("AWS Access Key ID".to_string(), AWS_ACCESS_KEY_ID.clone());
    patterns.insert("AWS Secret Key".to_string(), AWS_SECRET_KEY.clone());
    
    // GitHub Patterns
    patterns.insert("GitHub Token".to_string(), GITHUB_TOKEN.clone());
    patterns.insert("GitHub OAuth".to_string(), GITHUB_OAUTH.clone());
    
    // Google Patterns
    patterns.insert("Google API Key".to_string(), GOOGLE_API_KEY.clone());
    patterns.insert("Google OAuth".to_string(), GOOGLE_OAUTH.clone());
    
    // JWT
    patterns.insert("JWT Token".to_string(), JWT_TOKEN.clone());
    
    // Private Keys
    patterns.insert("RSA Private Key".to_string(), RSA_PRIVATE_KEY.clone());
    patterns.insert("EC Private Key".to_string(), EC_PRIVATE_KEY.clone());
    patterns.insert("PGP Private Key".to_string(), PGP_PRIVATE_KEY.clone());
    patterns.insert("SSH Private Key".to_string(), SSH_PRIVATE_KEY.clone());
    patterns.insert("Generic Private Key".to_string(), GENERIC_PRIVATE_KEY.clone());
    patterns.insert("Multi-line Private Key".to_string(), MULTILINE_PRIVATE_KEY.clone());
    
    // Database URLs
    patterns.insert("PostgreSQL URL".to_string(), POSTGRES_URL.clone());
    patterns.insert("MySQL URL".to_string(), MYSQL_URL.clone());
    patterns.insert("MongoDB URL".to_string(), MONGODB_URL.clone());
    patterns.insert("Redis URL".to_string(), REDIS_URL.clone());
    
    // API Keys
    patterns.insert("OpenAI API Key".to_string(), OPENAI_API_KEY.clone());
    patterns.insert("Stripe API Key".to_string(), STRIPE_API_KEY.clone());
    patterns.insert("SendGrid API Key".to_string(), SENDGRID_API_KEY.clone());
    patterns.insert("Slack Token".to_string(), SLACK_TOKEN.clone());
    patterns.insert("Twilio API Key".to_string(), TWILIO_API_KEY.clone());
    patterns.insert("Mailgun API Key".to_string(), MAILGUN_API_KEY.clone());
    patterns.insert("Firebase API Key".to_string(), FIREBASE_API_KEY.clone());
    patterns.insert("DigitalOcean Token".to_string(), DIGITALOCEAN_TOKEN.clone());
    patterns.insert("Heroku API Key".to_string(), HEROKU_API_KEY.clone());
    patterns.insert("Discord Token".to_string(), DISCORD_TOKEN.clone());
    patterns.insert("Shopify Token".to_string(), SHOPIFY_TOKEN.clone());
    patterns.insert("GitLab Token".to_string(), GITLAB_TOKEN.clone());
    
    // OAuth Patterns
    patterns.insert("Generic OAuth Secret".to_string(), GENERIC_OAUTH_SECRET.clone());
    patterns.insert("Generic Client ID".to_string(), GENERIC_CLIENT_ID.clone());
    
    // Azure Patterns
    patterns.insert("Azure Tenant ID".to_string(), AZURE_TENANT_ID.clone());
    patterns.insert("Azure Client Secret".to_string(), AZURE_CLIENT_SECRET.clone());
    
    // PayPal Patterns
    patterns.insert("PayPal Client ID".to_string(), PAYPAL_CLIENT_ID.clone());
    patterns.insert("PayPal Secret".to_string(), PAYPAL_SECRET.clone());
    
    // Password Patterns
    patterns.insert("Password in JSON".to_string(), PASSWORD_IN_JSON.clone());
    patterns.insert("Password in YAML".to_string(), PASSWORD_IN_YAML.clone());
    patterns.insert("Password Environment Variable".to_string(), PASSWORD_ENV_VAR.clone());
    patterns.insert("Password in URL".to_string(), PASSWORD_IN_URL.clone());
    patterns.insert("Generic Secret".to_string(), GENERIC_SECRET.clone());
    
    // Connection Strings
    patterns.insert("Connection String".to_string(), CONNECTION_STRING.clone());
    patterns.insert("Database URL".to_string(), DATABASE_URL.clone());
    
    // Obfuscated/Encoded Patterns
    patterns.insert("Base64 Variable Pattern".to_string(), BASE64_VARIABLE_PATTERN.clone());
    patterns.insert("Hex Variable Pattern".to_string(), HEX_VARIABLE_PATTERN.clone());
    patterns.insert("Suspicious Base64".to_string(), SUSPICIOUS_BASE64.clone());
    patterns.insert("Suspicious Hex".to_string(), SUSPICIOUS_HEX.clone());
    patterns.insert("URL Encoded Pattern".to_string(), URL_ENCODED_PATTERN.clone());
    patterns.insert("Character Array Pattern".to_string(), CHARACTER_ARRAY_PATTERN.clone());
    patterns.insert("Split Secret Pattern".to_string(), SPLIT_SECRET_PATTERN.clone());
    
    patterns
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
