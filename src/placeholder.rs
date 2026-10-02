//! Placeholder detection for the generic, context-based rules.
//!
//! Rules such as "Generic Secret" or "Password Environment Variable" match an
//! assignment by the *name* of the variable, so they also match documentation
//! and templates: `password = "changeme"`, `api_key: <your-api-key>`,
//! `SECRET_KEY=${SECRET_KEY}`. Those values are not secrets. Format-exact
//! rules (provider tokens, private keys) are never filtered here: a string in
//! a provider's exact format is reported even if it says EXAMPLE.

/// Built-in rules whose matched value is checked for placeholders.
const CHECKED_RULES: [&str; 13] = [
    "Generic Secret",
    "Generic OAuth Secret",
    "Generic Client ID",
    "Password in JSON",
    "Password in YAML",
    "Password Environment Variable",
    "Password in URL",
    "Connection String",
    "Database URL",
    "Base64 Variable Pattern",
    "Hex Variable Pattern",
    "Azure Client Secret",
    "PayPal Secret",
];

/// Substrings that mark a value as a stand-in.
const STOPWORDS: [&str; 22] = [
    "example",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "your_",
    "your-",
    "yourpassword",
    "yoursecret",
    "yourkey",
    "yourtoken",
    "xxxx",
    "redacted",
    "dummy",
    "sample",
    "insert",
    "replace",
    "todo",
    "fixme",
    "foobar",
    "****",
    "....",
];

/// Whole values that are never a secret.
const NON_VALUES: [&str; 14] = [
    "null", "none", "nil", "true", "false", "undefined", "empty", "password", "passwd", "secret",
    "token", "string", "value", "test",
];

/// Whether placeholder filtering applies to findings from `rule_name`.
pub fn applies_to(rule_name: &str) -> bool {
    CHECKED_RULES.contains(&rule_name)
}

/// Whether `value` is a stand-in rather than a real secret.
pub fn is_placeholder(value: &str) -> bool {
    let trimmed = value.trim_matches(|c: char| c.is_whitespace() || "\"'`,;".contains(c));
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_lowercase();

    // <your-key>, {{ secret }}, ${VAR}, $VAR, %(name)s, %VAR%
    let templated = (lower.starts_with('<') && lower.ends_with('>'))
        || lower.contains("{{")
        || lower.contains("${")
        || lower.contains("%(")
        || (lower.starts_with('$') && lower.len() > 1)
        || (lower.starts_with('%') && lower.ends_with('%') && lower.len() > 2);
    if templated {
        return true;
    }

    // A reference to configuration, not a literal: os.environ[...], process.env.X, ENV["X"]
    if lower.starts_with("os.environ")
        || lower.starts_with("os.getenv")
        || lower.starts_with("process.env")
        || lower.starts_with("env[")
        || lower.starts_with("env.")
        || lower.starts_with("getenv(")
    {
        return true;
    }

    if NON_VALUES.contains(&lower.as_str()) || STOPWORDS.iter().any(|word| lower.contains(word)) {
        return true;
    }

    // "aaaaaaaa", "00000000", "abababab": at most two distinct characters.
    let mut distinct: Vec<char> = lower.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    distinct.len() <= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_recognised() {
        for value in [
            "changeme",
            "CHANGE_ME",
            "<your-api-key>",
            "your_api_key_here",
            "YOUR-SECRET",
            "${DB_PASSWORD}",
            "$DB_PASSWORD",
            "{{ vault.password }}",
            "%(password)s",
            "%PASSWORD%",
            "os.environ['KEY']",
            "process.env.API_KEY",
            "ENV[\"SECRET\"]",
            "xxxxxxxxxxxxxxxx",
            "XXXX-XXXX-XXXX",
            "aaaaaaaaaaaa",
            "0000000000",
            "abababab",
            "example-password",
            "REDACTED",
            "dummy_value_123",
            "\"placeholder\"",
            "password",
            "null",
            "",
            "'  '",
            "********",
            "insert-token-here",
        ] {
            assert!(is_placeholder(value), "{value:?} should be a placeholder");
        }
    }

    #[test]
    fn real_looking_values_are_kept() {
        for value in [
            "hunter2pass",
            "S3cur3P@ssw0rd!",
            "wJalrXUtnFEMIK7MDENGbPxRfiCY",
            "a1B2c3D4e5F6g7H8i9J0k1L2",
            "correct horse battery staple",
            "p@ssw0rd123",
            "Tr0ub4dor&3",
            "postgres://app:Xk29fLq8@db.internal:5432/app",
        ] {
            assert!(!is_placeholder(value), "{value:?} should be kept");
        }
    }

    #[test]
    fn only_generic_rules_are_checked() {
        assert!(applies_to("Generic Secret"));
        assert!(applies_to("Password in YAML"));
        assert!(!applies_to("GitHub Token"));
        assert!(!applies_to("AWS Access Key ID"));
        assert!(!applies_to("RSA Private Key"));
        assert!(!applies_to("My Custom Rule"));
    }
}
