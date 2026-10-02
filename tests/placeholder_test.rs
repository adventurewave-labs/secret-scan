//! Generic rules ignore documentation stand-ins; format-exact rules do not.

use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use tempfile::TempDir;

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("settings.txt"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

#[test]
fn template_and_documentation_values_are_not_reported() {
    let content = "\
password = \"changeme\"
api_key = \"<your-api-key-goes-here>\"
secret_key = \"${SECRET_KEY_FROM_ENVIRONMENT}\"
auth_token: \"{{ vault.auth_token_value }}\"
api_key = \"xxxxxxxxxxxxxxxxxxxxxxxx\"
password: your_password_here
access_token = \"REDACTED-REDACTED-REDACTED\"
DB_PASSWORD=$DATABASE_PASSWORD
url = \"https://user:password@host.internal/path\"
client_secret = \"00000000000000000000000000000000\"
";
    let findings = scan(content);
    assert!(
        findings.is_empty(),
        "placeholders reported: {:?}",
        findings
            .iter()
            .map(|f| (&f.pattern_name, &f.matched_text))
            .collect::<Vec<_>>()
    );
}

#[test]
fn real_looking_values_under_the_same_names_are_still_reported() {
    for (line, rule) in [
        ("api_key = \"a1B2c3D4e5F6g7H8i9J0k1L2m3N4\"", "Generic Secret"),
        ("password = \"Tr0ub4dor&3xQ9\"", "Password Environment Variable"),
        (
            "client_secret = \"k9Lm2Nq7Rt4Vx8Zb3Cf6Hj1Pw5Sy0Ad2\"",
            "Generic OAuth Secret",
        ),
        ("url = \"https://deploy:Xk29fLq8Wm@host.internal/path\"", "Password in URL"),
    ] {
        let findings = scan(&format!("{line}\n"));
        assert!(
            findings.iter().any(|f| f.pattern_name == rule),
            "{line} -> {:?}",
            findings.iter().map(|f| &f.pattern_name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn format_exact_rules_report_even_example_values() {
    // The documented AWS example key has the exact format of a real key; it
    // is reported, and can be allowlisted in .secretscan.toml if unwanted.
    let findings = scan("key = \"AKIAIOSFODNN7EXAMPLE\"\n");
    assert!(findings.iter().any(|f| f.pattern_name == "AWS Access Key ID"));
}
