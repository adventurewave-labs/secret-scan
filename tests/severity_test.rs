//! Severity on rules, in every output format, and as a filter.

use secretscan::output::{
    filter_by_severity, fingerprint, format_as_json, format_as_json_with_fingerprints,
    format_as_sarif, format_as_text, generate_summary, redact_findings,
};
use secretscan::patterns::{rules, severity_for, Severity};
use secretscan::Finding;
use std::path::PathBuf;
use std::process::Command;

fn finding(pattern: &str, secret: &str) -> Finding {
    Finding {
        file_path: PathBuf::from("src/app.rs"),
        line_number: 3,
        line_content: format!("x = \"{secret}\""),
        pattern_name: pattern.to_string(),
        matched_text: secret.to_string(),
        entropy: Some(4.0),
    }
}

#[test]
fn severities_are_ordered_and_round_trip() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    for level in [Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
        assert_eq!(Severity::parse(level.as_str()), Some(level));
        assert_eq!(Severity::parse(&level.as_str().to_uppercase()), Some(level));
        assert_eq!(level.to_string(), level.as_str());
    }
    assert_eq!(Severity::parse("urgent"), None);
}

#[test]
fn representative_rules_have_the_expected_severity() {
    for (name, expected) in [
        ("RSA Private Key", Severity::Critical),
        ("AWS Secret Key", Severity::Critical),
        ("GitHub Token", Severity::High),
        ("PostgreSQL URL", Severity::High),
        ("Anthropic API Key", Severity::High),
        ("Generic Secret", Severity::Medium),
        ("Password in YAML", Severity::Medium),
        ("Azure Tenant ID", Severity::Low),
        ("Suspicious Hex", Severity::Low),
    ] {
        assert_eq!(severity_for(name), expected, "{name}");
    }
    // Every level is in use, and every rule resolves to its own severity.
    for level in [Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
        assert!(rules().iter().any(|r| r.severity == level), "{level} unused");
    }
    for rule in rules() {
        assert_eq!(severity_for(rule.name), rule.severity);
    }
}

#[test]
fn decoded_findings_inherit_the_underlying_rule_and_unknown_rules_are_medium() {
    assert_eq!(severity_for("Base64 Encoded GitHub Token"), Severity::High);
    assert_eq!(severity_for("Hex Encoded RSA Private Key"), Severity::Critical);
    assert_eq!(severity_for("URL Decoded PostgreSQL URL"), Severity::High);
    assert_eq!(severity_for("Character Array Encoded Generic Secret"), Severity::Medium);
    assert_eq!(severity_for("My Custom Rule"), Severity::Medium);
}

#[test]
fn json_carries_rule_id_severity_and_fingerprint() {
    let findings = vec![finding("GitHub Token", "ghp_abc"), finding("Suspicious Hex", "deadbeef")];
    let doc: serde_json::Value = serde_json::from_str(&format_as_json(&findings).unwrap()).unwrap();
    assert_eq!(doc[0]["rule_id"], "github-token");
    assert_eq!(doc[0]["severity"], "high");
    assert_eq!(doc[0]["fingerprint"], fingerprint(&findings[0]));
    assert_eq!(doc[1]["severity"], "low");
    // Existing fields are unchanged, so the output still parses as findings.
    let parsed: Vec<Finding> = serde_json::from_value(doc).unwrap();
    assert_eq!(parsed, findings);
}

#[test]
fn redacted_json_keeps_the_fingerprint_of_the_real_secret() {
    let mut findings = vec![finding("GitHub Token", "ghp_0123456789abcdefghij")];
    let fingerprints: Vec<String> = findings.iter().map(fingerprint).collect();
    redact_findings(&mut findings);
    let out = format_as_json_with_fingerprints(&findings, &fingerprints).unwrap();
    assert!(!out.contains("ghp_0123456789abcdefghij"));
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc[0]["fingerprint"], fingerprints[0].as_str());
}

#[test]
fn sarif_maps_severity_to_level_and_security_severity() {
    let findings = vec![
        finding("RSA Private Key", "k"),
        finding("Generic Secret", "s"),
        finding("Azure Tenant ID", "t"),
    ];
    let doc: serde_json::Value =
        serde_json::from_str(&format_as_sarif(&findings, "1.0.0").unwrap()).unwrap();
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["properties"]["severity"], "critical");
    assert_eq!(results[1]["level"], "warning");
    assert_eq!(results[2]["level"], "note");

    let rules = doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let rule = |id: &str| rules.iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(rule("rsa-private-key")["properties"]["security-severity"], "9.5");
    assert_eq!(rule("generic-secret")["defaultConfiguration"]["level"], "warning");
    assert_eq!(rule("azure-tenant-id")["properties"]["security-severity"], "3.0");
}

#[test]
fn text_output_shows_severity_and_the_summary_is_stable() {
    let findings = vec![
        finding("Slack Token", "a"),
        finding("GitHub Token", "b"),
        finding("AWS Secret Key", "c"),
        finding("GitHub Token", "d"),
    ];
    let text = format_as_text(&findings);
    assert!(text.contains("Pattern: GitHub Token\nSeverity: high\n"));
    assert!(text.contains("Pattern: AWS Secret Key\nSeverity: critical\n"));

    let summary = generate_summary(&findings);
    assert_eq!(
        summary,
        "4 secrets found:\nAWS Secret Key: 1\nGitHub Token: 2\nSlack Token: 1\n"
    );
}

#[test]
fn filter_keeps_findings_at_or_above_the_minimum() {
    let all = vec![
        finding("RSA Private Key", "k"),
        finding("GitHub Token", "g"),
        finding("Generic Secret", "s"),
        finding("Suspicious Hex", "h"),
    ];
    for (minimum, expected) in [
        (Severity::Low, 4),
        (Severity::Medium, 3),
        (Severity::High, 2),
        (Severity::Critical, 1),
    ] {
        let mut findings = all.clone();
        filter_by_severity(&mut findings, minimum);
        assert_eq!(findings.len(), expected, "{minimum}");
    }
}

#[test]
fn cli_min_severity_filters_output_and_exit_code() {
    let dir = tempfile::TempDir::new().unwrap();
    // A client ID only: a low-severity finding.
    std::fs::write(
        dir.path().join("app.conf"),
        "client_id = \"a1B2c3D4e5F6g7H8i9J0k1L2m3N4\"\n",
    )
    .unwrap();
    let run = |level: &str| {
        Command::new(env!("CARGO_BIN_EXE_secretscan"))
            .args(["-q", "-f", "json", "--min-severity", level])
            .arg(dir.path())
            .output()
            .unwrap()
    };

    let low = run("low");
    let doc: serde_json::Value = serde_json::from_slice(&low.stdout).unwrap();
    let items = doc.as_array().unwrap();
    assert!(!items.is_empty(), "expected a low-severity finding");
    assert!(items.iter().all(|i| i["severity"] == "low"));
    assert_eq!(low.status.code(), Some(1));

    let high = run("high");
    let doc: serde_json::Value = serde_json::from_slice(&high.stdout).unwrap();
    assert!(doc.as_array().unwrap().is_empty());
    assert_eq!(high.status.code(), Some(0), "nothing reported means exit 0");

    let bad = run("urgent");
    assert_eq!(bad.status.code(), Some(2), "invalid level is a usage error");
}
