//! Tests for SARIF output, redaction, fingerprints, inline suppression and the
//! modern provider token patterns.
//!
//! Token fixtures are assembled at runtime so no credential-shaped literal is
//! committed to the repository.

use secretscan::output::{
    fingerprint, format_as_sarif, redact_findings, redact_secret, rule_id,
};
use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Deterministic mixed-case alphanumeric filler of the requested length.
fn filler(len: usize) -> String {
    const ALPHABET: &[u8] = b"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ";
    (0..len)
        .map(|i| ALPHABET[(i * 7 + 3) % ALPHABET.len()] as char)
        .collect()
}

fn hex_filler(len: usize) -> String {
    const ALPHABET: &[u8] = b"0a1b2c3d4e5f6789";
    (0..len)
        .map(|i| ALPHABET[(i * 5 + 1) % ALPHABET.len()] as char)
        .collect()
}

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("config.txt"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

fn sample(pattern: &str, secret: &str) -> Finding {
    Finding {
        file_path: PathBuf::from("./src/config.rs"),
        line_number: 7,
        line_content: format!("let key = \"{}\";", secret),
        pattern_name: pattern.to_string(),
        matched_text: secret.to_string(),
        entropy: Some(4.0),
    }
}

#[test]
fn modern_provider_tokens_are_detected() {
    let cases: Vec<(&str, String)> = vec![
        ("GitHub Fine-Grained PAT", format!("github_pat_{}", filler(82))),
        ("Anthropic API Key", format!("sk-ant-api03-{}", filler(95))),
        ("OpenAI Project Key", format!("sk-proj-{}", filler(48))),
        ("Hugging Face Token", format!("hf_{}", filler(34))),
        ("npm Access Token", format!("npm_{}", filler(36))),
        ("PyPI Upload Token", format!("pypi-AgEIcHlwaS5vcmc{}", filler(60))),
        (
            "Slack App Token",
            format!("xapp-1-A0{}-123456789012-{}", "B2C3D4E5F", hex_filler(64)),
        ),
        ("Stripe Restricted Key", format!("rk_live_{}", filler(24))),
        ("Stripe Restricted Key", format!("whsec_{}", filler(32))),
    ];

    for (pattern, token) in cases {
        let findings = scan(&format!("value = \"{}\"\n", token));
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == pattern && f.matched_text == token),
            "expected {} to be reported, got {:?}",
            pattern,
            findings.iter().map(|f| &f.pattern_name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn truncated_tokens_are_not_reported_as_modern_formats() {
    let content = format!(
        "a = \"github_pat_{}\"\nb = \"npm_{}\"\nc = \"hf_{}\"\n",
        filler(20),
        filler(10),
        filler(8)
    );
    let findings = scan(&content);
    for name in ["GitHub Fine-Grained PAT", "npm Access Token", "Hugging Face Token"] {
        assert!(
            !findings.iter().any(|f| f.pattern_name == name),
            "{} matched a truncated token",
            name
        );
    }
}

#[test]
fn inline_allow_marker_suppresses_a_finding() {
    let token = format!("ghp_{}", filler(36));
    let flagged = scan(&format!("token = \"{}\"\n", token));
    assert!(flagged.iter().any(|f| f.matched_text == token));

    for marker in ["secretscan:allow", "gitleaks:allow"] {
        let allowed = scan(&format!("token = \"{}\" # {}\n", token, marker));
        assert!(
            allowed.is_empty(),
            "{} did not suppress: {:?}",
            marker,
            allowed
        );
    }
}

#[test]
fn findings_are_returned_in_deterministic_order() {
    let dir = TempDir::new().unwrap();
    for i in 0..12 {
        fs::write(
            dir.path().join(format!("file_{:02}.txt", i)),
            format!("a = \"ghp_{}\"\nb = \"hf_{}\"\n", filler(36), filler(34)),
        )
        .unwrap();
    }
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());

    let first = scanner.scan_directory(dir.path()).unwrap();
    assert!(first.len() >= 24);
    for _ in 0..3 {
        assert_eq!(first, scanner.scan_directory(dir.path()).unwrap());
    }
    let mut sorted = first.clone();
    sorted.sort_by(|a, b| (&a.file_path, a.line_number).cmp(&(&b.file_path, b.line_number)));
    let key = |f: &Finding| (f.file_path.clone(), f.line_number);
    assert_eq!(
        first.iter().map(key).collect::<Vec<_>>(),
        sorted.iter().map(key).collect::<Vec<_>>()
    );
}

#[test]
fn rule_ids_are_slugs() {
    assert_eq!(rule_id("AWS Access Key ID"), "aws-access-key-id");
    assert_eq!(rule_id("GitHub Fine-Grained PAT"), "github-fine-grained-pat");
    assert_eq!(rule_id("Multi-line Private Key"), "multi-line-private-key");
    assert_eq!(rule_id("  Odd -- Name! "), "odd-name");
}

#[test]
fn fingerprint_is_stable_and_ignores_line_number() {
    let a = sample("GitHub Token", "ghp_one");
    let mut moved = a.clone();
    moved.line_number = 99;
    moved.line_content = "something else".to_string();
    assert_eq!(fingerprint(&a), fingerprint(&moved));
    assert_eq!(fingerprint(&a).len(), 16);

    let other_secret = sample("GitHub Token", "ghp_two");
    let other_rule = sample("Slack Token", "ghp_one");
    let mut other_file = a.clone();
    other_file.file_path = PathBuf::from("./src/other.rs");
    assert_ne!(fingerprint(&a), fingerprint(&other_secret));
    assert_ne!(fingerprint(&a), fingerprint(&other_rule));
    assert_ne!(fingerprint(&a), fingerprint(&other_file));

    // Pinned literal: guards against an accidental change to the hash, which
    // would silently invalidate every stored baseline. A fresh
    // fingerprint(&sample(...)) call here would pass under ANY hash change.
    assert_eq!(fingerprint(&a), "fbeeef2b61cbafea");
}

#[test]
fn redaction_removes_the_secret_everywhere() {
    let secret = format!("ghp_{}", filler(36));
    let mut findings = vec![sample("GitHub Token", &secret)];
    redact_findings(&mut findings);

    assert_eq!(findings[0].matched_text, "ghp_************");
    assert!(!findings[0].line_content.contains(&secret));
    assert!(findings[0].line_content.contains("ghp_************"));

    // Short secrets keep no prefix at all.
    assert_eq!(redact_secret("hunter2pass"), "***********");
    assert_eq!(redact_secret(""), "");
}

#[test]
fn redaction_masks_every_secret_sharing_a_line() {
    // Two findings on the same line: each finding's reported line_content
    // must have BOTH secrets masked, not just its own match.
    let gh = format!("ghp_{}", filler(36));
    let slack = format!("xoxb-{}", filler(30));
    let line = format!("export GH=\"{gh}\" SLACK=\"{slack}\"\n");
    let mut a = sample("GitHub Token", &gh);
    let mut b = sample("Slack Token", &slack);
    a.line_content = line.clone();
    b.line_content = line;
    let mut findings = vec![a, b];
    redact_findings(&mut findings);
    for f in &findings {
        assert!(!f.line_content.contains(&gh), "github secret survived in {}", f.pattern_name);
        assert!(!f.line_content.contains(&slack), "slack secret survived in {}", f.pattern_name);
    }
}

#[test]
fn sarif_output_is_valid_and_contains_no_secret() {
    let secret = format!("ghp_{}", filler(36));
    let findings = vec![
        sample("GitHub Token", &secret),
        sample("GitHub Token", "ghp_second"),
        sample("Slack Token", "xoxb-something"),
    ];
    let sarif = format_as_sarif(&findings, "9.9.9").unwrap();
    assert!(!sarif.contains(&secret), "SARIF must not leak the secret");

    let doc: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "secretscan");
    assert_eq!(run["tool"]["driver"]["version"], "9.9.9");

    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "rules are deduplicated");
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    let first = &results[0];
    assert_eq!(first["ruleId"], "github-token");
    let location = &first["locations"][0]["physicalLocation"];
    assert_eq!(location["artifactLocation"]["uri"], "src/config.rs");
    assert_eq!(location["region"]["startLine"], 7);
    assert_eq!(
        first["partialFingerprints"]["secretscan/v1"],
        fingerprint(&findings[0])
    );

    // Every result references a declared rule.
    for result in results {
        assert!(rules.iter().any(|r| r["id"] == result["ruleId"]));
    }
}

#[test]
fn sarif_for_no_findings_is_a_valid_empty_run() {
    let doc: serde_json::Value =
        serde_json::from_str(&format_as_sarif(&[], "1.0.0").unwrap()).unwrap();
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
    assert_eq!(doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
}

#[test]
fn entropy_is_reproducible_and_counts_characters() {
    let text = format!("ghp_{}", filler(36));
    let first = secretscan::shannon_entropy(&text);
    for _ in 0..200 {
        assert_eq!(first.to_bits(), secretscan::shannon_entropy(&text).to_bits());
    }
    // Four distinct characters, each once: exactly 2 bits, whatever their
    // UTF-8 width.
    assert_eq!(secretscan::shannon_entropy("añ€𝄞"), 2.0);
    assert_eq!(secretscan::shannon_entropy(""), 0.0);
}
