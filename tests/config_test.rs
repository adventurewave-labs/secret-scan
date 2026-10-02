//! `.secretscan.toml`: allowlists, disabled rules and custom rules.

use secretscan::config::{Config, ConfigError};
use secretscan::output::fingerprint;
use secretscan::Finding;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn finding(path: &str, pattern: &str, secret: &str) -> Finding {
    Finding {
        file_path: PathBuf::from(path),
        line_number: 1,
        line_content: format!("v = \"{secret}\""),
        pattern_name: pattern.to_string(),
        matched_text: secret.to_string(),
        entropy: Some(4.0),
    }
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .args(["-q", "-f", "json"])
        .args(args)
        .arg(".")
        .output()
        .unwrap()
}

fn rules_reported(output: &Output) -> Vec<String> {
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stderr)));
    let mut ids: Vec<String> = doc
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

#[test]
fn empty_config_changes_nothing() {
    let config = Config::parse("").unwrap();
    assert!(config.is_empty());
    assert!(!config.excludes(&finding("a.rs", "GitHub Token", "x")));
}

#[test]
fn allowlist_by_path_regex_and_fingerprint() {
    let kept = finding("src/app.rs", "GitHub Token", "ghp_real");
    let by_fingerprint = finding("src/cfg.rs", "GitHub Token", "ghp_known");
    let text = format!(
        "[allowlist]\npaths = [\"^vendor/\", \"\\\\.lock$\"]\nregexes = [\"EXAMPLE\"]\n\
         fingerprints = [\"{}\"]\n",
        fingerprint(&by_fingerprint)
    );
    let config = Config::parse(&text).unwrap();
    assert!(!config.is_empty());

    let mut findings = vec![
        kept.clone(),
        finding("./vendor/lib.js", "GitHub Token", "ghp_vendored"),
        finding("Cargo.lock", "Suspicious Hex", "abcdef"),
        finding("src/app.rs", "AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE"),
        by_fingerprint,
    ];
    assert_eq!(config.apply(&mut findings), 4);
    assert_eq!(findings, vec![kept]);
}

#[test]
fn disabled_rule_also_silences_its_decoded_variants() {
    let config = Config::parse("[rules]\ndisable = [\"github-token\"]\n").unwrap();
    assert!(config.excludes(&finding("a.rs", "GitHub Token", "x")));
    assert!(config.excludes(&finding("a.rs", "Base64 Encoded GitHub Token", "x")));
    assert!(!config.excludes(&finding("a.rs", "GitHub OAuth", "x")));
}

#[test]
fn mistakes_in_the_config_are_errors() {
    for (text, expected) in [
        ("[rules]\ndisable = [\"github-tokn\"]\n", "unknown rule id"),
        ("[allowlist]\npaths = [\"(\"]\n", "invalid allowlist.paths regex"),
        ("[allowlist]\nregexes = [\"[\"]\n", "invalid allowlist.regexes regex"),
        ("[allowlist]\npath = [\"x\"]\n", "unknown field"),
        ("[allowlists]\n", "unknown field"),
        ("[[rules.custom]]\nname = \"GitHub Token\"\nregex = \"x\"\n", "clashes"),
        ("[[rules.custom]]\nname = \"Mine\"\nregex = \"(\"\n", "invalid regex"),
        (
            "[[rules.custom]]\nname = \"Mine\"\nregex = \"x\"\nseverity = \"urgent\"\n",
            "unknown severity",
        ),
        ("[[rules.custom]]\nname = \" \"\nregex = \"x\"\n", "name is empty"),
        ("[[rules.custom]]\nname = \"Mine\"\n", "missing field"),
        (
            "[[rules.custom]]\nname = \"Mine\"\nregex = \"x\"\n\
             [[rules.custom]]\nname = \"mine\"\nregex = \"y\"\n",
            "clashes",
        ),
        ("not toml at all [", ""),
    ] {
        let err = Config::parse(text).expect_err(text);
        assert!(
            err.to_string().contains(expected),
            "{text:?} gave {err}, expected {expected:?}"
        );
    }
    assert!(matches!(
        Config::load(Path::new("/nonexistent/.secretscan.toml")),
        Err(ConfigError::Io(_))
    ));
}

#[test]
fn discover_finds_the_file_in_the_scanned_directory() {
    let dir = TempDir::new().unwrap();
    assert_eq!(Config::discover(dir.path()), None);
    let file = dir.path().join(".secretscan.toml");
    fs::write(&file, "").unwrap();
    assert_eq!(Config::discover(dir.path()), Some(file.clone()));
    // Scanning a single file uses the config next to it.
    let source = dir.path().join("app.rs");
    fs::write(&source, "x").unwrap();
    assert_eq!(Config::discover(&source), Some(file));
}

#[test]
fn cli_applies_a_discovered_config() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("vendor")).unwrap();
    fs::write(dir.path().join("vendor/lib.txt"), format!("t = \"{}\"\n", token())).unwrap();
    fs::write(
        dir.path().join("app.txt"),
        format!("t = \"{}\"\ninternal = \"acme_0123456789abcdef0123456789abcdef\"\n", token()),
    )
    .unwrap();

    // No config: both GitHub tokens, no custom rule.
    let plain = run(dir.path(), &[]);
    assert_eq!(rules_reported(&plain), vec!["github-token", "github-token"]);

    fs::write(
        dir.path().join(".secretscan.toml"),
        "[allowlist]\npaths = [\"^vendor/\"]\n\n\
         [[rules.custom]]\nname = \"Acme Token\"\nregex = \"acme_[a-f0-9]{32}\"\nseverity = \"critical\"\n",
    )
    .unwrap();
    let configured = run(dir.path(), &[]);
    assert_eq!(rules_reported(&configured), vec!["acme-token", "github-token"]);
    let doc: serde_json::Value = serde_json::from_slice(&configured.stdout).unwrap();
    let acme = doc.as_array().unwrap().iter().find(|i| i["rule_id"] == "acme-token").unwrap();
    assert_eq!(acme["severity"], "critical");
    assert_eq!(acme["file_path"], "./app.txt");

    // --min-severity sees the custom severity.
    let critical = run(dir.path(), &["--min-severity", "critical"]);
    assert_eq!(rules_reported(&critical), vec!["acme-token"]);

    // --no-config ignores the file.
    let ignored = run(dir.path(), &["--no-config"]);
    assert_eq!(rules_reported(&ignored), vec!["github-token", "github-token"]);
}

#[test]
fn cli_custom_rule_reports_low_entropy_matches() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("notes.txt"), "ref TICKET-0000\n").unwrap();
    fs::write(
        dir.path().join(".secretscan.toml"),
        "[[rules.custom]]\nname = \"Ticket\"\nregex = \"TICKET-[0-9]{4}\"\n",
    )
    .unwrap();
    assert_eq!(rules_reported(&run(dir.path(), &[])), vec!["ticket"]);
}

#[test]
fn cli_config_file_is_not_scanned_and_disable_works() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.txt"), format!("t = \"{}\"\n", token())).unwrap();
    // The allowlist entry is itself token-shaped; it must not be reported.
    fs::write(
        dir.path().join("custom.toml"),
        format!("# known: \"{}\"\n[rules]\ndisable = [\"github-token\"]\n", token()),
    )
    .unwrap();
    let out = run(dir.path(), &["--config", "custom.toml"]);
    assert!(rules_reported(&out).is_empty());
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn cli_rejects_a_bad_or_missing_config() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.txt"), "x = 1\n").unwrap();
    fs::write(dir.path().join(".secretscan.toml"), "[rules]\ndisable = [\"nope\"]\n").unwrap();
    let bad = run(dir.path(), &[]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown rule id"));

    let missing = run(dir.path(), &["--config", "absent.toml"]);
    assert_eq!(missing.status.code(), Some(2));

    let both = run(dir.path(), &["--config", "x.toml", "--no-config"]);
    assert_eq!(both.status.code(), Some(2));
}
