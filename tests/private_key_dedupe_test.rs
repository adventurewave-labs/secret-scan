//! A private key is reported once, under its most specific rule.
//!
//! PEM markers are assembled at runtime so no key-shaped literal is committed.

use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use tempfile::TempDir;

fn begin(label: &str) -> String {
    let dashes = "-".repeat(5);
    if label.is_empty() {
        format!("{dashes}BEGIN PRIVATE KEY{dashes}")
    } else {
        format!("{dashes}BEGIN {label} PRIVATE KEY{dashes}")
    }
}

fn end(label: &str) -> String {
    let dashes = "-".repeat(5);
    if label.is_empty() {
        format!("{dashes}END PRIVATE KEY{dashes}")
    } else {
        format!("{dashes}END {label} PRIVATE KEY{dashes}")
    }
}

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("key.pem"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

fn key_findings(findings: &[Finding]) -> Vec<&str> {
    findings
        .iter()
        .filter(|f| f.pattern_name.contains("Private Key"))
        .map(|f| f.pattern_name.as_str())
        .collect()
}

fn pem(label: &str) -> String {
    format!("{}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n{}\n", begin(label), end(label))
}

#[test]
fn each_key_type_is_reported_once_under_its_own_rule() {
    for (label, rule) in [
        ("RSA", "RSA Private Key"),
        ("EC", "EC Private Key"),
        ("OPENSSH", "SSH Private Key"),
        ("", "Generic Private Key"),
        ("DSA", "Generic Private Key"),
        ("ENCRYPTED", "Generic Private Key"),
    ] {
        let findings = scan(&pem(label));
        assert_eq!(
            key_findings(&findings),
            vec![rule],
            "label {label:?} produced {:?}",
            key_findings(&findings)
        );
    }
}

#[test]
fn pgp_block_is_reported_once() {
    let dashes = "-".repeat(5);
    let content = format!(
        "{dashes}BEGIN PGP PRIVATE KEY BLOCK{dashes}\nlQOYBF\n{dashes}END PGP PRIVATE KEY BLOCK{dashes}\n"
    );
    assert_eq!(key_findings(&scan(&content)), vec!["PGP Private Key"]);
}

#[test]
fn unlabelled_pkcs8_key_is_no_longer_called_rsa() {
    let findings = scan(&pem(""));
    assert!(!key_findings(&findings).contains(&"RSA Private Key"));
}

#[test]
fn key_embedded_on_a_single_line_is_reported_once() {
    // e.g. a JSON service-account file, where the PEM is one escaped string.
    let content = format!(
        "{{\"private_key\": \"{}\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n{}\\n\"}}\n",
        begin("RSA"),
        end("RSA")
    );
    assert_eq!(key_findings(&scan(&content)), vec!["RSA Private Key"]);

    let pkcs8 = format!(
        "{{\"private_key\": \"{}\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n{}\\n\"}}\n",
        begin(""),
        end("")
    );
    assert_eq!(key_findings(&scan(&pkcs8)), vec!["Generic Private Key"]);
}

#[test]
fn two_keys_in_one_file_are_two_findings() {
    let content = format!("{}\n{}", pem("RSA"), pem("EC"));
    assert_eq!(
        key_findings(&scan(&content)),
        vec!["RSA Private Key", "EC Private Key"]
    );
}

#[test]
fn public_keys_and_certificates_are_not_reported() {
    let dashes = "-".repeat(5);
    let content = format!(
        "{dashes}BEGIN PUBLIC KEY{dashes}\nMIIB\n{dashes}END PUBLIC KEY{dashes}\n\
         {dashes}BEGIN CERTIFICATE{dashes}\nMIIC\n{dashes}END CERTIFICATE{dashes}\n"
    );
    assert!(key_findings(&scan(&content)).is_empty());
}
