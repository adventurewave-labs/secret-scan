//! Provider rules added in the second batch.
//!
//! Fixtures are assembled at runtime so no credential-shaped literal is
//! committed.

use secretscan::patterns::{severity_for, Severity};
use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use tempfile::TempDir;

fn mixed(len: usize) -> String {
    const ALPHABET: &[u8] = b"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ";
    (0..len).map(|i| ALPHABET[(i * 7 + 3) % ALPHABET.len()] as char).collect()
}

fn hex(len: usize) -> String {
    const ALPHABET: &[u8] = b"0a1b2c3d4e5f6789";
    (0..len).map(|i| ALPHABET[(i * 5 + 1) % ALPHABET.len()] as char).collect()
}

fn bech32(len: usize) -> String {
    const ALPHABET: &[u8] = b"QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";
    (0..len).map(|i| ALPHABET[(i * 11 + 5) % ALPHABET.len()] as char).collect()
}

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("settings.txt"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

fn rules_found(content: &str) -> Vec<String> {
    scan(content).into_iter().map(|f| f.pattern_name).collect()
}

fn positives() -> Vec<(&'static str, String)> {
    vec![
        (
            "Azure Storage Account Key",
            format!(
                "conn = \"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={}==;\"",
                mixed(86)
            ),
        ),
        ("Databricks Token", format!("token = \"dapi{}\"", hex(32))),
        ("Databricks Token", format!("token = \"dapi{}-2\"", hex(32))),
        ("Supabase Access Token", format!("t = \"sbp_{}\"", hex(40))),
        ("Telegram Bot Token", format!("bot = \"123456789:AA{}\"", mixed(33))),
        ("Postman API Key", format!("k = \"PMAK-{}-{}\"", hex(24), hex(34))),
        ("Linear API Key", format!("k = \"lin_api_{}\"", mixed(40))),
        ("Notion Token", format!("k = \"secret_{}\"", mixed(43))),
        ("Notion Token", format!("k = \"ntn_{}\"", mixed(46))),
        ("Doppler Token", format!("k = \"dp.pt.{}\"", mixed(43))),
        ("Docker Hub Token", format!("k = \"dckr_pat_{}\"", mixed(27))),
        (
            "Grafana Service Account Token",
            format!("k = \"glsa_{}_{}\"", mixed(32), hex(8)),
        ),
        ("Age Secret Key", format!("AGE-SECRET-KEY-1{}", bech32(58))),
        ("GCP Service Account", "  \"type\": \"service_account\",".to_string()),
        ("Datadog API Key", format!("DD_API_KEY={}", hex(32))),
        ("Datadog API Key", format!("datadog_app_key: \"{}\"", hex(40))),
        ("Cloudflare API Token", format!("CLOUDFLARE_API_TOKEN={}", mixed(40))),
        ("Vercel Token", format!("VERCEL_TOKEN=\"{}\"", mixed(24))),
    ]
}

#[test]
fn each_provider_format_is_detected() {
    for (rule, line) in positives() {
        let found = rules_found(&format!("{line}\n"));
        assert!(found.iter().any(|name| name == rule), "{rule} not found in {line:?}: {found:?}");
    }
}

#[test]
fn near_misses_are_not_reported_under_the_new_rules() {
    let new_rules: Vec<&str> = positives().iter().map(|(rule, _)| *rule).collect();
    let lines = vec![
        format!("AccountKey={}==", mixed(40)),              // too short
        format!("dapi{}", hex(20)),                         // too short
        format!("handle_dapi{}", hex(32)),                  // not at a word start
        format!("sbp_{}", hex(12)),
        format!("12345:AA{}", mixed(33)),                   // bot id too short
        format!("PMAK-{}", hex(24)),                        // second half missing
        format!("lin_api_{}", mixed(12)),
        format!("secret_{}", mixed(10)),                    // an ordinary identifier
        format!("dp.xx.{}", mixed(43)),                     // unknown token type
        format!("dckr_pat_{}", mixed(5)),
        "AGE-SECRET-KEY-1SHORT".to_string(),
        "\"type\": \"authorized_user\"".to_string(),
        format!("api_checksum = {}", hex(32)),              // 32 hex with no Datadog context
        format!("cdn = cloudflare; id = {}", mixed(40)),    // provider named, not assigned
        format!("vercel_project = {}", mixed(24)),          // not a token variable
    ];
    for line in lines {
        let found = rules_found(&format!("{line}\n"));
        let wrong: Vec<&String> =
            found.iter().filter(|name| new_rules.contains(&name.as_str())).collect();
        assert!(wrong.is_empty(), "{line:?} wrongly matched {wrong:?}");
    }
}

#[test]
fn severities_are_assigned() {
    assert_eq!(severity_for("Age Secret Key"), Severity::Critical);
    assert_eq!(severity_for("GCP Service Account"), Severity::Medium);
    for (rule, _) in positives() {
        if rule != "Age Secret Key" && rule != "GCP Service Account" {
            assert_eq!(severity_for(rule), Severity::High, "{rule}");
        }
    }
}

#[test]
fn a_service_account_file_reports_the_marker_and_the_key_once_each() {
    let dashes = "-".repeat(5);
    let content = format!(
        "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo\",\n  \
         \"private_key\": \"{dashes}BEGIN PRIVATE KEY{dashes}\\nMIIEvQIBADANBg\\n{dashes}END PRIVATE KEY{dashes}\\n\"\n}}\n"
    );
    let mut found = rules_found(&content);
    found.sort();
    assert_eq!(found, vec!["GCP Service Account", "Generic Private Key"]);
}
