//! A bare UUID is not a secret: the Heroku and Azure rules need provider context.

use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use tempfile::TempDir;

const UUID: &str = "3f2b8c1e-9d47-4a6b-8e15-7c0a2d9f4b63";

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("settings.txt"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

fn names(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.pattern_name.as_str()).collect()
}

#[test]
fn bare_uuids_are_not_reported() {
    let content = format!(
        "request_id = \"{UUID}\"\nid: {UUID}\nTRACE {UUID} started\nuser_uuid={UUID}\n\
         app_id = \"{UUID}\"\ndirectory = \"{UUID}\"\n"
    );
    let findings = scan(&content);
    assert!(
        !names(&findings).contains(&"Heroku API Key")
            && !names(&findings).contains(&"Azure Tenant ID"),
        "bare UUID reported: {:?}",
        names(&findings)
    );
}

#[test]
fn heroku_keys_are_reported_with_provider_context() {
    for line in [
        format!("HEROKU_API_KEY={UUID}"),
        format!("heroku_api_key: \"{UUID}\""),
        format!("heroku.token = '{UUID}'"),
        format!("\"herokuApiKey\": \"{UUID}\""),
    ] {
        let findings = scan(&format!("{line}\n"));
        assert!(
            names(&findings).contains(&"Heroku API Key"),
            "not reported: {line} -> {:?}",
            names(&findings)
        );
    }
}

#[test]
fn azure_tenant_ids_are_reported_with_provider_context() {
    for line in [
        format!("AZURE_TENANT_ID={UUID}"),
        format!("azure_tenant_id: \"{UUID}\""),
        format!("ARM_TENANT_ID = \"{UUID}\""),
        format!("\"azureTenantId\": \"{UUID}\""),
    ] {
        let findings = scan(&format!("{line}\n"));
        assert!(
            names(&findings).contains(&"Azure Tenant ID"),
            "not reported: {line} -> {:?}",
            names(&findings)
        );
    }
}

#[test]
fn provider_name_elsewhere_on_the_line_is_not_enough() {
    let content = format!(
        "// deployed to heroku, request {UUID}\nlog(\"azure tenant lookup\", id = \"{UUID}\")\n"
    );
    let findings = scan(&content);
    assert!(
        !names(&findings).contains(&"Heroku API Key")
            && !names(&findings).contains(&"Azure Tenant ID"),
        "{:?}",
        names(&findings)
    );
}
