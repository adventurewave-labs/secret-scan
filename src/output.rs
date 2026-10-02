use crate::patterns::{severity_for, Severity};
use crate::Finding;
use serde_json;
use std::collections::BTreeMap;

/// Render findings as a JSON array.
///
/// Each element has the finding's own fields plus `rule_id`, `severity` and
/// `fingerprint`.
pub fn format_as_json(findings: &[Finding]) -> Result<String, serde_json::Error> {
    let fingerprints: Vec<String> = findings.iter().map(fingerprint).collect();
    format_as_json_with_fingerprints(findings, &fingerprints)
}

/// Like [`format_as_json`], with fingerprints supplied by the caller.
///
/// Used when the findings have been redacted: a fingerprint has to be taken
/// from the real secret, before redaction.
pub fn format_as_json_with_fingerprints(
    findings: &[Finding],
    fingerprints: &[String],
) -> Result<String, serde_json::Error> {
    let items: Vec<serde_json::Value> = findings
        .iter()
        .zip(fingerprints.iter())
        .map(|(finding, fingerprint)| {
            serde_json::json!({
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "line_content": finding.line_content,
                "pattern_name": finding.pattern_name,
                "rule_id": rule_id(&finding.pattern_name),
                "severity": severity_for(&finding.pattern_name).as_str(),
                "matched_text": finding.matched_text,
                "entropy": finding.entropy,
                "fingerprint": fingerprint,
            })
        })
        .collect();
    serde_json::to_string_pretty(&items)
}

pub fn format_as_text(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No secrets found.".to_string();
    }

    let mut output = String::new();

    for finding in findings {
        output.push_str(&format!(
            "File: {}\nline {}: {}\nPattern: {}\nSeverity: {}\nMatch: {}\nEntropy: {:.1}\n\n",
            finding.file_path.display(),
            finding.line_number,
            finding.line_content.trim(),
            finding.pattern_name,
            severity_for(&finding.pattern_name),
            finding.matched_text,
            finding.entropy.unwrap_or(0.0)
        ));
    }

    output
}

pub fn generate_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No secrets found.".to_string();
    }

    // BTreeMap: the summary lists rules in the same order on every run.
    let mut pattern_counts = BTreeMap::new();
    for finding in findings {
        *pattern_counts.entry(&finding.pattern_name).or_insert(0) += 1;
    }

    let mut summary = format!("{} secrets found:\n", findings.len());
    for (pattern, count) in pattern_counts {
        summary.push_str(&format!("{}: {}\n", pattern, count));
    }

    summary
}

/// Stable, machine-friendly rule identifier derived from a pattern name
/// (e.g. "AWS Access Key ID" -> "aws-access-key-id").
pub fn rule_id(pattern_name: &str) -> String {
    let mut id = String::with_capacity(pattern_name.len());
    let mut last_dash = true;
    for c in pattern_name.chars() {
        if c.is_ascii_alphanumeric() {
            id.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            id.push('-');
            last_dash = true;
        }
    }
    id.trim_end_matches('-').to_string()
}

/// A path as it appears in reports and fingerprints: forward slashes, no
/// leading `./`. `secretscan .` and `secretscan src` therefore agree on the
/// identity of a finding in `src/config.rs`.
pub fn normalize_path(path: &std::path::Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut trimmed = text.as_str();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    trimmed.to_string()
}

/// Stable fingerprint for a finding: FNV-1a 64 over path, rule and secret.
///
/// Deliberately excludes the line number so a finding keeps its identity when
/// unrelated lines move. Hand-rolled FNV rather than `DefaultHasher`, whose
/// output is not guaranteed stable across Rust releases.
pub fn fingerprint(finding: &Finding) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    let path = normalize_path(&finding.file_path);
    let rule = rule_id(&finding.pattern_name);
    for part in [path.as_str(), rule.as_str(), finding.matched_text.as_str()] {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0u8)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{:016x}", hash)
}

/// Mask a secret, keeping at most the first four characters as a hint.
pub fn redact_secret(secret: &str) -> String {
    let total = secret.chars().count();
    let keep = if total > 12 { 4 } else { 0 };
    let prefix: String = secret.chars().take(keep).collect();
    format!("{}{}", prefix, "*".repeat(total.saturating_sub(keep).min(12)))
}

/// Replace every secret in the findings with its redacted form, in both the
/// matched text and the surrounding line.
///
/// Call this after computing fingerprints: a fingerprint of redacted text
/// would no longer identify the secret.
pub fn redact_findings(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        if finding.matched_text.is_empty() {
            continue;
        }
        let masked = redact_secret(&finding.matched_text);
        finding.line_content = finding.line_content.replace(&finding.matched_text, &masked);
        finding.matched_text = masked;
    }
}

/// Render findings as SARIF 2.1.0, the format consumed by GitHub code
/// scanning, GitLab and most CI security dashboards.
///
/// Secrets never appear in SARIF output: results carry the rule, location and
/// a fingerprint, so the report is safe to upload as a CI artifact.
pub fn format_as_sarif(findings: &[Finding], tool_version: &str) -> Result<String, serde_json::Error> {
    let mut rule_names: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
    rule_names.sort_unstable();
    rule_names.dedup();

    let rules: Vec<serde_json::Value> = rule_names
        .iter()
        .map(|name| {
            serde_json::json!({
                "id": rule_id(name),
                "name": name,
                "shortDescription": { "text": format!("{} detected", name) },
                "defaultConfiguration": { "level": severity_for(name).sarif_level() },
                "properties": {
                    "tags": ["security", "secret"],
                    "security-severity": severity_for(name).security_severity()
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let uri = normalize_path(&f.file_path);
            serde_json::json!({
                "ruleId": rule_id(&f.pattern_name),
                "level": severity_for(&f.pattern_name).sarif_level(),
                "properties": { "severity": severity_for(&f.pattern_name).as_str() },
                "message": { "text": format!("{} detected", f.pattern_name) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": f.line_number.max(1) }
                    }
                }],
                "partialFingerprints": { "secretscan/v1": fingerprint(f) }
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secretscan",
                    "version": tool_version,
                    "informationUri": "https://github.com/adventurewave-labs/secret-scan",
                    "rules": rules
                }
            },
            "results": results
        }]
    }))
}

/// Keep only findings at or above `minimum`.
pub fn filter_by_severity(findings: &mut Vec<Finding>, minimum: Severity) {
    findings.retain(|finding| severity_for(&finding.pattern_name) >= minimum);
}
