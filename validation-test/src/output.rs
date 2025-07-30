use crate::Finding;
use serde_json;
use std::collections::HashMap;

pub fn format_as_json(findings: &[Finding]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(findings)
}

pub fn format_as_text(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No secrets found.".to_string();
    }

    let mut output = String::new();

    for finding in findings {
        output.push_str(&format!(
            "File: {}\nline {}: {}\nPattern: {}\nMatch: {}\nEntropy: {:.1}\n\n",
            finding.file_path.display(),
            finding.line_number,
            finding.line_content.trim(),
            finding.pattern_name,
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

    let mut pattern_counts = HashMap::new();
    for finding in findings {
        *pattern_counts.entry(&finding.pattern_name).or_insert(0) += 1;
    }

    let mut summary = format!("{} secrets found:\n", findings.len());
    for (pattern, count) in pattern_counts {
        summary.push_str(&format!("{}: {}\n", pattern, count));
    }

    summary
}
