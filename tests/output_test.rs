use secretscan::output::*;
use secretscan::Finding;
use std::path::PathBuf;

#[test]
fn test_json_output_format() {
    let findings = vec![
        Finding {
            file_path: PathBuf::from("/test/file1.txt"),
            line_number: 1,
            line_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
            pattern_name: "AWS Access Key".to_string(),
            matched_text: "AKIAIOSFODNN7EXAMPLE".to_string(),
            entropy: Some(4.2),
        },
        Finding {
            file_path: PathBuf::from("/test/file2.txt"),
            line_number: 5,
            line_content: "let token = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\";".to_string(),
            pattern_name: "GitHub Token".to_string(),
            matched_text: "ghp_1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
            entropy: Some(5.1),
        },
    ];

    let json_output = format_as_json(&findings).unwrap();

    // Verify JSON is valid and contains expected data
    let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    assert!(parsed.is_array());

    let array = parsed.as_array().unwrap();
    assert_eq!(array.len(), 2);

    // Check first finding
    assert_eq!(array[0]["file_path"], "/test/file1.txt");
    assert_eq!(array[0]["line_number"], 1);
    assert_eq!(array[0]["pattern_name"], "AWS Access Key");
    assert_eq!(array[0]["entropy"], 4.2);

    // Check second finding
    assert_eq!(array[1]["file_path"], "/test/file2.txt");
    assert_eq!(array[1]["line_number"], 5);
    assert_eq!(array[1]["pattern_name"], "GitHub Token");
    assert_eq!(array[1]["entropy"], 5.1);
}

#[test]
fn test_text_output_format() {
    let findings = vec![Finding {
        file_path: PathBuf::from("/test/file1.txt"),
        line_number: 1,
        line_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
        pattern_name: "AWS Access Key".to_string(),
        matched_text: "AKIAIOSFODNN7EXAMPLE".to_string(),
        entropy: Some(4.2),
    }];

    let text_output = format_as_text(&findings);

    // Verify text output contains expected information
    assert!(text_output.contains("file1.txt"));
    assert!(text_output.contains("line 1"));
    assert!(text_output.contains("AWS Access Key"));
    assert!(text_output.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(text_output.contains("4.2"));
}

#[test]
fn test_empty_findings_json() {
    let findings: Vec<Finding> = vec![];
    let json_output = format_as_json(&findings).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn test_empty_findings_text() {
    let findings: Vec<Finding> = vec![];
    let text_output = format_as_text(&findings);

    assert!(text_output.contains("No secrets found"));
}

#[test]
fn test_output_summary() {
    let findings = vec![
        Finding {
            file_path: PathBuf::from("/test/file1.txt"),
            line_number: 1,
            line_content: "secret1".to_string(),
            pattern_name: "AWS Access Key".to_string(),
            matched_text: "secret1".to_string(),
            entropy: Some(4.2),
        },
        Finding {
            file_path: PathBuf::from("/test/file2.txt"),
            line_number: 1,
            line_content: "secret2".to_string(),
            pattern_name: "GitHub Token".to_string(),
            matched_text: "secret2".to_string(),
            entropy: Some(5.1),
        },
    ];

    let summary = generate_summary(&findings);

    assert!(summary.contains("2 secrets found"));
    assert!(summary.contains("AWS Access Key: 1"));
    assert!(summary.contains("GitHub Token: 1"));
}
