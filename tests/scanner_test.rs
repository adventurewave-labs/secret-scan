use secretscan::scanner::*;
use secretscan::Finding;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_scanner_creation() {
    let scanner = Scanner::new();
    assert!(scanner.is_ok());
}

#[test]
fn test_scanner_with_custom_patterns() {
    let patterns = vec![("test".to_string(), regex::Regex::new(r"test").unwrap())];

    let scanner = Scanner::with_patterns(patterns);
    assert!(scanner.is_ok());
}

#[test]
fn test_scan_directory_basic() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create a test file with a secret
    let test_file = temp_path.join("test.txt");
    fs::write(&test_file, "AKIAIOSFODNN7EXAMPLE").unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    assert!(!findings.is_empty());
    assert_eq!(findings[0].file_path, test_file);
    assert_eq!(findings[0].line_number, 1);
    assert_eq!(findings[0].pattern_name, "AWS Access Key");
}

#[test]
fn test_scan_respects_gitignore() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Initialize git repository for ignore crate to work
    std::process::Command::new("git")
        .arg("init")
        .current_dir(temp_path)
        .output()
        .unwrap();

    // Create .gitignore
    fs::write(temp_path.join(".gitignore"), "ignored_file.txt\n").unwrap();

    // Create ignored file with secret
    fs::write(temp_path.join("ignored_file.txt"), "AKIAIOSFODNN7EXAMPLE").unwrap();

    // Create non-ignored file with secret
    fs::write(
        temp_path.join("normal_file.txt"),
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should only find the secret in normal_file.txt, not ignored_file.txt
    assert_eq!(findings.len(), 1);
    assert!(findings[0].file_path.ends_with("normal_file.txt"));
}

#[test]
fn test_scan_nested_directories() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create nested directory structure
    let nested_dir = temp_path.join("src").join("lib");
    fs::create_dir_all(&nested_dir).unwrap();

    // Create file in nested directory
    fs::write(
        nested_dir.join("config.rs"),
        "let api_key = \"AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI\";",
    )
    .unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].file_path.ends_with("config.rs"));
}

#[test]
fn test_finding_struct() {
    let finding = Finding {
        file_path: PathBuf::from("/test/file.txt"),
        line_number: 42,
        line_content: "secret content".to_string(),
        pattern_name: "Test Pattern".to_string(),
        matched_text: "secret".to_string(),
        entropy: Some(3.5),
    };

    assert_eq!(finding.line_number, 42);
    assert_eq!(finding.pattern_name, "Test Pattern");
    assert_eq!(finding.entropy, Some(3.5));
}
