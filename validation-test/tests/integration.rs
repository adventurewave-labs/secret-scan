use secretscan::{ContextFilter, Scanner};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_end_to_end_secrets_detection() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Initialize git repository
    Command::new("git")
        .arg("init")
        .current_dir(temp_path)
        .output()
        .unwrap();

    // Create a realistic project structure
    fs::create_dir_all(temp_path.join("src")).unwrap();
    fs::create_dir_all(temp_path.join("config")).unwrap();

    // Create files with secrets
    fs::write(
        temp_path.join("src/config.rs"),
        r#"
pub const DATABASE_URL: &str = "postgres://user:pass@localhost/db";
pub const AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const API_ENDPOINT: &str = "https://api.example.com";
"#,
    )
    .unwrap();

    fs::write(
        temp_path.join("config/production.env"),
        r#"
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
GOOGLE_API_KEY=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI
DATABASE_PASSWORD=secure_password_123
"#,
    )
    .unwrap();

    // Create normal files without secrets
    fs::write(
        temp_path.join("src/main.rs"),
        r#"
fn main() {
    println!("Hello, world!");
    let api_key = std::env::var("API_KEY").expect("API_KEY not set");
    println!("Using API key: {}", api_key);
}
"#,
    )
    .unwrap();

    // Scan the directory
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Verify we found the expected secrets
    assert!(
        findings.len() >= 3,
        "Should find at least 3 secrets, found {}",
        findings.len()
    );

    // Check that we found specific pattern types
    let aws_keys: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name == "AWS Access Key ID")
        .collect();
    let github_tokens: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name == "GitHub Token")
        .collect();
    let google_keys: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name == "Google API Key")
        .collect();

    assert_eq!(aws_keys.len(), 1, "Should find exactly 1 AWS access key");
    assert_eq!(github_tokens.len(), 1, "Should find exactly 1 GitHub token");
    assert_eq!(google_keys.len(), 1, "Should find exactly 1 Google API key");

    // Verify file paths are correct
    assert!(aws_keys[0].file_path.ends_with("src/config.rs"));
    assert!(github_tokens[0]
        .file_path
        .ends_with("config/production.env"));
    assert!(google_keys[0].file_path.ends_with("config/production.env"));
}

#[test]
fn test_gitignore_integration() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Initialize git repository
    Command::new("git")
        .arg("init")
        .current_dir(temp_path)
        .output()
        .unwrap();

    // Create .gitignore
    fs::write(
        temp_path.join(".gitignore"),
        r#"
# Ignore sensitive files
*.env
secrets/
config/private.conf
"#,
    )
    .unwrap();

    // Create directories
    fs::create_dir_all(temp_path.join("secrets")).unwrap();
    fs::create_dir_all(temp_path.join("config")).unwrap();

    // Create ignored files with secrets
    fs::write(
        temp_path.join("secrets/prod.env"),
        "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
    )
    .unwrap();

    fs::write(
        temp_path.join("config/private.conf"),
        "github_token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    fs::write(
        temp_path.join("development.env"),
        "GOOGLE_API_KEY=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",
    )
    .unwrap();

    // Create non-ignored file with secret
    fs::write(
        temp_path.join("config/public.conf"),
        "api_token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    )
    .unwrap();

    // Scan the directory
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should only find the secret in the non-ignored file
    assert_eq!(
        findings.len(),
        1,
        "Should find exactly 1 secret (others ignored), found {}",
        findings.len()
    );
    assert!(findings[0].file_path.ends_with("config/public.conf"));
    assert_eq!(findings[0].pattern_name, "GitHub Token");
}

#[test]
fn test_false_positive_rate() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create files with strings that look like secrets but aren't
    let false_positive_content = r#"
// These should NOT be flagged as secrets
let placeholder_key = "AKIA_PLACEHOLDER_KEY_123";
let example_token = "ghp_example_token_not_real";
let test_api_key = "AIza_test_key_for_documentation";
let fake_secret = "fake_secret_value";
let example_password = "example_password_123";
let demo_token = "demo_token_abc123";
let sample_api = "sample_api_key_xyz789";

// Template strings
const TEMPLATE = "Your API key: ${API_KEY}";
const EXAMPLE = "AKIA${RANDOM_CHARS}";

// Comments and documentation
# AWS_ACCESS_KEY=your_key_here
# GITHUB_TOKEN=your_token_here
// TODO: Replace with real API_KEY

// Short strings that might match patterns partially
let short = "AKIA";
let partial = "ghp_";
let incomplete = "AIza";
"#;

    fs::write(temp_path.join("examples.rs"), false_positive_content).unwrap();

    // Create a few files with legitimate content
    fs::write(
        temp_path.join("readme.md"),
        r#"
# Secretscan

This tool scans for secrets like:
- AWS access keys (format: AKIA...)
- GitHub tokens (format: ghp_...)
- Google API keys (format: AIza...)

## Usage

```bash
secretscan /path/to/scan
```
"#,
    )
    .unwrap();

    fs::write(
        temp_path.join("constants.rs"),
        r#"
pub const MAX_FILE_SIZE: usize = 1024 * 1024;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const API_VERSION: &str = "v1";
"#,
    )
    .unwrap();

    // Scan the directory
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Calculate false positive rate
    let total_lines = false_positive_content.lines().count() + 20; // approximate total lines
    let false_positive_rate = findings.len() as f64 / total_lines as f64;

    // Should have very low false positive rate (< 10%)
    assert!(
        false_positive_rate < 0.1,
        "False positive rate too high: {:.2}% ({} findings in ~{} lines)",
        false_positive_rate * 100.0,
        findings.len(),
        total_lines
    );

    // Print findings for debugging if any
    if !findings.is_empty() {
        eprintln!("False positive findings:");
        for finding in &findings {
            eprintln!("  - {}: {}", finding.pattern_name, finding.matched_text);
        }
    }
}

#[test]
fn test_nested_directory_scanning() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create deep nested structure
    let deep_path = temp_path.join("src/components/auth/providers");
    fs::create_dir_all(&deep_path).unwrap();

    // Place secret in deeply nested file
    fs::write(
        deep_path.join("oauth.rs"),
        r#"
use std::env;

pub struct OAuthProvider {
    client_id: String,
    client_secret: String,
}

impl OAuthProvider {
    pub fn new() -> Self {
        Self {
            client_id: "public_client_id".to_string(),
            client_secret: "AKIAIOSFODNN7EXAMPLE".to_string(), // This should be found
        }
    }
}
"#,
    )
    .unwrap();

    // Scan from root
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].file_path.to_string_lossy().contains("oauth.rs"));
    assert_eq!(findings[0].pattern_name, "AWS Access Key ID");
}

#[test]
fn test_performance_with_large_files() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create a large file with one secret at the end
    let mut large_content = String::new();
    for i in 0..1000 {
        large_content.push_str(&format!("// Line {} with normal content\n", i));
        large_content.push_str(&format!("let variable_{} = \"some_value_{}\";\n", i, i));
    }
    large_content.push_str("let aws_key = \"AKIAIOSFODNN7EXAMPLE\"; // Secret at the end\n");

    fs::write(temp_path.join("large_file.rs"), large_content).unwrap();

    // Time the scan
    let start = std::time::Instant::now();
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();
    let duration = start.elapsed();

    // Should find the secret
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].pattern_name, "AWS Access Key ID");
    assert_eq!(findings[0].line_number, 2001); // At the end

    // Should be reasonably fast (less than 30 seconds for this test with many patterns)
    assert!(
        duration.as_secs() < 30,
        "Scanning took too long: {:?}",
        duration
    );
}

#[test]
fn test_binary_file_handling() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create a binary file (should be skipped or handled gracefully)
    let binary_data: Vec<u8> = vec![0, 1, 2, 3, 255, 254, 253];
    fs::write(temp_path.join("binary.bin"), binary_data).unwrap();

    // Create a text file with secret
    fs::write(
        temp_path.join("text.txt"),
        "github_token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    // Scan should not crash and should find the text secret
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should find only the text secret, binary file should be handled gracefully
    assert_eq!(findings.len(), 1);
    assert!(findings[0].file_path.ends_with("text.txt"));
}

#[test]
fn test_context_filtering() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create test directory structure
    fs::create_dir_all(temp_path.join("src")).unwrap();
    fs::create_dir_all(temp_path.join("tests")).unwrap();
    fs::create_dir_all(temp_path.join("examples")).unwrap();
    fs::create_dir_all(temp_path.join("docs")).unwrap();

    // Create real secrets in production code
    fs::write(
        temp_path.join("src/config.rs"),
        r#"
pub const PROD_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const PROD_GITHUB_TOKEN: &str = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
"#,
    )
    .unwrap();

    // Create test files with fake secrets that should be filtered
    fs::write(
        temp_path.join("tests/test_config.rs"),
        r#"
const TEST_AWS_KEY: &str = "AKIATEST123456789EXAMPLE";
const TEST_GITHUB_TOKEN: &str = "ghp_testtoken1234567890abcdefghijklmn";
let dummy_secret = "AKIADUMMY12345678EXAMPLE";
"#,
    )
    .unwrap();

    // Create example files with demo secrets that should be filtered
    fs::write(
        temp_path.join("examples/demo.rs"),
        r#"
// Example configuration
let example_aws_key = "AKIAEXAMPLE123456789TEST";
let sample_github_token = "ghp_sampletoken1234567890abcdefghijk";
"#,
    )
    .unwrap();

    // Create documentation with example secrets that should be filtered
    fs::write(
        temp_path.join("docs/readme.md"),
        r#"
# Configuration

Set your AWS key:
```
AWS_ACCESS_KEY=AKIADOCUMENTATION123456789
GITHUB_TOKEN=ghp_documentationtoken1234567890
```
"#,
    )
    .unwrap();

    // Create file with test variable names that should be filtered
    fs::write(
        temp_path.join("src/test_helpers.rs"),
        r#"
let test_secret = "AKIATEST123456789EXAMPLE";
let mock_token = "ghp_mocktoken1234567890abcdefghijklmn";
let fake_api_key = "AKIAFAKE123456789EXAMPLE";
let dummy_password = "password123";
let placeholder_key = "changeme";
"#,
    )
    .unwrap();

    // Test with context filtering ENABLED (default)
    let mut scanner_with_filter = Scanner::new().unwrap();
    scanner_with_filter.set_context_filter(ContextFilter::new());
    let findings_filtered = scanner_with_filter.scan_directory(temp_path).unwrap();

    // Test with context filtering DISABLED
    let mut scanner_no_filter = Scanner::new().unwrap();
    scanner_no_filter.set_context_filter(ContextFilter::none());
    let findings_unfiltered = scanner_no_filter.scan_directory(temp_path).unwrap();

    // With filtering, should only find the real secrets in src/config.rs
    assert_eq!(
        findings_filtered.len(),
        2,
        "With filtering should find only 2 real secrets, found {}",
        findings_filtered.len()
    );

    // Verify the filtered findings are from the production config file
    for finding in &findings_filtered {
        assert!(
            finding.file_path.ends_with("src/config.rs"),
            "Filtered scan should only find secrets in src/config.rs, found in {:?}",
            finding.file_path
        );
        assert!(
            finding.matched_text.contains("AKIAIOSFODNN7EXAMPLE")
                || finding
                    .matched_text
                    .contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
            "Should only find real production secrets, found {}",
            finding.matched_text
        );
    }

    // Without filtering, should find many more secrets including test ones
    assert!(
        findings_unfiltered.len() > findings_filtered.len(),
        "Unfiltered scan should find more secrets than filtered scan. Filtered: {}, Unfiltered: {}",
        findings_filtered.len(),
        findings_unfiltered.len()
    );

    // Without filtering should find secrets in test directories
    let test_file_findings: Vec<_> = findings_unfiltered
        .iter()
        .filter(|f| f.file_path.to_string_lossy().contains("tests/"))
        .collect();
    assert!(
        !test_file_findings.is_empty(),
        "Unfiltered scan should find secrets in test files"
    );

    // Print findings for debugging
    println!("Filtered findings ({}):", findings_filtered.len());
    for finding in &findings_filtered {
        println!("  {:?}: {}", finding.file_path, finding.matched_text);
    }

    println!("Unfiltered findings ({}):", findings_unfiltered.len());
    for finding in &findings_unfiltered {
        println!("  {:?}: {}", finding.file_path, finding.matched_text);
    }
}

#[test]
fn test_specific_test_patterns() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create file with various test patterns that should be filtered
    fs::write(
        temp_path.join("patterns.rs"),
        r#"
// These should be filtered out
let test_api_key = "AKIATEST123456789EXAMPLE";
let dummy_secret = "ghp_dummy1234567890abcdefghijklmnop";
let fake_token = "AKIAFAKE123456789EXAMPLE";
let example_key = "AIzaExample1234567890abcdefghijk";
let mock_password = "password123";
let sample_data = "secret123";
let placeholder = "changeme";

// Common test value patterns
let repeated_key = "aaaaaaaaaaaaaaaaaaaaa";
let pattern_key = "123123123123123123123";
let test_default = "testSecret";
let demoValue = "demoToken";

// These should NOT be filtered (real secrets)
let prod_key = "AKIAPROD567890123456";  // 20 chars total (AKIA + 16)
let live_token = "ghp_live9876543210zyxwvutsrqponmlkji1234";  // 40 chars total (ghp_ + 36)
"#,
    )
    .unwrap();

    // Test with filtering enabled
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::new());
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should only find the real secrets at the end
    assert_eq!(
        findings.len(),
        2,
        "Should find only 2 real secrets, found {}. Findings: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.matched_text).collect::<Vec<_>>()
    );

    // Verify we found the real secrets
    let found_texts: Vec<&String> = findings.iter().map(|f| &f.matched_text).collect();
    assert!(
        found_texts.contains(&&"AKIAPROD567890123456".to_string()),
        "Should find the real AWS key"
    );
    assert!(
        found_texts.contains(&&"ghp_live9876543210zyxwvutsrqponmlkji1234".to_string()),
        "Should find the real GitHub token"
    );
}

#[test]
fn test_directory_path_filtering() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create various directory structures that should be filtered
    let filtered_dirs = vec![
        "tests/unit",
        "tests/integration",
        "__tests__/components",
        "spec/helpers",
        "examples/basic",
        "examples/advanced",
        "demo/simple",
        "samples/full",
        "docs/api",
        "documentation/guides",
    ];

    let unfiltered_dirs = vec!["src/main", "lib/core", "config/prod", "scripts/deploy"];

    // Create secrets in directories that should be filtered
    for dir in &filtered_dirs {
        fs::create_dir_all(temp_path.join(dir)).unwrap();
        fs::write(
            temp_path.join(dir).join("config.rs"),
            format!(
                "const SECRET_{}: &str = \"AKIA123456789EXAMPLE\";",
                dir.replace("/", "_").to_uppercase()
            ),
        )
        .unwrap();
    }

    // Create secrets in directories that should NOT be filtered
    for dir in &unfiltered_dirs {
        fs::create_dir_all(temp_path.join(dir)).unwrap();
        fs::write(
            temp_path.join(dir).join("config.rs"),
            format!(
                "const REAL_{}: &str = \"AKIA123456789REALKEY\";",
                dir.replace("/", "_").to_uppercase()
            ),
        )
        .unwrap();
    }

    // Test with filtering
    let mut scanner_filtered = Scanner::new().unwrap();
    scanner_filtered.set_context_filter(ContextFilter::new());
    let findings_filtered = scanner_filtered.scan_directory(temp_path).unwrap();

    // Test without filtering
    let mut scanner_unfiltered = Scanner::new().unwrap();
    scanner_unfiltered.set_context_filter(ContextFilter::none());
    let findings_unfiltered = scanner_unfiltered.scan_directory(temp_path).unwrap();

    // Should find only secrets in non-filtered directories
    assert_eq!(
        findings_filtered.len(),
        unfiltered_dirs.len(),
        "Should find {} secrets (one per non-filtered dir), found {}",
        unfiltered_dirs.len(),
        findings_filtered.len()
    );

    // Should find all secrets when filtering is disabled
    assert_eq!(
        findings_unfiltered.len(),
        filtered_dirs.len() + unfiltered_dirs.len(),
        "Without filtering should find {} secrets total, found {}",
        filtered_dirs.len() + unfiltered_dirs.len(),
        findings_unfiltered.len()
    );

    // Verify filtered findings are only from non-filtered directories
    for finding in &findings_filtered {
        let path_str = finding.file_path.to_string_lossy();
        let is_in_filtered_dir = filtered_dirs.iter().any(|dir| path_str.contains(dir));
        assert!(
            !is_in_filtered_dir,
            "Found secret in filtered directory: {}",
            path_str
        );

        let is_in_unfiltered_dir = unfiltered_dirs.iter().any(|dir| path_str.contains(dir));
        assert!(
            is_in_unfiltered_dir,
            "Secret should be in unfiltered directory: {}",
            path_str
        );
    }
}

#[test]
fn test_jwt_token_detection() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create files with JWT tokens
    let jwt_content = r#"
// Valid JWT tokens
let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
let another_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQ2MjIyfQ.B_8O4i0GjhRaXjVPWzlMHJq-vj-w1o2y_mLdTqK2v4s4-dJ-K9jO6wW0t8wK4o3vQ0g9Y_ZfcHb3OzqgEhWjNg";

// Should not match these
let incomplete_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
let malformed_jwt = "eyJ.malformed.jwt";
let not_jwt = "this-is-not-a-jwt-token";
"#;
    fs::write(temp_path.join("auth.rs"), jwt_content).unwrap();

    // JWT in config file
    let config_content = r#"{
  "auth": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA0MjM5MDIyLCJleHAiOjE1MDQzMjU0MjJ9.v3Tpu0nI2OqG3e7YwvLTQVWZIjc3_sBKa_vP7LGKgYw"
  }
}"#;
    fs::write(temp_path.join("config.json"), config_content).unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should find 3 JWT tokens
    let jwt_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name == "JWT Token")
        .collect();

    assert_eq!(
        jwt_findings.len(),
        3,
        "Should find exactly 3 JWT tokens, found {}",
        jwt_findings.len()
    );

    // Verify JWT tokens start with eyJ
    for finding in &jwt_findings {
        assert!(
            finding.matched_text.starts_with("eyJ"),
            "JWT token should start with eyJ, found: {}",
            finding.matched_text
        );
    }
}

#[test]
fn test_private_key_detection() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create RSA private key file
    let rsa_key_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0vOQKjJJJJ6cJYvYGcP5nY4Y5nI1qM8YrW8yXz+oJ8QJQJQJ\n-----END RSA PRIVATE KEY-----";
    fs::write(temp_path.join("rsa_key.pem"), rsa_key_content).unwrap();

    // Create EC private key file
    let ec_key_content = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKCPgXFNJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJoAoGCCqGSM49\n-----END EC PRIVATE KEY-----";
    fs::write(temp_path.join("ec_key.pem"), ec_key_content).unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should find 2 private keys total
    let private_key_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name.contains("Private"))
        .collect();

    assert!(
        private_key_findings.len() >= 2,
        "Should find at least 2 private keys, found {}",
        private_key_findings.len()
    );
}

#[test]
fn test_database_url_detection() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    // Create configuration file with database URLs
    let config_content = r#"
DATABASE_URL=postgres://user:password@localhost:5432/mydb
POSTGRES_URL=postgres://admin:secret123@prod.example.com:5432/production
MYSQL_URL=mysql://root:mypass@127.0.0.1:3306/app_db
MONGODB_URL=mongodb://user:pass@cluster.example.com:27017/myapp
MONGO_CONNECTION=mongodb://admin:adminpass@mongodb.example.com:27017/logs
HTTP_URL=https://api.example.com/v1/users
"#;
    fs::write(temp_path.join("database.config"), config_content).unwrap();

    // Create environment file
    let env_content = r#"
POSTGRES_DATABASE_URL=postgres://appuser:apppass@db.company.com:5432/app
MYSQL_DATABASE_URL=mysql://webapp:webpass@mysql.company.com:3306/webapp
MONGODB_DATABASE_URL=mongodb://analytics:analyticspass@mongo.company.com:27017/analytics
"#;
    let env_filename = format!(".{}", "env");
    fs::write(temp_path.join(env_filename), env_content).unwrap();

    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();

    // Should find database URLs
    let db_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern_name.contains("URL"))
        .collect();

    assert!(
        db_findings.len() >= 5,
        "Should find at least 5 database URLs, found {}",
        db_findings.len()
    );

    // Verify we found different types
    let postgres_found = db_findings
        .iter()
        .any(|f| f.matched_text.starts_with("postgres://"));
    let mysql_found = db_findings
        .iter()
        .any(|f| f.matched_text.starts_with("mysql://"));
    let mongodb_found = db_findings
        .iter()
        .any(|f| f.matched_text.starts_with("mongodb://"));

    assert!(postgres_found, "Should find PostgreSQL URLs");
    assert!(mysql_found, "Should find MySQL URLs");
    assert!(mongodb_found, "Should find MongoDB URLs");
}
