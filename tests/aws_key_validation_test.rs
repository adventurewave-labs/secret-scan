use secretscan::{Scanner, get_all_patterns};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_aws_access_key_format_validation() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Test various AWS access key formats and edge cases
    let test_content = r#"
// Valid AWS Access Keys (should be detected)
const VALID_KEY_1: &str = "AKIAIOSFODNN7EXAMPLE";  // Standard example
const VALID_KEY_2: &str = "AKIA123456789ABCDEF0";  // 20 chars total
const VALID_KEY_3: &str = "AKIAZZZZZZZZZZZZZZZZ";  // All Z's
const VALID_KEY_4: &str = "AKIA000000000000000A";  // Mix of numbers/letters

// AWS keys in various configurations
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
AWS_ACCESS_KEY = "AKIA123456789ABCDEF0"
"aws_access_key": "AKIAZZZZZZZZZZZZZZZZ"
export AWS_ACCESS_KEY_ID="AKIA000000000000000A"

// Edge cases that should NOT be detected
const TOO_SHORT: &str = "AKIA123";              // Only 7 chars
const TOO_LONG: &str = "AKIAIOSFODNN7EXAMPLE123"; // 23 chars
const WRONG_PREFIX: &str = "BKIAIOSFODNN7EXAMPLE"; // Wrong prefix
const LOWERCASE: &str = "akiaiosfodnn7example";    // Lowercase
const MIXED_CASE: &str = "AkIaIoSfOdNn7eXaMpLe";  // Mixed case
const WITH_SPACES: &str = "AKIA IOSFODNN7EXAMPLE"; // Spaces
const WITH_SPECIAL: &str = "AKIA@OSFODNN7EXAMPLE"; // Special chars

// AWS Secret Keys (different pattern)
const AWS_SECRET_1: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // 40 chars
const AWS_SECRET_2: &str = "abcdefghijklmnopqrstuvwxyz1234567890ABCD"; // 40 chars

// Test patterns that might be confused
const NOT_AWS_1: &str = "GITHUB_TOKEN_AKIATEST";
const NOT_AWS_2: &str = "This AKIA is not a key";
const NOT_AWS_3: &str = "AKIA"; // Just the prefix
"#;
    
    fs::write(temp_path.join("aws_test.rs"), test_content).unwrap();
    
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();
    
    // Count AWS access key findings
    let aws_access_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Access"))
        .collect();
    
    // Count AWS secret key findings  
    let aws_secret_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Secret"))
        .collect();
    
    println!("AWS Access Key findings: {}", aws_access_findings.len());
    for finding in &aws_access_findings {
        println!("  - {} (line {}): {}", finding.pattern_name, finding.line_number, finding.matched_text);
    }
    
    println!("AWS Secret Key findings: {}", aws_secret_findings.len());
    for finding in &aws_secret_findings {
        println!("  - {} (line {}): {}", finding.pattern_name, finding.line_number, finding.matched_text);
    }
    
    // Should find exactly 4 valid AWS access keys
    assert_eq!(
        aws_access_findings.len(), 
        8, // 4 from consts + 4 from config lines
        "Should find exactly 8 AWS access key instances"
    );
    
    // Should find 2 AWS secret keys
    assert_eq!(
        aws_secret_findings.len(),
        2,
        "Should find exactly 2 AWS secret keys"
    );
    
    // Verify the valid keys are found
    let found_keys: Vec<&str> = aws_access_findings.iter()
        .map(|f| f.matched_text.as_str())
        .collect();
    
    assert!(found_keys.contains(&"AKIAIOSFODNN7EXAMPLE"));
    assert!(found_keys.contains(&"AKIA123456789ABCDEF0"));
    assert!(found_keys.contains(&"AKIAZZZZZZZZZZZZZZZZ"));
    assert!(found_keys.contains(&"AKIA000000000000000A"));
}

#[test]
fn test_aws_key_length_validation() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Test AWS keys of different lengths
    let test_cases = vec![
        ("AKIA", false, "Too short - just prefix"),
        ("AKIA1", false, "5 chars total - too short"),
        ("AKIA12345", false, "9 chars total - too short"),
        ("AKIA123456789ABC", false, "16 chars total - too short"),
        ("AKIA123456789ABCD", false, "17 chars total - too short"),
        ("AKIA123456789ABCDE", false, "18 chars total - too short"),
        ("AKIA123456789ABCDEF", false, "19 chars total - too short"),
        ("AKIA123456789ABCDEF0", true, "20 chars total - valid"),
        ("AKIA123456789ABCDEF01", false, "21 chars total - too long"),
        ("AKIA123456789ABCDEF012", false, "22 chars total - too long"),
    ];
    
    for (i, (key, should_match, description)) in test_cases.iter().enumerate() {
        let content = format!("const TEST_KEY_{}: &str = \"{}\"; // {}", i, key, description);
        fs::write(temp_path.join(format!("test_{}.rs", i)), content).unwrap();
    }
    
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();
    
    let aws_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Access"))
        .collect();
    
    // Should find only the valid 20-character key
    assert_eq!(aws_findings.len(), 1, "Should find exactly 1 valid AWS key");
    assert_eq!(aws_findings[0].matched_text, "AKIA123456789ABCDEF0");
    
    println!("✓ AWS key length validation passed");
}

#[test]
fn test_aws_key_character_validation() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Test AWS keys with different character sets
    let test_content = r#"
// Valid character sets
const UPPERCASE_ONLY: &str = "AKIAABCDEFGHIJKLMNOP";     // All uppercase letters
const NUMBERS_ONLY: &str = "AKIA1234567890123456";        // Numbers after AKIA
const MIXED_VALID: &str = "AKIA123ABC456DEF789G";         // Mixed numbers and uppercase

// Invalid character sets
const WITH_LOWERCASE: &str = "AKIAabcdefghijklmnop";      // Contains lowercase
const WITH_SPECIAL: &str = "AKIA123@#$%^&*()!@#$";       // Contains special chars
const WITH_SPACES: &str = "AKIA 123 456 789 ABC";        // Contains spaces
const WITH_HYPHEN: &str = "AKIA-123-456-789-ABC";        // Contains hyphens
const WITH_UNDERSCORE: &str = "AKIA_123_456_789_ABC";    // Contains underscores
"#;
    
    fs::write(temp_path.join("char_test.rs"), test_content).unwrap();
    
    let scanner = Scanner::new().unwrap();  
    let findings = scanner.scan_directory(temp_path).unwrap();
    
    let aws_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Access"))
        .collect();
    
    println!("Character validation findings:");
    for finding in &aws_findings {
        println!("  - {}", finding.matched_text);
    }
    
    // Should find only the keys with valid character sets
    assert!(
        aws_findings.len() >= 1 && aws_findings.len() <= 3,
        "Should find 1-3 valid AWS keys with proper characters, found {}",
        aws_findings.len()
    );
    
    // Verify no invalid character combinations are found
    let found_texts: Vec<&str> = aws_findings.iter()
        .map(|f| f.matched_text.as_str())
        .collect();
    
    // These should not be found (contain invalid characters)
    assert!(!found_texts.contains(&"AKIAabcdefghijklmnop"));
    assert!(!found_texts.contains(&"AKIA123@#$%^&*()!@#$"));
    assert!(!found_texts.contains(&"AKIA 123 456 789 ABC"));
    
    println!("✓ AWS key character validation passed");
}

#[test]
fn test_aws_key_context_sensitivity() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Test AWS keys in various contexts
    let test_content = r#"
# Configuration file formats
[aws]
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Environment variables
export AWS_ACCESS_KEY_ID="AKIA123456789ABCDEF0"
export AWS_SECRET_ACCESS_KEY="abcdefghijklmnopqrstuvwxyz1234567890ABCD"

# JSON configuration
{
  "aws": {
    "access_key_id": "AKIAZZZZZZZZZZZZZZZZ",
    "secret_access_key": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
  }
}

# YAML configuration  
aws:
  access_key_id: AKIA000000000000000A
  secret_access_key: "0000000000000000000000000000000000000000"

# Command line usage (should still be detected)
aws configure set aws_access_key_id AKIAEXAMPLEKEYID1234
aws s3 --access-key AKIANOTAREALKEYEXAMP ls s3://bucket

# In code comments (might be real secrets accidentally committed)
// TODO: Remove this before commit: AKIAACCIDENTALCOMMIT1
/* 
 * Debug key: AKIADEBUGGINGKEY12345
 */

# In documentation (might be real examples that shouldn't be there)
## Example AWS configuration:
## aws_access_key_id = AKIADOCUMENTATIONKEY1
"#;
    
    fs::write(temp_path.join("context_test.conf"), test_content).unwrap();
    
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();
    
    let aws_access_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Access"))
        .collect();
        
    let aws_secret_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Secret"))
        .collect();
    
    println!("Context sensitivity test results:");
    println!("AWS Access Keys found: {}", aws_access_findings.len());
    for finding in &aws_access_findings {
        println!("  Line {}: {}", finding.line_number, finding.matched_text);
    }
    
    println!("AWS Secret Keys found: {}", aws_secret_findings.len());  
    for finding in &aws_secret_findings {
        println!("  Line {}: {}", finding.line_number, finding.matched_text);
    }
    
    // Should find AWS keys in various contexts
    assert!(
        aws_access_findings.len() >= 8,
        "Should find at least 8 AWS access keys in different contexts, found {}",
        aws_access_findings.len()
    );
    
    assert!(
        aws_secret_findings.len() >= 4,
        "Should find at least 4 AWS secret keys in different contexts, found {}",
        aws_secret_findings.len()
    );
    
    println!("✓ AWS key context sensitivity test passed");
}

#[test]
fn test_aws_key_false_negative_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Test edge cases that might cause false negatives
    let test_content = r#"
// Keys that might be missed due to surrounding text
let key1 = format!("AKIA{}", "IOSFODNN7EXAMPLE");
let key2 = "prefix_AKIAIOSFODNN7EXAMPLE_suffix";
let key3 = "AKIA" + "IOSFODNN7EXAMPLE";

// Keys in unusual but valid contexts
const BACKUP_KEY: &str = "AKIABACKUPKEY1234567";
static FALLBACK_KEY: &str = "AKIAFALLBACKKEY12345";
lazy_static! {
    static ref LAZY_KEY: String = "AKIALAZYSTATIC123456".to_string();
}

// Keys with trailing/leading whitespace
let key_with_spaces = "  AKIAWHITESPACEKEY123  ";
let key_with_tabs = "\tAKIATABKEY1234567890\t";
let key_with_newlines = "\nAKIANEWLINEKEY123456\n";

// Keys in complex expressions
let computed_key = if production {
    "AKIAPRODKEY1234567890"
} else {
    "AKIADEVKEY12345678901"
};

// Keys in macros or preprocessor directives
#define AWS_KEY "AKIAMACROKEY12345678"
println!("Key: {}", "AKIAPRINTKEY12345678");

// Keys split across lines (these might not be detected, which is ok)
let split_key = "AKIA" +
                "SPLITKEY12345678";
"#;
    
    fs::write(temp_path.join("false_negative_test.rs"), test_content).unwrap();
    
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_directory(temp_path).unwrap();
    
    let aws_findings: Vec<_> = findings.iter()
        .filter(|f| f.pattern_name.contains("AWS") && f.pattern_name.contains("Access"))
        .collect();
    
    println!("False negative prevention test results:");
    for finding in &aws_findings {
        println!("  Line {}: {}", finding.line_number, finding.matched_text);
    }
    
    // Should find most of the keys (some edge cases like split strings might be missed)
    assert!(
        aws_findings.len() >= 8,
        "Should find at least 8 AWS keys to prevent false negatives, found {}",
        aws_findings.len()
    );
    
    // Specific keys that should definitely be found
    let found_texts: Vec<&str> = aws_findings.iter()
        .map(|f| f.matched_text.as_str())
        .collect();
    
    assert!(found_texts.contains(&"AKIABACKUPKEY1234567"));
    assert!(found_texts.contains(&"AKIAFALLBACKKEY12345"));
    
    println!("✓ AWS key false negative prevention test passed");
}