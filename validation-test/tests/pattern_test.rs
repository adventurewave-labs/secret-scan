use secretscan::patterns::*;

#[test]
fn test_aws_access_key_pattern() {
    let patterns = get_all_patterns();
    let pattern = patterns.get("AWS Access Key").unwrap();

    // Valid AWS access keys
    assert!(pattern.is_match("AKIAIOSFODNN7EXAMPLE"));
    assert!(pattern.is_match("AKIA1234567890ABCDEF"));
    assert!(pattern.is_match("AKIAJKLMNOPQRSTUVWXY"));

    // Invalid patterns
    assert!(!pattern.is_match("BKIAIOSFODNN7EXAMPLE"));
    assert!(!pattern.is_match("AKIAIOSFODNN7EXAMPL"));
    assert!(!pattern.is_match("akiaiosfodnn7example"));
}

#[test]
fn test_github_token_pattern() {
    let patterns = get_all_patterns();
    let pattern = patterns.get("GitHub Token").unwrap();

    // Valid GitHub tokens
    assert!(pattern.is_match("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
    assert!(pattern.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));

    // Invalid patterns
    assert!(!pattern.is_match("gho_1234567890abcdefghijklmnopqrstuvwxyz"));
    assert!(!pattern.is_match("ghp_12345"));
    assert!(!pattern.is_match("ghp_1234567890abcdefghijklmnopqrstuvwxy"));
}

#[test]
fn test_google_api_key_pattern() {
    let patterns = get_all_patterns();
    let pattern = patterns.get("Google API Key").unwrap();

    // Valid Google API keys
    assert!(pattern.is_match("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"));
    assert!(pattern.is_match("AIzaBCDEFGHIJKLMNOPQRSTUVWXYZ-1234567"));
    assert!(pattern.is_match("AIza1234567890abcdefghijklmnopqrstuvw_x"));

    // Invalid patterns
    assert!(!pattern.is_match("BIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"));
    assert!(!pattern.is_match("AIza12345"));
    assert!(!pattern.is_match("aizasyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"));
}

#[test]
fn test_all_patterns_combined() {
    let patterns = get_all_patterns();

    assert!(patterns.len() >= 3);

    let test_text = "AKIAIOSFODNN7EXAMPLE and ghp_1234567890abcdefghijklmnopqrstuvwxyz and AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";

    let mut matches = 0;
    for (_name, pattern) in patterns.iter() {
        if pattern.is_match(test_text) {
            matches += 1;
        }
    }

    assert_eq!(matches, 3);
}
