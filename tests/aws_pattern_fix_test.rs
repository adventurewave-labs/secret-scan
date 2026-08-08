use secretscan::get_all_patterns;

// AWS access key IDs are exactly 20 characters: the literal prefix AKIA followed by
// 16 uppercase alphanumerics. These tests pin that format. (An earlier version of this
// file asserted case-INsensitive matching — that "fix" made the scanner report strings
// that cannot be live AWS keys, and contradicted aws_key_validation_test.)

#[test]
fn test_aws_access_key_pattern_matches_integration_test_data() {
    let patterns = get_all_patterns();
    let aws_pattern = patterns.get("AWS Access Key").expect("AWS Access Key pattern should exist");

    // The exact line format used in integration tests
    let test_line = r#"pub const AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";"#;
    let result = aws_pattern.find(test_line);
    assert!(result.is_some(), "AWS Access Key pattern should match integration test data");

    let matched_text = result.unwrap().as_str();
    assert!(matched_text.contains("AKIAIOSFODNN7EXAMPLE"),
        "Match should contain the key, got: {}", matched_text);

    // Test additional aws-named assignment forms
    let test_cases = vec![
        r#"AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE""#,
        r#"aws_access_key: "AKIAIOSFODNN7EXAMPLE""#,
        r#"const AWS_ACCESS_KEY_ID: string = "AKIAIOSFODNN7EXAMPLE";"#,
    ];
    for test_case in test_cases {
        let result = aws_pattern.find(test_case);
        assert!(result.is_some(), "AWS pattern should match: {}", test_case);
    }
}

#[test]
fn test_aws_access_key_id_pattern_matches_direct_keys() {
    let patterns = get_all_patterns();
    let aws_id_pattern = patterns.get("AWS Access Key ID").expect("AWS Access Key ID pattern should exist");

    let direct_key = "AKIAIOSFODNN7EXAMPLE";
    let result = aws_id_pattern.find(direct_key);
    assert!(result.is_some(), "AWS Access Key ID pattern should match direct key");

    let matched = result.unwrap();
    assert_eq!(matched.as_str(), direct_key, "Should match the entire key");
}

#[test]
fn test_aws_patterns_are_case_sensitive() {
    let patterns = get_all_patterns();
    let aws_id_pattern = patterns.get("AWS Access Key ID").expect("AWS Access Key ID pattern should exist");

    // Real AWS key IDs are uppercase-only after the AKIA prefix. Lowercase or
    // mixed-case strings cannot be live keys and must not be reported.
    let invalid_case_keys = vec![
        "AKIAiosfodnn7example", // lowercase after AKIA
        "AKIAIoSfOdNn7ExAmPlE", // mixed case
        "akiaiosfodnn7example", // fully lowercase
    ];
    for key in invalid_case_keys {
        assert!(aws_id_pattern.find(key).is_none(),
            "AWS Access Key ID pattern should NOT match non-uppercase key: {}", key);
    }

    // The canonical uppercase form matches, bare and in context
    assert!(aws_id_pattern.find("AKIAIOSFODNN7EXAMPLE").is_some());
    assert!(aws_id_pattern.find(r#"const key: &str = "AKIAIOSFODNN7EXAMPLE";"#).is_some());
}

#[test]
fn test_aws_patterns_reject_invalid_keys() {
    let patterns = get_all_patterns();
    let aws_id_pattern = patterns.get("AWS Access Key ID").expect("AWS Access Key ID pattern should exist");

    let invalid_keys = vec![
        "AKIA123", // too short
        "AKIAIOSFODNN7EXAMPLEEXTRALONGTEXTTHATSHOULDFAIL", // too long — no 20-char boundary
        "BKIAIOSFODNN7EXAMPLE", // doesn't start with AKIA
        "AKIAiosfodnn7exampl",  // wrong case and too short
    ];
    for invalid_key in invalid_keys {
        let result = aws_id_pattern.find(invalid_key);
        assert!(result.is_none(), "AWS pattern should NOT match invalid key: {}", invalid_key);
    }
}
