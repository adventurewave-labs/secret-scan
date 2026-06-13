use secretscan::patterns::get_all_patterns;

#[test]
fn test_aws_access_key_pattern_matches_integration_test_data() {
    let patterns = get_all_patterns();
    let aws_pattern = patterns.get("AWS Access Key").expect("AWS Access Key pattern should exist");
    
    // This is the exact line from the integration test that was failing
    let test_line = r#"pub const AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";"#;
    
    // The pattern should match this line
    let result = aws_pattern.find(test_line);
    assert!(result.is_some(), "AWS Access Key pattern should match integration test data");
    
    let matched = result.unwrap();
    let matched_text = matched.as_str();
    
    // The match should contain the key
    assert!(matched_text.contains("AKIAIOSFODNN7EXAMPLE"), 
           "Matched text should contain the test key: {}", matched_text);
    
    // Test other common formats too
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
    
    // Test direct key matching
    let direct_key = "AKIAIOSFODNN7EXAMPLE";
    let result = aws_id_pattern.find(direct_key);
    assert!(result.is_some(), "AWS Access Key ID pattern should match direct key");
    
    let matched = result.unwrap();
    assert_eq!(matched.as_str(), direct_key, "Should match the entire key");
}

#[test]
fn test_aws_patterns_handle_mixed_case() {
    let patterns = get_all_patterns();
    let aws_pattern = patterns.get("AWS Access Key").expect("AWS Access Key pattern should exist");
    let aws_id_pattern = patterns.get("AWS Access Key ID").expect("AWS Access Key ID pattern should exist");
    
    // Test keys with mixed case (which was the original issue)
    let mixed_case_keys = vec![
        "AKIAiosfodnn7example", // lowercase after AKIA
        "AKIAIoSfOdNn7ExAmPlE", // mixed case
        "AKIAIOSFODNN7EXAMPLE", // all uppercase
    ];
    
    for key in mixed_case_keys {
        // Test the AWS_ACCESS_KEY_ID pattern (direct key matching)
        let result = aws_id_pattern.find(key);
        assert!(result.is_some(), "AWS Access Key ID pattern should match mixed case key: {}", key);
        
        // Test in context
        let in_context = format!(r#"const key: &str = "{}";"#, key);
        let context_result = aws_pattern.find(&in_context);
        assert!(context_result.is_some(), "AWS Access Key pattern should match mixed case key in context: {}", in_context);
    }
}

#[test]
fn test_aws_patterns_reject_invalid_keys() {
    let patterns = get_all_patterns();
    let aws_id_pattern = patterns.get("AWS Access Key ID").expect("AWS Access Key ID pattern should exist");
    
    // Keys that should NOT match
    let invalid_keys = vec![
        "AKIA123", // too short
        "AKIAIOSFODNN7EXAMPLEEXTRALONGTEXTTHATSHOULDFAIL", // too long
        "BKIAIOSFODNN7EXAMPLE", // doesn't start with AKIA
        "AKIAiosfodnn7exampl", // too short (15 chars after AKIA)
    ];
    
    for invalid_key in invalid_keys {
        let result = aws_id_pattern.find(invalid_key);
        assert!(result.is_none(), "AWS pattern should NOT match invalid key: {}", invalid_key);
    }
}