use secretscan::{Scanner, get_all_patterns, get_all_patterns_owned};
use std::collections::HashMap;

#[test]
fn test_pattern_name_consistency() {
    // Test that get_all_patterns() and get_all_patterns_owned() return the same pattern names
    let static_patterns = get_all_patterns();
    let owned_patterns = get_all_patterns_owned();
    
    // Should have the same number of patterns
    assert_eq!(
        static_patterns.len(), 
        owned_patterns.len(),
        "Static and owned pattern collections should have same length"
    );
    
    // Should have the same pattern names
    let static_names: std::collections::HashSet<_> = static_patterns.keys().collect();
    let owned_names: std::collections::HashSet<_> = owned_patterns.keys().collect();
    
    assert_eq!(
        static_names, 
        owned_names,
        "Static and owned pattern collections should have same pattern names"
    );
}

#[test]
fn test_pattern_compilation() {
    // Test that all patterns compile successfully
    let patterns = get_all_patterns_owned();
    
    for (name, pattern) in patterns {
        // Pattern should be valid regex (already compiled, so this tests they work)
        let test_string = "test string for pattern validation";
        let result = pattern.find(test_string);
        // We don't care about the result, just that it doesn't panic
        drop(result);
        
        println!("✓ Pattern '{}' compiles successfully", name);
    }
}

#[test]
fn test_aws_access_key_pattern_variants() {
    let scanner = Scanner::new().unwrap();
    let patterns = get_all_patterns();
    
    // Test various AWS access key formats
    let test_cases = vec![
        // Standard AWS access key format
        ("AKIAIOSFODNN7EXAMPLE", true, "Standard AWS access key"),
        ("AKIA123456789ABCDEF0", true, "20-character AWS access key"),
        
        // AWS access key in configuration
        ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", true, "AWS key in config"),
        ("AWS_ACCESS_KEY=AKIA123456789ABCDEF0", true, "AWS key as env var"),
        ("\"aws_access_key\": \"AKIAIOSFODNN7EXAMPLE\"", true, "AWS key in JSON"),
        
        // Invalid formats
        ("AKIA123", false, "Too short"),
        ("BKIAIOSFODNN7EXAMPLE", false, "Wrong prefix"),
        ("akia123456789abcdef0", false, "Lowercase"),
        ("AKIAIOSFODNN7EXAMPLE123", false, "Too long"),
    ];
    
    for (test_input, should_match, description) in test_cases {
        let aws_patterns: Vec<_> = patterns.iter()
            .filter(|(name, _)| name.contains("AWS") && name.contains("Access"))
            .collect();
        
        let mut found_match = false;
        for (pattern_name, pattern) in aws_patterns {
            if pattern.is_match(test_input) {
                found_match = true;
                println!("✓ '{}' matched by pattern '{}': {}", test_input, pattern_name, description);
                break;
            }
        }
        
        if should_match {
            assert!(found_match, "Expected '{}' to match AWS pattern ({})", test_input, description);
        } else {
            assert!(!found_match, "Expected '{}' NOT to match AWS pattern ({})", test_input, description);
        }
    }
}

#[test]
fn test_github_token_pattern_variants() {
    let patterns = get_all_patterns();
    
    let test_cases = vec![
        // Valid GitHub tokens
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", true, "Personal access token"),
        ("gho_1234567890abcdefghijklmnopqrstuvwxyz", true, "OAuth token"),
        ("ghu_1234567890abcdefghijklmnopqrstuvwxyz", true, "User token"),
        ("ghs_1234567890abcdefghijklmnopqrstuvwxyz", true, "Server token"),
        ("ghr_1234567890abcdefghijklmnopqrstuvwxyz", true, "Refresh token"),
        
        // In various contexts
        ("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz", true, "In environment"),
        ("\"github_token\": \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"", true, "In JSON"),
        
        // Invalid formats
        ("ghx_1234567890abcdefghijklmnopqrstuvwxyz", false, "Invalid prefix"),
        ("ghp_12345", false, "Too short"),
        ("GHP_1234567890abcdefghijklmnopqrstuvwxyz", false, "Uppercase"),
    ];
    
    for (test_input, should_match, description) in test_cases {
        let github_patterns: Vec<_> = patterns.iter()
            .filter(|(name, _)| name.contains("GitHub"))
            .collect();
        
        let mut found_match = false;
        for (pattern_name, pattern) in github_patterns {
            if pattern.is_match(test_input) {
                found_match = true;
                println!("✓ '{}' matched by pattern '{}': {}", test_input, pattern_name, description);
                break;
            }
        }
        
        if should_match {
            assert!(found_match, "Expected '{}' to match GitHub pattern ({})", test_input, description);
        } else {
            assert!(!found_match, "Expected '{}' NOT to match GitHub pattern ({})", test_input, description);
        }
    }
}

#[test]
fn test_google_api_key_pattern() {
    let patterns = get_all_patterns();
    
    let test_cases = vec![
        // Valid Google API keys
        ("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", true, "Standard Google API key"),
        ("AIzaBCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", true, "Another valid key"),
        
        // In configuration
        ("GOOGLE_API_KEY=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", true, "In environment"),
        ("google_api_key: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", true, "In YAML"),
        
        // Invalid formats
        ("AIza123", false, "Too short"),
        ("BIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", false, "Wrong prefix"),
        ("aizaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", false, "Lowercase"),
    ];
    
    for (test_input, should_match, description) in test_cases {
        let google_patterns: Vec<_> = patterns.iter()
            .filter(|(name, _)| name.contains("Google") && name.contains("API"))
            .collect();
        
        let mut found_match = false;
        for (pattern_name, pattern) in google_patterns {
            if pattern.is_match(test_input) {
                found_match = true;
                println!("✓ '{}' matched by pattern '{}': {}", test_input, pattern_name, description);
                break;
            }
        }
        
        if should_match {
            assert!(found_match, "Expected '{}' to match Google API pattern ({})", test_input, description);
        } else {
            assert!(!found_match, "Expected '{}' NOT to match Google API pattern ({})", test_input, description);
        }
    }
}

#[test]
fn test_pattern_coverage() {
    let patterns = get_all_patterns();
    
    // Ensure we have expected categories of patterns
    let expected_categories = vec![
        "AWS", "GitHub", "Google", "JWT", "Private Key", "PostgreSQL", "MySQL", 
        "MongoDB", "Redis", "OpenAI", "Stripe", "SendGrid", "Slack", "Twilio",
        "Mailgun", "Firebase", "DigitalOcean", "Azure", "PayPal", "Password",
        "Connection", "Database", "Base64", "Hex", "Discord", "Shopify", "GitLab"
    ];
    
    for category in expected_categories {
        let found_patterns: Vec<_> = patterns.iter()
            .filter(|(name, _)| name.contains(category))
            .collect();
        
        assert!(
            !found_patterns.is_empty(),
            "Should have at least one pattern for category '{}'",
            category
        );
        
        println!("✓ Found {} patterns for category '{}'", found_patterns.len(), category);
    }
    
    // Ensure we have a reasonable number of patterns
    assert!(
        patterns.len() >= 40,
        "Should have at least 40 patterns, found {}",
        patterns.len()
    );
    
    println!("✓ Total patterns: {}", patterns.len());
}

#[test]
fn test_pattern_specificity() {
    // Test that patterns are specific enough to avoid excessive false positives
    let patterns = get_all_patterns();
    
    let common_false_positives = vec![
        "password",
        "secret",
        "key",
        "token",
        "api",
        "config",
        "test",
        "example",
        "demo",
        "sample",
        "123456789",
        "abcdefghijklmnop",
        "EXAMPLE",
        "placeholder",
        "your_key_here",
        "changeme",
    ];
    
    for test_string in common_false_positives {
        let mut matches = 0;
        let mut matching_patterns = Vec::new();
        
        for (pattern_name, pattern) in patterns.iter() {
            if pattern.is_match(test_string) {
                matches += 1;
                matching_patterns.push(pattern_name);
            }
        }
        
        // Allow some patterns to match common words (like Generic Secret might match "secret")
        // but ensure it's not excessive
        assert!(
            matches <= 3,
            "String '{}' matched too many patterns ({}): {:?}",
            test_string,
            matches,
            matching_patterns
        );
        
        if matches > 0 {
            println!("⚠ String '{}' matched {} patterns: {:?}", test_string, matches, matching_patterns);
        }
    }
}