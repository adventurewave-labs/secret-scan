use regex::Regex;
use std::path::Path;

/// Configuration for context filtering to reduce false positives
#[derive(Debug, Clone)]
pub struct ContextFilter {
    pub skip_test_directories: bool,
    pub skip_example_directories: bool,
    pub skip_docs_directories: bool,
    pub skip_test_variables: bool,
    pub custom_skip_patterns: Vec<String>,
}

impl Default for ContextFilter {
    fn default() -> Self {
        Self {
            skip_test_directories: true,
            skip_example_directories: true,
            skip_docs_directories: true,
            skip_test_variables: true,
            custom_skip_patterns: Vec::new(),
        }
    }
}

impl ContextFilter {
    /// Create a new context filter with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context filter with all filtering disabled
    pub fn none() -> Self {
        Self {
            skip_test_directories: false,
            skip_example_directories: false,
            skip_docs_directories: false,
            skip_test_variables: false,
            custom_skip_patterns: Vec::new(),
        }
    }

    /// Check if a file path should be skipped based on directory filtering rules
    pub fn should_skip_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        let path_components: Vec<&str> = path_str.split('/').collect();

        // Check for test directories
        if self.skip_test_directories
            && path_components.iter().any(|&component| {
                matches!(component, "test" | "tests" | "__tests__" | "spec" | "specs")
            })
        {
            return true;
        }

        // Check for example directories
        if self.skip_example_directories
            && path_components.iter().any(|&component| {
                matches!(
                    component,
                    "example" | "examples" | "demo" | "demos" | "sample" | "samples"
                )
            })
        {
            return true;
        }

        // Check for documentation directories
        if self.skip_docs_directories
            && path_components.iter().any(|&component| {
                matches!(
                    component,
                    "doc" | "docs" | "documentation" | "manual" | "guide"
                )
            })
        {
            return true;
        }

        // Check custom patterns
        for pattern in &self.custom_skip_patterns {
            if path_str.contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Check if a line should be skipped based on variable name filtering rules
    pub fn should_skip_line(&self, line: &str, matched_text: &str) -> bool {
        if !self.skip_test_variables {
            return false;
        }

        let line_lower = line.to_lowercase();
        let matched_lower = matched_text.to_lowercase();

        // Check if the line or surrounding context contains test-related keywords
        let test_keywords = [
            "test",
            "spec",
            "mock",
            "fake",
            "dummy",
            "example",
            "sample",
            "placeholder",
            "fixture",
            "stub",
            "demo",
            "template",
        ];

        // Check if any test keywords appear in variable names or comments
        for keyword in &test_keywords {
            // Check for variable names containing test keywords
            if self.contains_test_variable(&line_lower, keyword, &matched_lower) {
                return true;
            }

            // Check for comments indicating test data
            if line_lower.contains(&format!("# {}", keyword))
                || line_lower.contains(&format!("// {}", keyword))
                || line_lower.contains(&format!("/* {}", keyword))
                || line_lower.contains(&format!("* {}", keyword))
            {
                return true;
            }
        }

        // Check for common test patterns
        self.is_test_pattern(line, matched_text)
    }

    /// Check if the line contains a variable name with test-related keywords
    fn contains_test_variable(&self, line: &str, keyword: &str, matched_text: &str) -> bool {
        // Common variable naming patterns with test keywords
        let patterns = [
            format!("{}_", keyword),                               // test_secret
            format!("_{}", keyword),                               // secret_test
            format!("{}.", keyword),                               // test.secret
            format!(".{}", keyword),                               // secret.test
            format!("{}{}", keyword, "_"),                         // test_
            format!("{}_{}", keyword, ""),                         // test_
            format!("{}{}", keyword, matched_text.to_lowercase()), // testsecret
            format!("{}{}", matched_text.to_lowercase(), keyword), // secrettest
        ];

        for pattern in &patterns {
            if line.contains(pattern) {
                return true;
            }
        }

        // Check for camelCase patterns
        let camel_patterns = [
            format!("{}[A-Z]", keyword), // testSecret
            format!("[A-Z]{}", keyword), // SecretTest
        ];

        for pattern in &camel_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(line) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for common test data patterns
    fn is_test_pattern(&self, _line: &str, matched_text: &str) -> bool {
        let matched_lower = matched_text.to_lowercase();

        // Common test patterns - be more specific to avoid false positives
        let test_patterns = [
            "password123",
            "secret123",
            "test123",
            "dummy",
            "fake",
            "placeholder",
            "changeme",
            "default_",
            "example_",
            "sample_",
        ];

        // Check if the matched text itself is a common test value (exact matches or starts with)
        for pattern in &test_patterns {
            if matched_lower == *pattern || matched_lower.starts_with(pattern) {
                return true;
            }
        }

        // Check for repeated characters (common in test data)
        if self.is_repeated_pattern(&matched_lower) {
            return true;
        }

        // Check for obvious test formats (be more specific)
        if matched_lower.starts_with("test_")
            || matched_lower.starts_with("fake_")
            || matched_lower.starts_with("dummy_")
            || matched_lower.starts_with("example_")
            || matched_lower.starts_with("sample_")
        {
            return true;
        }

        false
    }

    /// Check if a string contains repeated patterns (common in test data)
    fn is_repeated_pattern(&self, text: &str) -> bool {
        if text.len() < 8 {
            // Increased minimum length
            return false;
        }

        // Check for patterns like "aaaaaa", "123123", "abcabc"
        let chars: Vec<char> = text.chars().collect();

        // Check for single character repetition (6+ consecutive same chars)
        if chars.windows(6).any(|w| w.iter().all(|&c| c == w[0])) {
            return true;
        }

        // Check for simple patterns (only for shorter strings to avoid false positives)
        if text.len() >= 8 && text.len() <= 16 {
            let half = text.len() / 2;
            if text[..half] == text[half..] {
                return true;
            }
        }

        false
    }

    /// Add a custom skip pattern
    pub fn add_custom_pattern(&mut self, pattern: String) {
        self.custom_skip_patterns.push(pattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_filter() {
        let filter = ContextFilter::new();
        assert!(filter.skip_test_directories);
        assert!(filter.skip_example_directories);
        assert!(filter.skip_docs_directories);
        assert!(filter.skip_test_variables);
    }

    #[test]
    fn test_none_filter() {
        let filter = ContextFilter::none();
        assert!(!filter.skip_test_directories);
        assert!(!filter.skip_example_directories);
        assert!(!filter.skip_docs_directories);
        assert!(!filter.skip_test_variables);
    }

    #[test]
    fn test_path_filtering() {
        let filter = ContextFilter::new();

        // Test directories should be skipped
        assert!(filter.should_skip_path(&PathBuf::from("src/tests/test_file.rs")));
        assert!(filter.should_skip_path(&PathBuf::from("tests/integration.rs")));
        assert!(filter.should_skip_path(&PathBuf::from("examples/demo.rs")));
        assert!(filter.should_skip_path(&PathBuf::from("docs/readme.md")));

        // Regular files should not be skipped
        assert!(!filter.should_skip_path(&PathBuf::from("src/main.rs")));
        assert!(!filter.should_skip_path(&PathBuf::from("config/settings.json")));
    }

    #[test]
    fn test_line_filtering() {
        let filter = ContextFilter::new();

        // Test variables should be skipped
        assert!(filter.should_skip_line("let test_secret = \"abc123\";", "abc123"));
        assert!(filter.should_skip_line("const DUMMY_KEY = \"xyz789\";", "xyz789"));
        assert!(filter.should_skip_line("// test password", "password123"));

        // Regular secrets should not be skipped
        assert!(!filter.should_skip_line("let api_key = \"real_secret\";", "real_secret"));
        assert!(!filter.should_skip_line("const PASSWORD = \"production_pwd\";", "production_pwd"));
    }

    #[test]
    fn test_test_patterns() {
        let filter = ContextFilter::new();

        // Common test patterns should be skipped
        assert!(filter.should_skip_line("password = \"password123\"", "password123"));
        assert!(filter.should_skip_line("secret = \"test123\"", "test123"));
        assert!(filter.should_skip_line("key = \"dummy_key\"", "dummy_key"));

        // Real patterns should not be skipped
        assert!(!filter.should_skip_line("password = \"MyRealP@ssw0rd\"", "MyRealP@ssw0rd"));
    }

    #[test]
    fn test_repeated_patterns() {
        let filter = ContextFilter::new();

        // Repeated patterns should be detected (need 6+ consecutive same chars or exact halves for 8-16 char strings)
        assert!(filter.is_repeated_pattern("aaaaaaaaa")); // 9 consecutive 'a's
        assert!(filter.is_repeated_pattern("12341234")); // exact halves
        assert!(filter.is_repeated_pattern("abcdabcd")); // exact halves

        // Non-repeated patterns should not be detected
        assert!(!filter.is_repeated_pattern("aaaaaa")); // only 6 chars
        assert!(!filter.is_repeated_pattern("abc123"));
        assert!(!filter.is_repeated_pattern("MyPassword"));
        assert!(!filter.is_repeated_pattern("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
        // real token
    }

    #[test]
    fn test_custom_patterns() {
        let mut filter = ContextFilter::new();
        filter.add_custom_pattern("staging".to_string());

        assert!(filter.should_skip_path(&PathBuf::from("config/staging/database.yml")));
        assert!(!filter.should_skip_path(&PathBuf::from("config/production/database.yml")));
    }
}
