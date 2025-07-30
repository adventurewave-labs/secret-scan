use secretscan::entropy::*;

#[test]
fn test_shannon_entropy_high() {
    // High entropy strings (random-like)
    assert!(shannon_entropy("aB3xZ9kL2mN7pQ5tY8vW1jR6") > 3.5);
    assert!(shannon_entropy("X8k2N9pL5mQ7vY3tZ6jR1bW4") > 3.5);
    assert!(shannon_entropy("9kL2mN7pQ5tY8vW1jR6bX3Z") > 3.5);
    assert!(shannon_entropy("M5tY8vW1jR6bX3Z9kL2mN7p") > 3.5);
}

#[test]
fn test_shannon_entropy_low() {
    // Low entropy strings (predictable)
    assert!(shannon_entropy("aaaaaaa") < 3.5);
    assert!(shannon_entropy("1111111") < 3.5);
    assert!(shannon_entropy("password") < 3.5);
    assert!(shannon_entropy("hello world") < 3.5);
    assert!(shannon_entropy("testtest") < 3.5);
}

#[test]
fn test_shannon_entropy_edge_cases() {
    // Empty string
    assert_eq!(shannon_entropy(""), 0.0);

    // Single character
    assert_eq!(shannon_entropy("a"), 0.0);

    // Two different characters
    let entropy_two = shannon_entropy("ab");
    assert!(entropy_two > 0.0);
    assert!(entropy_two < 3.5);
}

#[test]
fn test_is_high_entropy() {
    // Test the convenience function
    assert!(is_high_entropy("aB3xZ9kL2mN7pQ5tY8vW1jR6"));
    assert!(is_high_entropy("X8k2N9pL5mQ7vY3tZ6jR1bW4"));

    assert!(!is_high_entropy("password"));
    assert!(!is_high_entropy("aaaaaaa"));
    assert!(!is_high_entropy("hello world"));
}

#[test]
fn test_entropy_calculation() {
    // Test known entropy values (approximate)
    let uniform_4_chars = "abcd"; // log2(4) = 2.0
    let entropy = shannon_entropy(uniform_4_chars);
    assert!((entropy - 2.0).abs() < 0.1);

    let uniform_8_chars = "abcdefgh"; // log2(8) = 3.0
    let entropy = shannon_entropy(uniform_8_chars);
    assert!((entropy - 3.0).abs() < 0.1);
}
