use std::collections::HashMap;

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut frequency = HashMap::new();
    let len = s.len() as f64;

    // Count character frequencies
    for c in s.chars() {
        *frequency.entry(c).or_insert(0) += 1;
    }

    // Calculate Shannon entropy
    let mut entropy = 0.0;
    for &count in frequency.values() {
        let probability = count as f64 / len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

pub fn is_high_entropy(s: &str) -> bool {
    shannon_entropy(s) > 3.5
}
