use std::collections::BTreeMap;

/// Shannon entropy of `s` in bits per character.
///
/// Frequencies are accumulated in a `BTreeMap` so the floating-point sum is
/// taken in a fixed order: with a `HashMap` the per-process random iteration
/// order changed the last bits of the result from run to run, making scan
/// output non-reproducible. The divisor is the character count (not the byte
/// length), so multi-byte text is measured correctly.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut frequency: BTreeMap<char, usize> = BTreeMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *frequency.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }

    let len = total as f64;
    let mut entropy = 0.0;
    for &count in frequency.values() {
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

pub fn is_high_entropy(s: &str) -> bool {
    shannon_entropy(s) > 3.5
}
