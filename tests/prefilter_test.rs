//! The RegexSet prefilter must select exactly the rules whose regex matches.

use regex::Regex;
use secretscan::patterns::rules;
use secretscan::scanner::PatternSet;
use secretscan::{ContextFilter, Scanner};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

fn corpus_lines() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(text) = fs::read_to_string(&path) {
                out.extend(text.lines().map(str::to_string));
            }
        }
    }
    let mut lines = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    walk(&root.join("test-repo"), &mut lines);
    walk(&root.join("src"), &mut lines);
    walk(&root.join("validation-test"), &mut lines);
    lines
}

#[test]
fn prefilter_is_active_for_the_built_in_rules() {
    let scanner = Scanner::new().unwrap();
    assert!(scanner.pattern_set().has_prefilter());
    assert_eq!(scanner.pattern_set().len(), rules().len());
    assert!(!scanner.pattern_set().is_empty());
}

#[test]
fn candidates_equal_the_rules_that_actually_match() {
    let scanner = Scanner::new().unwrap();
    let set = scanner.pattern_set();
    let lines = corpus_lines();
    assert!(lines.len() > 500, "corpus too small: {}", lines.len());

    let mut lines_with_matches = 0;
    for line in &lines {
        let expected: BTreeSet<&str> = rules()
            .iter()
            .filter(|rule| rule.regex.is_match(line))
            .map(|rule| rule.name)
            .collect();
        let actual: BTreeSet<&str> = set
            .candidates(line)
            .into_iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(expected, actual, "prefilter disagrees on line: {line}");
        if !expected.is_empty() {
            lines_with_matches += 1;
        }
    }
    assert!(
        lines_with_matches >= 10,
        "corpus exercised too few rules: {lines_with_matches}"
    );
}

#[test]
fn candidates_are_returned_in_a_fixed_order() {
    let scanner = Scanner::new().unwrap();
    let line = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";
    let names = |s: &Scanner| -> Vec<String> {
        s.pattern_set()
            .candidates(line)
            .into_iter()
            .map(|(n, _)| n.clone())
            .collect()
    };
    let first = names(&scanner);
    assert!(first.len() >= 2);
    let mut sorted = first.clone();
    sorted.sort();
    assert_eq!(first, sorted);
    assert_eq!(first, names(&Scanner::new().unwrap()));
}

#[test]
fn custom_patterns_get_a_prefilter_too() {
    let mut patterns = HashMap::new();
    patterns.insert("Ticket".to_string(), Regex::new(r"TICKET-[0-9]{4}").unwrap());
    patterns.insert("Word".to_string(), Regex::new(r"\bzebra\b").unwrap());
    let set = PatternSet::new(&patterns);
    assert!(set.has_prefilter());
    assert!(set.candidates("nothing here").is_empty());
    let hits = set.candidates("see TICKET-1234");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, "Ticket");

    let dir = tempfile::TempDir::new().unwrap();
    fs::write(dir.path().join("notes.txt"), "a zebra filed TICKET-9876\n").unwrap();
    let mut scanner = Scanner::with_patterns(patterns.into_iter().collect()).unwrap();
    scanner.set_context_filter(ContextFilter::none());
    let found: BTreeSet<String> = scanner
        .scan_directory(dir.path())
        .unwrap()
        .into_iter()
        .map(|f| f.pattern_name)
        .collect();
    assert!(found.contains("Ticket"));
}
