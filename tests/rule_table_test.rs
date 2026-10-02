//! The rule table is the single source of truth for built-in rules.

use secretscan::patterns::rules;
use secretscan::{get_all_patterns, get_all_patterns_owned};
use std::collections::HashSet;

#[test]
fn rule_names_and_ids_are_unique() {
    let names: HashSet<&str> = rules().iter().map(|r| r.name).collect();
    let ids: HashSet<&str> = rules().iter().map(|r| r.id.as_str()).collect();
    assert_eq!(names.len(), rules().len(), "duplicate rule name");
    assert_eq!(ids.len(), rules().len(), "duplicate rule id");
}

#[test]
fn rule_ids_are_well_formed_slugs() {
    for rule in rules() {
        assert!(!rule.id.is_empty());
        assert!(
            rule.id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "bad id {:?}",
            rule.id
        );
        assert!(!rule.id.starts_with('-') && !rule.id.ends_with('-'));
    }
}

#[test]
fn both_pattern_maps_are_derived_from_the_table() {
    let borrowed = get_all_patterns();
    let owned = get_all_patterns_owned();
    assert_eq!(borrowed.len(), rules().len());
    assert_eq!(owned.len(), rules().len());
    for rule in rules() {
        assert_eq!(borrowed[rule.name].as_str(), rule.regex.as_str());
        assert_eq!(owned[rule.name].as_str(), rule.regex.as_str());
    }
}

#[test]
fn the_table_still_holds_every_shipped_rule() {
    // Guards the refactor: the count and a sample from each family must
    // survive. Update the count when rules are added or removed.
    assert_eq!(rules().len(), 73);
    for name in [
        "AWS Access Key ID",
        "GitHub Token",
        "JWT Token",
        "Multi-line Private Key",
        "PostgreSQL URL",
        "Stripe API Key",
        "Password in YAML",
        "Split Secret Pattern",
        "Anthropic API Key",
    ] {
        assert!(rules().iter().any(|r| r.name == name), "missing {name}");
    }
}
