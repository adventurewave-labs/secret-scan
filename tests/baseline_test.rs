//! Baselines suppress known findings so only new ones are reported.

use secretscan::baseline::{Baseline, BaselineError};
use secretscan::output::{fingerprint, normalize_path};
use secretscan::Finding;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn token(seed: char) -> String {
    format!("ghp_{}{}", seed, "B3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn finding(path: &str, line: usize, secret: &str) -> Finding {
    Finding {
        file_path: PathBuf::from(path),
        line_number: line,
        line_content: format!("t = \"{secret}\""),
        pattern_name: "GitHub Token".to_string(),
        matched_text: secret.to_string(),
        entropy: Some(4.5),
    }
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .args(["-q", "-f", "json"])
        .args(args)
        .arg(".")
        .output()
        .unwrap()
}

fn reported(output: &Output) -> Vec<String> {
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    doc.as_array()
        .unwrap()
        .iter()
        .map(|i| i["matched_text"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn paths_are_normalized_so_fingerprints_agree_across_invocations() {
    assert_eq!(normalize_path(Path::new("./src/a.rs")), "src/a.rs");
    assert_eq!(normalize_path(Path::new("././src/a.rs")), "src/a.rs");
    assert_eq!(normalize_path(Path::new("src\\a.rs")), "src/a.rs");
    assert_eq!(normalize_path(Path::new("/abs/a.rs")), "/abs/a.rs");
    assert_eq!(
        fingerprint(&finding("./src/a.rs", 1, "s")),
        fingerprint(&finding("src/a.rs", 9, "s"))
    );
}

#[test]
fn baseline_is_sorted_deduplicated_and_holds_no_secret() {
    let a = token('a');
    let b = token('b');
    let findings = vec![
        finding("src/z.rs", 4, &b),
        finding("src/a.rs", 1, &a),
        finding("src/a.rs", 7, &a), // same secret, same file: one entry
    ];
    let baseline = Baseline::from_findings(&findings);
    assert_eq!(baseline.len(), 2);
    assert!(!baseline.is_empty());
    let mut sorted = baseline.findings.clone();
    sorted.sort();
    assert_eq!(baseline.findings, sorted);

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("baseline.json");
    baseline.save(&path).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains(&a) && !text.contains(&b), "baseline leaked a secret");
    assert!(text.ends_with('\n'));
    assert_eq!(Baseline::load(&path).unwrap(), baseline);

    // Order of discovery does not change the file.
    let reversed: Vec<Finding> = findings.iter().rev().cloned().collect();
    assert_eq!(Baseline::from_findings(&reversed), baseline);
}

#[test]
fn suppress_removes_known_findings_even_when_they_move() {
    let old = token('a');
    let new = token('n');
    let baseline = Baseline::from_findings(&[finding("src/a.rs", 3, &old)]);

    let mut findings = vec![
        finding("./src/a.rs", 40, &old), // moved down the file
        finding("src/a.rs", 5, &new),    // new secret
        finding("src/b.rs", 3, &old),    // same secret copied to another file
    ];
    assert_eq!(baseline.suppress(&mut findings), 1);
    let left: Vec<(String, &str)> = findings
        .iter()
        .map(|f| (normalize_path(&f.file_path), f.matched_text.as_str()))
        .collect();
    assert_eq!(
        left,
        vec![("src/a.rs".to_string(), new.as_str()), ("src/b.rs".to_string(), old.as_str())]
    );
}

#[test]
fn load_rejects_missing_malformed_and_future_files() {
    let dir = TempDir::new().unwrap();
    assert!(matches!(
        Baseline::load(&dir.path().join("absent.json")),
        Err(BaselineError::Io(_))
    ));
    let bad = dir.path().join("bad.json");
    fs::write(&bad, "[1, 2, 3]").unwrap();
    assert!(matches!(Baseline::load(&bad), Err(BaselineError::Parse(_))));
    let future = dir.path().join("future.json");
    fs::write(&future, "{\"version\": 99, \"findings\": []}").unwrap();
    let err = Baseline::load(&future).unwrap_err();
    assert!(matches!(err, BaselineError::UnsupportedVersion(99)));
    assert!(err.to_string().contains("99"));
}

#[test]
fn cli_round_trip_reports_only_new_findings() {
    let dir = TempDir::new().unwrap();
    let old = token('a');
    fs::write(dir.path().join("app.conf"), format!("token = \"{old}\"\n")).unwrap();

    // Without a baseline the finding fails the run.
    let first = run(dir.path(), &[]);
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(reported(&first), vec![old.clone()]);

    // Recording a baseline succeeds with exit 0 and writes no secret.
    let write = run(dir.path(), &["--write-baseline", "baseline.json"]);
    assert_eq!(write.status.code(), Some(0));
    let text = fs::read_to_string(dir.path().join("baseline.json")).unwrap();
    assert!(!text.contains(&old));
    assert!(text.contains("\"rule_id\": \"github-token\""));
    assert!(text.contains("\"file\": \"app.conf\""));

    // With the baseline the same tree is clean.
    let clean = run(dir.path(), &["--baseline", "baseline.json"]);
    assert_eq!(clean.status.code(), Some(0));
    assert!(reported(&clean).is_empty());

    // Unrelated edits above the secret do not resurrect it; a new secret is
    // reported and fails the run.
    let new = token('n');
    fs::write(
        dir.path().join("app.conf"),
        format!("# header\n# more\ntoken = \"{old}\"\nother = \"{new}\"\n"),
    )
    .unwrap();
    let after = run(dir.path(), &["--baseline", "baseline.json"]);
    assert_eq!(after.status.code(), Some(1));
    assert_eq!(reported(&after), vec![new]);
}

#[test]
fn cli_fails_fast_on_an_unusable_baseline() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.conf"), "x = 1\n").unwrap();
    let missing = run(dir.path(), &["--baseline", "nope.json"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("nope.json"));
}
