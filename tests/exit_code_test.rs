//! Exit status: 0 clean, 1 findings (configurable), 2 the scan could not be trusted.

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn code(dir: &Path, args: &[&str]) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .arg("-q")
        .args(args)
        .output()
        .unwrap()
        .status
        .code()
}

fn dirty() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.txt"), format!("t = \"{}\"\n", token())).unwrap();
    dir
}

fn clean() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.txt"), "nothing to see\n").unwrap();
    dir
}

#[test]
fn default_statuses() {
    assert_eq!(code(clean().path(), &["."]), Some(0));
    assert_eq!(code(dirty().path(), &["."]), Some(1));
}

#[test]
fn no_fail_reports_but_exits_zero() {
    let dir = dirty();
    let out = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir.path())
        .args(["-q", "--no-fail", "."])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("GitHub Token"));
}

#[test]
fn exit_code_sets_the_findings_status_only() {
    let dir = dirty();
    assert_eq!(code(dir.path(), &["--exit-code", "7", "."]), Some(7));
    assert_eq!(code(dir.path(), &["--exit-code", "0", "."]), Some(0));
    // No findings: still 0, whatever the configured code.
    assert_eq!(code(clean().path(), &["--exit-code", "7", "."]), Some(0));
}

#[test]
fn errors_exit_two_and_are_not_masked_by_no_fail() {
    let dir = dirty();
    assert_eq!(code(dir.path(), &["does-not-exist"]), Some(2));
    assert_eq!(code(dir.path(), &["--no-fail", "does-not-exist"]), Some(2));
    assert_eq!(code(dir.path(), &["--no-fail", "--baseline", "absent.json", "."]), Some(2));
    assert_eq!(code(dir.path(), &["--exit-code", "7", "--config", "absent.toml", "."]), Some(2));
    // Output file in a directory that does not exist.
    assert_eq!(code(dir.path(), &["-o", "missing-dir/out.txt", "."]), Some(2));
}

#[test]
fn invalid_usage_exits_two() {
    let dir = clean();
    assert_eq!(code(dir.path(), &["--exit-code", "300", "."]), Some(2));
    assert_eq!(code(dir.path(), &["--exit-code", "abc", "."]), Some(2));
    assert_eq!(code(dir.path(), &["--exit-code", "3", "--no-fail", "."]), Some(2));
    assert_eq!(code(dir.path(), &["--format", "xml", "."]), Some(2));
}
