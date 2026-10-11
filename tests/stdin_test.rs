//! `secretscan -` reads from standard input.

use secretscan::{ContextFilter, Scanner};
use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn pipe(dir: &Path, input: &[u8], args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .arg("-q")
        .args(args)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn scan_reader_reports_line_numbers_and_label() {
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    let text = format!("one\r\ntwo\r\nt = \"{}\"\r\nsame = \"{}\" # secretscan:allow\n", token(), token());
    let findings = scanner.scan_reader(Cursor::new(text), Path::new("<stdin>")).unwrap();
    assert_eq!(findings.len(), 1, "inline allow applies to piped input too");
    assert_eq!(findings[0].line_number, 3);
    assert_eq!(findings[0].file_path, Path::new("<stdin>"));
    assert!(!findings[0].line_content.ends_with('\r'));
}

#[test]
fn piped_secret_is_reported_and_fails() {
    let dir = TempDir::new().unwrap();
    let out = pipe(dir.path(), format!("a\nt = \"{}\"\n", token()).as_bytes(), &["-f", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc.as_array().unwrap().len(), 1);
    assert_eq!(doc[0]["file_path"], "<stdin>");
    assert_eq!(doc[0]["line_number"], 2);
    assert_eq!(doc[0]["rule_id"], "github-token");
}

#[test]
fn clean_and_empty_input_exit_zero() {
    let dir = TempDir::new().unwrap();
    assert_eq!(pipe(dir.path(), b"nothing here\n", &[]).status.code(), Some(0));
    assert_eq!(pipe(dir.path(), b"", &[]).status.code(), Some(0));
}

#[test]
fn invalid_utf8_on_stdin_is_scanned() {
    let dir = TempDir::new().unwrap();
    let mut input = b"caf\xe9\n".to_vec();
    input.extend_from_slice(format!("t = \"{}\"\n", token()).as_bytes());
    assert_eq!(pipe(dir.path(), &input, &[]).status.code(), Some(1));
}

#[test]
fn other_options_apply_to_piped_input() {
    let dir = TempDir::new().unwrap();
    let input = format!("t = \"{}\"\n", token());

    let redacted = pipe(dir.path(), input.as_bytes(), &["--redact"]);
    assert!(!String::from_utf8_lossy(&redacted.stdout).contains(&token()));

    let filtered = pipe(dir.path(), input.as_bytes(), &["--min-severity", "critical"]);
    assert_eq!(filtered.status.code(), Some(0));

    let sarif = pipe(dir.path(), input.as_bytes(), &["-f", "sarif"]);
    let doc: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    let uri = &doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
    assert_eq!(uri, "<stdin>");
}

#[test]
fn stdin_cannot_be_combined_with_git_modes() {
    let dir = TempDir::new().unwrap();
    assert_eq!(pipe(dir.path(), b"x\n", &["--git"]).status.code(), Some(2));
    assert_eq!(pipe(dir.path(), b"x\n", &["--staged"]).status.code(), Some(2));
}
