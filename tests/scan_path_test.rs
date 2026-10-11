//! All files go through one scan path, whatever their size or encoding.

use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn scan_dir(dir: &TempDir) -> Vec<Finding> {
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

#[test]
fn file_with_invalid_utf8_is_still_scanned() {
    let dir = TempDir::new().unwrap();
    let mut bytes = b"name = \"caf\xe9\"\n".to_vec(); // Latin-1 byte, invalid UTF-8
    bytes.extend_from_slice(format!("token = \"{}\"\n", token()).as_bytes());
    fs::write(dir.path().join("legacy.txt"), bytes).unwrap();

    let findings = scan_dir(&dir);
    let hit = findings
        .iter()
        .find(|f| f.matched_text == token())
        .expect("secret after an invalid byte must be found");
    assert_eq!(hit.line_number, 2);
}

#[test]
fn crlf_line_endings_do_not_leak_into_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("win.txt"),
        format!("first\r\ntoken = \"{}\"\r\nlast\r\n", token()),
    )
    .unwrap();

    let findings = scan_dir(&dir);
    let hit = findings.iter().find(|f| f.matched_text == token()).unwrap();
    assert_eq!(hit.line_number, 2);
    assert!(!hit.line_content.ends_with('\r'));
}

#[test]
fn last_line_without_trailing_newline_is_scanned() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("eof.txt"), format!("x\ntoken = \"{}\"", token())).unwrap();
    let findings = scan_dir(&dir);
    assert_eq!(
        findings.iter().find(|f| f.matched_text == token()).unwrap().line_number,
        2
    );
}

#[test]
fn large_file_reports_exact_line_numbers_and_applies_the_same_filters() {
    // 12 MB: beyond the old 10 MB switch to a separate chunked code path,
    // which skipped entropy filtering and could merge lines at chunk borders.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("big.txt");
    let mut file = fs::File::create(&path).unwrap();
    let filler = "the quick brown fox jumps over the lazy dog 0123456789\n";
    let lines_per_block = 20_000;
    let block = filler.repeat(lines_per_block);
    let mut line = 0usize;
    let mut expected = Vec::new();
    while line * filler.len() < 12 * 1024 * 1024 {
        file.write_all(block.as_bytes()).unwrap();
        line += lines_per_block;
        writeln!(file, "token = \"{}\"", token()).unwrap();
        line += 1;
        expected.push(line);
        // Low-entropy password: rejected by the entropy filter on small files,
        // so it must be rejected here too.
        writeln!(file, "password = \"aaaaaaaa\"").unwrap();
        line += 1;
    }
    drop(file);
    assert!(fs::metadata(&path).unwrap().len() > 10 * 1024 * 1024);

    let findings = scan_dir(&dir);
    let token_lines: Vec<usize> = findings
        .iter()
        .filter(|f| f.matched_text == token())
        .map(|f| f.line_number)
        .collect();
    assert_eq!(token_lines, expected);

    // Same input as a small file gives the same per-line verdicts.
    let small = TempDir::new().unwrap();
    fs::write(
        small.path().join("small.txt"),
        format!("token = \"{}\"\npassword = \"aaaaaaaa\"\n", token()),
    )
    .unwrap();
    let small_rules: Vec<String> = scan_dir(&small).into_iter().map(|f| f.pattern_name).collect();
    let mut big_rules: Vec<String> = findings.iter().map(|f| f.pattern_name.clone()).collect();
    big_rules.dedup();
    big_rules.sort();
    big_rules.dedup();
    let mut small_sorted = small_rules.clone();
    small_sorted.sort();
    assert_eq!(big_rules, small_sorted);
}
