//! `--staged`: scan what the next commit would add, for pre-commit hooks.

use secretscan::git::{scan_staged, GitError};
use secretscan::{ContextFilter, Scanner};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn token(seed: char) -> String {
    format!("ghp_{}{}", seed, "B3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn scanner() -> Scanner {
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=Ada Tester", "-c", "user.email=ada@example.invalid"])
        .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .expect("git must be installed to run these tests");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A repo with one committed secret (in old.txt) and a clean index.
fn repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join("old.txt"), format!("legacy = \"{}\"\n", token('o'))).unwrap();
    fs::write(dir.path().join("app.txt"), "line one\nline two\n").unwrap();
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "initial"]);
    dir
}

fn cli_code(dir: &Path, args: &[&str]) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .arg("-q")
        .args(args)
        .output()
        .unwrap()
        .status
        .code()
}

#[test]
fn nothing_staged_means_nothing_found_even_with_committed_secrets() {
    let dir = repo();
    assert!(scan_staged(&scanner(), dir.path()).unwrap().is_empty());
    assert_eq!(cli_code(dir.path(), &["--staged", "."]), Some(0));
    // The working-tree scan does see the committed secret.
    assert_eq!(cli_code(dir.path(), &["."]), Some(1));
}

#[test]
fn staged_secret_is_found_with_the_right_file_and_line() {
    let dir = repo();
    fs::write(
        dir.path().join("app.txt"),
        format!("line one\nline two\ntoken = \"{}\"\n", token('n')),
    )
    .unwrap();
    git(dir.path(), &["add", "app.txt"]);

    let findings = scan_staged(&scanner(), dir.path()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].matched_text, token('n'));
    assert_eq!(findings[0].line_number, 3);
    assert!(findings[0].file_path.ends_with("app.txt"));
    assert_eq!(cli_code(dir.path(), &["--staged", "."]), Some(1));
}

#[test]
fn unstaged_edits_are_ignored() {
    let dir = repo();
    // Modified in the working tree but not added: a commit would not include it.
    fs::write(dir.path().join("app.txt"), format!("token = \"{}\"\n", token('u'))).unwrap();
    assert!(scan_staged(&scanner(), dir.path()).unwrap().is_empty());
}

#[test]
fn new_file_is_scanned_and_removals_are_not_findings() {
    let dir = repo();
    fs::write(dir.path().join("new.env"), format!("A=1\nGH=\"{}\"\n", token('f'))).unwrap();
    fs::remove_file(dir.path().join("old.txt")).unwrap();
    git(dir.path(), &["add", "-A"]);

    let findings = scan_staged(&scanner(), dir.path()).unwrap();
    let secrets: Vec<&str> = findings.iter().map(|f| f.matched_text.as_str()).collect();
    assert_eq!(secrets, vec![token('f')], "deleting old.txt must not report its secret");
    assert_eq!(findings[0].line_number, 2);
}

#[test]
fn inline_allow_works_on_staged_lines() {
    let dir = repo();
    fs::write(
        dir.path().join("app.txt"),
        format!("token = \"{}\" # secretscan:allow\n", token('a')),
    )
    .unwrap();
    git(dir.path(), &["add", "-A"]);
    assert!(scan_staged(&scanner(), dir.path()).unwrap().is_empty());
}

#[test]
fn errors_and_usage() {
    let plain = TempDir::new().unwrap();
    assert!(matches!(
        scan_staged(&scanner(), plain.path()),
        Err(GitError::Failed(_))
    ));
    assert_eq!(cli_code(plain.path(), &["--staged", "."]), Some(2));
    let dir = repo();
    assert_eq!(cli_code(dir.path(), &["--staged", "--git", "."]), Some(2));
}

#[test]
fn pre_commit_hook_definition_is_valid_and_uses_staged_mode() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".pre-commit-hooks.yaml"),
    )
    .unwrap();
    for required in [
        "- id: secretscan",
        "language: rust",
        "pass_filenames: false",
        "entry: secretscan --staged",
    ] {
        assert!(text.contains(required), "missing {required:?}");
    }
    // The hook must not print secrets into commit output.
    assert!(text.contains("--redact"));
}

#[test]
fn the_hook_entry_blocks_a_commit_that_adds_a_secret() {
    // Runs the exact arguments from .pre-commit-hooks.yaml as a git hook.
    let dir = repo();
    let hook = dir.path().join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        format!("#!/bin/sh\nexec \"{}\" --staged --redact --quiet\n", env!("CARGO_BIN_EXE_secretscan")),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let commit = |dir: &Path| {
        Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=Ada", "-c", "user.email=ada@example.invalid"])
            .args(["-c", "commit.gpgsign=false", "commit", "-q", "-m", "change"])
            .output()
            .unwrap()
    };

    fs::write(dir.path().join("app.txt"), format!("t = \"{}\"\n", token('h'))).unwrap();
    git(dir.path(), &["add", "-A"]);
    let blocked = commit(dir.path());
    assert!(!blocked.status.success(), "commit with a secret must be rejected");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(output.contains("GitHub Token"));
    assert!(!output.contains(&token('h')), "hook output must be redacted");

    fs::write(dir.path().join("app.txt"), "harmless\n").unwrap();
    git(dir.path(), &["add", "-A"]);
    assert!(commit(dir.path()).status.success(), "clean commit must pass");
}
