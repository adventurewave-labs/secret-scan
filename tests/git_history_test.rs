//! `--git`: secrets that were committed and later removed are still found.

use secretscan::git::{scan_history, scan_log, GitError};
use secretscan::{ContextFilter, Scanner};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn token(seed: char) -> String {
    format!("ghp_{}{}", seed, "B3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJxR4u")
}

fn scanner() -> Scanner {
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=Ada Tester", "-c", "user.email=ada@example.invalid"])
        .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .expect("git must be installed to run these tests");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(dir: &Path, message: &str) -> String {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", message]);
    git(dir, &["rev-parse", "HEAD"])
}

/// A repo where a secret is added in commit 2 and deleted in commit 3, and a
/// second secret is added in commit 4.
struct Repo {
    dir: TempDir,
    leak_commit: String,
    cleanup_commit: String,
    second_commit: String,
}

fn repo() -> Repo {
    let dir = TempDir::new().unwrap();
    let path = dir.path();
    git(path, &["init", "-q"]);
    fs::write(path.join("app.conf"), "name = demo\nport = 8080\n").unwrap();
    commit(path, "initial");
    fs::write(
        path.join("app.conf"),
        format!("name = demo\nport = 8080\ntoken = \"{}\"\n", token('a')),
    )
    .unwrap();
    let leak_commit = commit(path, "add token");
    fs::write(path.join("app.conf"), "name = demo\nport = 8080\n").unwrap();
    let cleanup_commit = commit(path, "remove token");
    fs::create_dir(path.join("deploy")).unwrap();
    fs::write(path.join("deploy/env.txt"), format!("x = 1\nt = \"{}\"\n", token('b'))).unwrap();
    let second_commit = commit(path, "add deploy env");
    Repo { dir, leak_commit, cleanup_commit, second_commit }
}

fn cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(dir)
        .args(["-q", "-f", "json"])
        .args(args)
        .arg(".")
        .output()
        .unwrap()
}

#[test]
fn deleted_secret_is_found_in_history_at_the_commit_that_added_it() {
    let repo = repo();
    let path = repo.dir.path();

    // The working tree only has the second secret.
    let tree = scanner().scan_directory(path).unwrap();
    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].matched_text, token('b'));

    let history = scan_history(&scanner(), path, None).unwrap();
    assert_eq!(history.len(), 2, "{history:#?}");

    let leaked = history.iter().find(|h| h.finding.matched_text == token('a')).unwrap();
    assert_eq!(leaked.commit.commit, repo.leak_commit);
    assert_eq!(leaked.commit.author, "Ada Tester");
    assert!(leaked.commit.date.starts_with("20"), "ISO date, got {}", leaked.commit.date);
    assert_eq!(leaked.finding.line_number, 3);
    assert!(leaked.finding.file_path.ends_with("app.conf"));
    assert_eq!(leaked.finding.pattern_name, "GitHub Token");

    let second = history.iter().find(|h| h.finding.matched_text == token('b')).unwrap();
    assert_eq!(second.commit.commit, repo.second_commit);
    assert_eq!(second.finding.line_number, 2);
    assert!(second.finding.file_path.ends_with("deploy/env.txt"));
}

#[test]
fn since_limits_the_scan_to_later_commits() {
    let repo = repo();
    let history = scan_history(&scanner(), repo.dir.path(), Some(&repo.cleanup_commit)).unwrap();
    let secrets: Vec<&str> = history.iter().map(|h| h.finding.matched_text.as_str()).collect();
    assert_eq!(secrets, vec![token('b')]);
}

#[test]
fn a_secret_re_added_later_is_reported_once_at_its_first_commit() {
    let repo = repo();
    let path = repo.dir.path();
    fs::write(path.join("app.conf"), format!("token = \"{}\"\n", token('a'))).unwrap();
    commit(path, "token is back");

    let history = scan_history(&scanner(), path, None).unwrap();
    let hits: Vec<_> = history.iter().filter(|h| h.finding.matched_text == token('a')).collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].commit.commit, repo.leak_commit);
}

#[test]
fn errors_are_reported_not_swallowed() {
    let not_a_repo = TempDir::new().unwrap();
    let err = scan_history(&scanner(), not_a_repo.path(), None).unwrap_err();
    assert!(matches!(err, GitError::Failed(_)), "{err}");

    let repo = repo();
    let err = scan_history(&scanner(), repo.dir.path(), Some("no-such-rev")).unwrap_err();
    assert!(err.to_string().contains("no-such-rev"), "{err}");
}

#[test]
fn diff_content_that_looks_like_a_header_is_treated_as_content() {
    // The second added line is "++ b/fake", so the raw diff line is
    // "+++ b/fake": it must not be read as a file header and redirect the
    // third line's finding to a file that does not exist.
    let log = format!(
        "\u{1}abc123\u{1f}Ada Tester\u{1f}2026-01-02T03:04:05+00:00\n\
         diff --git a/notes.txt b/notes.txt\n\
         --- a/notes.txt\n\
         +++ b/notes.txt\n\
         @@ -0,0 +1,3 @@\n\
         +first\n\
         +++ b/fake\n\
         +token = \"{}\"\n",
        token('c')
    );
    let found = scan_log(&scanner(), Path::new("."), &log);
    assert_eq!(found.len(), 1);
    assert!(found[0].finding.file_path.ends_with("notes.txt"));
    assert_eq!(found[0].finding.line_number, 3);
    assert_eq!(found[0].commit.commit, "abc123");
}

#[test]
fn removed_lines_and_deleted_files_are_not_findings() {
    let log = format!(
        "\u{1}abc123\u{1f}Ada\u{1f}2026-01-02T03:04:05+00:00\n\
         diff --git a/old.txt b/old.txt\n\
         --- a/old.txt\n\
         +++ /dev/null\n\
         @@ -1 +0,0 @@\n\
         -token = \"{}\"\n",
        token('d')
    );
    assert!(scan_log(&scanner(), Path::new("."), &log).is_empty());
}

#[test]
fn cli_git_mode_reports_commit_details_in_json_text_and_sarif() {
    let repo = repo();
    let path = repo.dir.path();

    let tree = cli(path, &[]);
    let doc: serde_json::Value = serde_json::from_slice(&tree.stdout).unwrap();
    assert_eq!(doc.as_array().unwrap().len(), 1);
    assert!(doc[0].get("commit").is_none(), "working-tree scan has no commit");

    let out = cli(path, &["--git"]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let items = doc.as_array().unwrap();
    assert_eq!(items.len(), 2);
    let leaked = items.iter().find(|i| i["matched_text"] == token('a').as_str()).unwrap();
    assert_eq!(leaked["commit"], repo.leak_commit.as_str());
    assert_eq!(leaked["author"], "Ada Tester");
    assert_eq!(leaked["file_path"], "./app.conf");

    let text = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(path)
        .args(["-q", "--git", "--redact", "."])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(text.contains(&format!("Commit: {} (Ada Tester, ", repo.leak_commit)));
    assert!(!text.contains(&token('a')), "--redact applies in git mode");

    let sarif = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .current_dir(path)
        .args(["-q", "--git", "-f", "sarif", "."])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(results
        .iter()
        .any(|r| r["properties"]["commit"] == repo.leak_commit.as_str()));
}

#[test]
fn cli_since_and_usage_errors() {
    let repo = repo();
    let path = repo.dir.path();

    let since = cli(path, &["--git", "--since", &repo.cleanup_commit]);
    let doc: serde_json::Value = serde_json::from_slice(&since.stdout).unwrap();
    assert_eq!(doc.as_array().unwrap().len(), 1);

    // Nothing new since HEAD: clean, exit 0.
    let none = cli(path, &["--git", "--since", "HEAD"]);
    assert_eq!(none.status.code(), Some(0));

    // --since without --git, an unknown revision, and a non-repository.
    assert_eq!(cli(path, &["--since", "HEAD"]).status.code(), Some(2));
    assert_eq!(cli(path, &["--git", "--since", "nope"]).status.code(), Some(2));
    let plain = TempDir::new().unwrap();
    assert_eq!(cli(plain.path(), &["--git"]).status.code(), Some(2));
}

#[test]
fn cli_baseline_and_config_apply_to_history() {
    let repo = repo();
    let path = repo.dir.path();

    let write = cli(path, &["--git", "--write-baseline", "../baseline.json"]);
    assert_eq!(write.status.code(), Some(0));
    let clean = cli(path, &["--git", "--baseline", "../baseline.json"]);
    assert_eq!(clean.status.code(), Some(0));

    fs::write(path.join("rules.toml"), "[allowlist]\npaths = [\"^deploy/\"]\n").unwrap();
    let out = cli(path, &["--git", "--config", "rules.toml"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files: Vec<&str> =
        doc.as_array().unwrap().iter().map(|i| i["file_path"].as_str().unwrap()).collect();
    assert_eq!(files, vec!["./app.conf"]);
}
