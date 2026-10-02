//! Scanning git history.
//!
//! A secret that was committed and later deleted is still in the repository
//! and still compromised. This module walks `git log -p` and scans every
//! added line, reporting each secret once at the commit that introduced it.
//!
//! It shells out to the `git` binary rather than linking a git library: the
//! scanner then reads history exactly as the user's own git does, and the
//! dependency tree stays small.

use crate::output::fingerprint;
use crate::scanner::Scanner;
use crate::Finding;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The commit a finding was introduced in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitInfo {
    pub commit: String,
    pub author: String,
    /// Author date, ISO 8601.
    pub date: String,
}

/// A finding from history, with its commit.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryFinding {
    pub finding: Finding,
    pub commit: CommitInfo,
}

#[derive(Debug)]
pub enum GitError {
    /// `git` could not be started (not installed, not on PATH).
    Spawn(std::io::Error),
    /// `git` ran and failed: not a repository, unknown revision, …
    Failed(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GitError::Spawn(e) => write!(f, "could not run git: {e}"),
            GitError::Failed(message) => write!(f, "git failed: {}", message.trim()),
        }
    }
}

impl std::error::Error for GitError {}

const COMMIT_MARKER: char = '\u{1}';
const FIELD_SEPARATOR: char = '\u{1f}';

/// Scan the history of the repository at `repo`.
///
/// With `since`, only commits in `since..HEAD` are scanned (for incremental
/// CI runs); otherwise everything reachable from `HEAD`. Findings are
/// returned in the order produced by [`Scanner::postprocess`], each attached
/// to the oldest scanned commit that added it.
pub fn scan_history(
    scanner: &Scanner,
    repo: &Path,
    since: Option<&str>,
) -> Result<Vec<HistoryFinding>, GitError> {
    let range = match since {
        Some(rev) => format!("{rev}..HEAD"),
        None => "HEAD".to_string(),
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "log",
            "--reverse",
            "-p",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            "--format=%x01%H%x1f%an%x1f%aI",
        ])
        .arg(&range)
        .arg("--")
        .stdin(Stdio::null())
        .output()
        .map_err(GitError::Spawn)?;
    if !output.status.success() {
        return Err(GitError::Failed(String::from_utf8_lossy(&output.stderr).into_owned()));
    }
    let log = String::from_utf8_lossy(&output.stdout);
    Ok(scan_log(scanner, repo, &log))
}

/// Scan the text of `git log -p --unified=0` in the format requested by
/// [`scan_history`]. Separate from the git invocation so it can be tested
/// without a repository.
pub fn scan_log(scanner: &Scanner, repo: &Path, log: &str) -> Vec<HistoryFinding> {
    let mut raw: Vec<(Finding, CommitInfo)> = scan_diff(scanner, repo, log)
        .into_iter()
        .filter_map(|(finding, commit)| Some((finding, commit?)))
        .collect();

    // Oldest first, so the first time a fingerprint is seen is the commit
    // that introduced the secret; later re-additions are the same finding.
    let mut seen = HashSet::new();
    raw.retain(|(finding, _)| seen.insert((fingerprint(finding), finding.pattern_name.clone())));

    let mut findings: Vec<Finding> = raw.iter().map(|(finding, _)| finding.clone()).collect();
    Scanner::postprocess(&mut findings);
    findings
        .into_iter()
        .filter_map(|finding| {
            raw.iter()
                .find(|(candidate, _)| *candidate == finding)
                .map(|(_, commit)| HistoryFinding { finding, commit: commit.clone() })
        })
        .collect()
}

/// Scan what is staged for the next commit (`git diff --cached`): the lines
/// a commit would add. This is what a pre-commit hook should check, so that
/// a secret is stopped before it enters history and unrelated, already
/// committed findings do not block the commit.
pub fn scan_staged(scanner: &Scanner, repo: &Path) -> Result<Vec<Finding>, GitError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            "--",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(GitError::Spawn)?;
    if !output.status.success() {
        return Err(GitError::Failed(String::from_utf8_lossy(&output.stderr).into_owned()));
    }
    let diff = String::from_utf8_lossy(&output.stdout);
    let mut findings: Vec<Finding> =
        scan_diff(scanner, repo, &diff).into_iter().map(|(finding, _)| finding).collect();
    Scanner::postprocess(&mut findings);
    Ok(findings)
}

/// Scan the added lines of unified-diff text. Findings are raw (not
/// post-processed) and carry the commit whose header preceded them, if any.
fn scan_diff(scanner: &Scanner, repo: &Path, log: &str) -> Vec<(Finding, Option<CommitInfo>)> {
    let mut raw: Vec<(Finding, Option<CommitInfo>)> = Vec::new();
    let mut commit: Option<CommitInfo> = None;
    let mut file: Option<PathBuf> = None;
    let mut new_line = 0usize;
    let mut old_remaining = 0usize;
    let mut new_remaining = 0usize;

    for line in log.lines() {
        // Inside a hunk the header says exactly how many lines follow, so a
        // content line that happens to look like a diff header is not
        // mistaken for one.
        if old_remaining > 0 || new_remaining > 0 {
            if let Some(added) = line.strip_prefix('+') {
                if new_remaining > 0 {
                    if let Some(path) = &file {
                        for finding in scanner.scan_text_line(added, new_line, path) {
                            raw.push((finding, commit.clone()));
                        }
                    }
                    new_line += 1;
                    new_remaining -= 1;
                    continue;
                }
            } else if line.starts_with('-') && old_remaining > 0 {
                old_remaining -= 1;
                continue;
            } else if line.starts_with('\\') {
                continue; // "\ No newline at end of file"
            }
            // Anything else means the hunk was shorter than announced.
            old_remaining = 0;
            new_remaining = 0;
        }

        if let Some(header) = line.strip_prefix(COMMIT_MARKER) {
            let mut fields = header.split(FIELD_SEPARATOR);
            commit = Some(CommitInfo {
                commit: fields.next().unwrap_or_default().to_string(),
                author: fields.next().unwrap_or_default().to_string(),
                date: fields.next().unwrap_or_default().to_string(),
            });
            file = None;
        } else if let Some(target) = line.strip_prefix("+++ ") {
            file = parse_new_path(target)
                .map(|relative| repo.join(relative))
                .filter(|path| !scanner.context_filter().should_skip_path(path));
        } else if line.starts_with("@@ ") {
            if let Some((old_count, start, new_count)) = parse_hunk_header(line) {
                old_remaining = old_count;
                new_remaining = new_count;
                new_line = start;
            }
        }
    }

    raw
}

/// The path in a `+++ b/path` line; `None` for `/dev/null` (a deletion).
fn parse_new_path(target: &str) -> Option<PathBuf> {
    let target = target.trim_end_matches('\t');
    let unquoted = target
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(target);
    if unquoted == "/dev/null" {
        return None;
    }
    Some(PathBuf::from(unquoted.strip_prefix("b/").unwrap_or(unquoted)))
}

/// `(old line count, new start line, new line count)` from
/// `@@ -a[,b] +c[,d] @@`. A missing count means 1.
fn parse_hunk_header(line: &str) -> Option<(usize, usize, usize)> {
    let mut parts = line.split(' ');
    parts.next()?; // "@@"
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let count = |range: &str| -> Option<(usize, usize)> {
        match range.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((range.parse().ok()?, 1)),
        }
    };
    let (_, old_count) = count(old)?;
    let (new_start, new_count) = count(new)?;
    Some((old_count, new_start, new_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_headers() {
        assert_eq!(parse_hunk_header("@@ -0,0 +1,3 @@"), Some((0, 1, 3)));
        assert_eq!(parse_hunk_header("@@ -7 +7 @@ fn main() {"), Some((1, 7, 1)));
        assert_eq!(parse_hunk_header("@@ -4,2 +3,0 @@"), Some((2, 3, 0)));
        assert_eq!(parse_hunk_header("@@ nonsense @@"), None);
    }

    #[test]
    fn new_paths() {
        assert_eq!(parse_new_path("b/src/a.rs"), Some(PathBuf::from("src/a.rs")));
        assert_eq!(parse_new_path("\"b/with space.txt\""), Some(PathBuf::from("with space.txt")));
        assert_eq!(parse_new_path("/dev/null"), None);
    }
}
