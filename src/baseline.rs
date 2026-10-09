//! Baselines: a recorded set of known findings to suppress on later scans.
//!
//! A baseline stores fingerprints, rule ids and file paths — never secret
//! text — so it is safe to commit. Adopting the scanner on an existing
//! codebase then means: record a baseline once, and from that point only new
//! findings are reported and fail the build.

use crate::output::{fingerprint, normalize_path, rule_id};
use crate::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

const BASELINE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub version: u32,
    pub findings: Vec<BaselineEntry>,
}

#[derive(Debug)]
pub enum BaselineError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    UnsupportedVersion(u32),
}

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BaselineError::Io(e) => write!(f, "{e}"),
            BaselineError::Parse(e) => write!(f, "not a valid baseline file: {e}"),
            BaselineError::UnsupportedVersion(v) => write!(
                f,
                "baseline version {v} is not supported (expected {BASELINE_VERSION})"
            ),
        }
    }
}

impl std::error::Error for BaselineError {}

impl Baseline {
    /// Record `findings`. Entries are sorted and deduplicated, so the same
    /// findings always produce the same file and diffs stay small.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries: BTreeSet<BaselineEntry> = findings
            .iter()
            .map(|finding| BaselineEntry {
                fingerprint: fingerprint(finding),
                rule_id: rule_id(&finding.pattern_name),
                file: normalize_path(&finding.file_path),
            })
            .collect();
        Baseline {
            version: BASELINE_VERSION,
            findings: entries.into_iter().collect(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        let text = fs::read_to_string(path).map_err(BaselineError::Io)?;
        let baseline: Baseline = serde_json::from_str(&text).map_err(BaselineError::Parse)?;
        if baseline.version != BASELINE_VERSION {
            return Err(BaselineError::UnsupportedVersion(baseline.version));
        }
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        let mut text = serde_json::to_string_pretty(self).map_err(BaselineError::Parse)?;
        text.push('\n');
        fs::write(path, text).map_err(BaselineError::Io)
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Remove findings recorded in this baseline; returns how many were removed.
    pub fn suppress(&self, findings: &mut Vec<Finding>) -> usize {
        let known: BTreeSet<&str> = self.findings.iter().map(|e| e.fingerprint.as_str()).collect();
        let before = findings.len();
        findings.retain(|finding| !known.contains(fingerprint(finding).as_str()));
        before - findings.len()
    }
}
