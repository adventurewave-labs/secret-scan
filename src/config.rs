//! `.secretscan.toml`: per-repository allowlists, disabled rules and custom rules.
//!
//! ```toml
//! [allowlist]
//! paths = ["^vendor/", "\\.lock$"]        # regexes matched against the file path
//! regexes = ["EXAMPLE", "^changeme$"]     # regexes matched against the secret
//! fingerprints = ["4ac28efb3d612a0a"]     # exact findings, from JSON/SARIF output
//!
//! [rules]
//! disable = ["azure-tenant-id"]           # rule ids
//!
//! [[rules.custom]]
//! name = "Acme Token"
//! regex = "acme_[a-z0-9]{32}"
//! severity = "high"                       # optional, default "medium"
//! ```
//!
//! Unknown keys, unknown rule ids and invalid regexes are errors: a typo in a
//! security tool's configuration should fail loudly, not silently do nothing.

use crate::output::{fingerprint, normalize_path, rule_id};
use crate::patterns::{base_rule_name, rules, Severity};
use crate::Finding;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// File name looked up in the directory being scanned.
pub const CONFIG_FILE_NAME: &str = ".secretscan.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    allowlist: RawAllowlist,
    #[serde(default)]
    rules: RawRules,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowlist {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    fingerprints: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    custom: Vec<RawCustomRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCustomRule {
    name: String,
    regex: String,
    severity: Option<String>,
}

/// A user-defined rule.
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub name: String,
    pub regex: Regex,
    pub severity: Severity,
}

/// A validated configuration.
#[derive(Debug, Default)]
pub struct Config {
    allow_paths: Vec<Regex>,
    allow_regexes: Vec<Regex>,
    allow_fingerprints: BTreeSet<String>,
    disabled_rules: BTreeSet<String>,
    custom_rules: Vec<CustomRule>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "{e}"),
            ConfigError::Parse(e) => write!(f, "{}", e.trim_end()),
            ConfigError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn compile(kind: &str, patterns: &[String]) -> Result<Vec<Regex>, ConfigError> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|e| ConfigError::Invalid(format!("invalid {kind} regex {pattern:?}: {e}")))
        })
        .collect()
}

impl Config {
    /// Parse and validate configuration text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

        let mut disabled_rules = BTreeSet::new();
        for id in raw.rules.disable {
            if !rules().iter().any(|rule| rule.id == id) {
                return Err(ConfigError::Invalid(format!(
                    "rules.disable: unknown rule id {id:?}"
                )));
            }
            disabled_rules.insert(id);
        }

        let mut custom_rules: Vec<CustomRule> = Vec::new();
        for raw_rule in raw.rules.custom {
            let name = raw_rule.name.trim().to_string();
            if name.is_empty() {
                return Err(ConfigError::Invalid("rules.custom: name is empty".into()));
            }
            let id = rule_id(&name);
            let clashes = rules().iter().any(|rule| rule.id == id)
                || custom_rules.iter().any(|rule| rule_id(&rule.name) == id);
            if clashes {
                return Err(ConfigError::Invalid(format!(
                    "rules.custom: {name:?} clashes with an existing rule ({id})"
                )));
            }
            let regex = Regex::new(&raw_rule.regex).map_err(|e| {
                ConfigError::Invalid(format!("rules.custom: invalid regex for {name:?}: {e}"))
            })?;
            let severity = match raw_rule.severity.as_deref() {
                None => Severity::Medium,
                Some(text) => Severity::parse(text).ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "rules.custom: unknown severity {text:?} for {name:?} \
                         (expected low, medium, high or critical)"
                    ))
                })?,
            };
            custom_rules.push(CustomRule { name, regex, severity });
        }

        Ok(Config {
            allow_paths: compile("allowlist.paths", &raw.allowlist.paths)?,
            allow_regexes: compile("allowlist.regexes", &raw.allowlist.regexes)?,
            allow_fingerprints: raw.allowlist.fingerprints.into_iter().collect(),
            disabled_rules,
            custom_rules,
        })
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::parse(&text)
    }

    /// The config file that applies to a scan of `scan_path`, if one exists:
    /// `.secretscan.toml` in the scanned directory (or next to a scanned file).
    pub fn discover(scan_path: &Path) -> Option<PathBuf> {
        let dir = if scan_path.is_dir() {
            scan_path
        } else {
            scan_path.parent()?
        };
        let candidate = dir.join(CONFIG_FILE_NAME);
        candidate.is_file().then_some(candidate)
    }

    pub fn custom_rules(&self) -> &[CustomRule] {
        &self.custom_rules
    }

    /// True if the config changes nothing.
    pub fn is_empty(&self) -> bool {
        self.allow_paths.is_empty()
            && self.allow_regexes.is_empty()
            && self.allow_fingerprints.is_empty()
            && self.disabled_rules.is_empty()
            && self.custom_rules.is_empty()
    }

    /// Whether a finding is switched off or allowlisted by this config.
    pub fn excludes(&self, finding: &Finding) -> bool {
        // A disabled rule also silences findings it produced after decoding
        // ("Base64 Encoded GitHub Token" when github-token is disabled).
        if self
            .disabled_rules
            .contains(&rule_id(base_rule_name(&finding.pattern_name)))
        {
            return true;
        }
        let path = normalize_path(&finding.file_path);
        self.allow_paths.iter().any(|re| re.is_match(&path))
            || self.allow_regexes.iter().any(|re| re.is_match(&finding.matched_text))
            || self.allow_fingerprints.contains(&fingerprint(finding))
    }

    /// Remove excluded findings; returns how many were removed.
    pub fn apply(&self, findings: &mut Vec<Finding>) -> usize {
        let before = findings.len();
        findings.retain(|finding| !self.excludes(finding));
        before - findings.len()
    }
}
