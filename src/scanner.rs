use crate::context::ContextFilter;
use crate::entropy::shannon_entropy;
use crate::patterns::{
    get_all_patterns_owned, analyze_base64_for_secrets, analyze_hex_for_secrets,
    analyze_url_encoded_for_secrets, analyze_character_array_for_secrets,
    is_suspicious_base64, is_suspicious_hex
};
use crate::Finding;
use ignore::WalkBuilder;
use rayon::prelude::*;
use lazy_static::lazy_static;
use regex::{Regex, RegexSet, RegexSetBuilder};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct ScannerError {
    message: String,
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Scanner error: {}", self.message)
    }
}

impl Error for ScannerError {}

impl From<std::io::Error> for ScannerError {
    fn from(err: std::io::Error) -> Self {
        ScannerError {
            message: format!("IO error: {}", err),
        }
    }
}

lazy_static! {
    // Compiled once. These used to be rebuilt with `Regex::new` for every line
    // scanned, which dominated total scan time.
    static ref OBFUSCATED_BASE64: Regex =
        Regex::new(r#"["']([A-Za-z0-9+/]{20,}={0,2})["']"#).unwrap();
    static ref OBFUSCATED_HEX: Regex = Regex::new(r#"["']([a-fA-F0-9]{40,})["']"#).unwrap();
    static ref OBFUSCATED_URL_ENCODED: Regex =
        Regex::new(r#"["']([^"']*%[0-9A-Fa-f]{2}[^"']*)["']"#).unwrap();
    static ref OBFUSCATED_CHAR_ARRAY: Regex =
        Regex::new(r"\[(?:\s*\d+\s*,?\s*){10,}\]").unwrap();
}

/// The active rules plus a `RegexSet` prefilter over all of them.
///
/// One pass of the set over a line says which rules can match, so the
/// individual regexes run only for those. Most lines match nothing and cost a
/// single automaton pass instead of one search per rule. The set is built from
/// the same regexes it gates, so it cannot introduce false negatives.
pub struct PatternSet {
    names: Vec<String>,
    regexes: Vec<Regex>,
    set: Option<RegexSet>,
}

impl PatternSet {
    pub fn new(patterns: &HashMap<String, Regex>) -> Self {
        // Sorted by name so rules are always tried in the same order.
        let mut entries: Vec<(&String, &Regex)> = patterns.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let names: Vec<String> = entries.iter().map(|(n, _)| (*n).clone()).collect();
        let regexes: Vec<Regex> = entries.iter().map(|(_, r)| (*r).clone()).collect();
        // If the combined automaton cannot be built (e.g. oversized custom
        // rules) fall back to running every regex, which is always correct.
        let set = RegexSetBuilder::new(regexes.iter().map(|r| r.as_str()))
            .size_limit(256 * 1024 * 1024)
            .build()
            .ok();
        PatternSet { names, regexes, set }
    }

    /// Whether the prefilter is active (false means every rule runs per line).
    pub fn has_prefilter(&self) -> bool {
        self.set.is_some()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Rules that can match `text`, as (name, regex) pairs.
    pub fn candidates<'a>(&'a self, text: &str) -> Vec<(&'a String, &'a Regex)> {
        match &self.set {
            Some(set) => set
                .matches(text)
                .into_iter()
                .map(|i| (&self.names[i], &self.regexes[i]))
                .collect(),
            None => self.names.iter().zip(self.regexes.iter()).collect(),
        }
    }
}

pub struct Scanner {
    matcher: Arc<PatternSet>,
    context_filter: ContextFilter,
}

impl Scanner {
    pub fn new() -> Result<Self, ScannerError> {
        let patterns = get_all_patterns_owned();
        Ok(Scanner {
            matcher: Arc::new(PatternSet::new(&patterns)),
            context_filter: ContextFilter::new(),
        })
    }

    pub fn with_patterns(patterns: Vec<(String, Regex)>) -> Result<Self, ScannerError> {
        let mut pattern_map = HashMap::new();
        for (name, pattern) in patterns {
            pattern_map.insert(name, pattern);
        }

        Ok(Scanner {
            matcher: Arc::new(PatternSet::new(&pattern_map)),
            context_filter: ContextFilter::new(),
        })
    }

    /// Create scanner with custom context filter
    pub fn with_context_filter(context_filter: ContextFilter) -> Result<Self, ScannerError> {
        let patterns = get_all_patterns_owned();
        Ok(Scanner {
            matcher: Arc::new(PatternSet::new(&patterns)),
            context_filter,
        })
    }

    /// The active rules and their prefilter.
    pub fn pattern_set(&self) -> &PatternSet {
        &self.matcher
    }

    /// Set context filter for this scanner
    pub fn set_context_filter(&mut self, context_filter: ContextFilter) {
        self.context_filter = context_filter;
    }

    /// Get a reference to the context filter
    pub fn context_filter(&self) -> &ContextFilter {
        &self.context_filter
    }

    pub fn scan_directory(&self, path: &Path) -> Result<Vec<Finding>, ScannerError> {
        let mut findings = self.scan_directory_optimized(path)?;
        Self::postprocess(&mut findings);
        Ok(findings)
    }

    /// Scan a single line of text that did not come from a file on disk
    /// (for example an added line in a git diff). The result is raw: pass the
    /// collected findings through [`Scanner::postprocess`].
    pub fn scan_text_line(&self, line: &str, line_number: usize, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        Self::scan_line(
            line,
            line_number,
            file_path,
            &self.matcher,
            &self.context_filter,
            &mut findings,
        );
        findings
    }

    /// Turn raw findings into reported findings: collapse overlapping rules,
    /// honour inline allow markers, and sort.
    pub fn postprocess(findings: &mut Vec<Finding>) {
        Self::dedupe_overlapping_findings(findings);
        // Inline suppression: a line carrying an allow marker is an explicit,
        // reviewable decision by the author (same convention as gitleaks).
        findings.retain(|f| !Self::has_inline_allow(&f.line_content));
        // Deterministic order — parallel scanning otherwise yields a different
        // ordering per run, which breaks diffing, baselines and CI caching.
        findings.sort_by(|a, b| {
            (&a.file_path, a.line_number, &a.pattern_name, &a.matched_text).cmp(&(
                &b.file_path,
                b.line_number,
                &b.pattern_name,
                &b.matched_text,
            ))
        });
    }

    /// Specificity of a private-key rule: lower is more specific. `None` for
    /// rules outside the private-key family.
    fn private_key_rank(pattern_name: &str) -> Option<u8> {
        match pattern_name {
            "RSA Private Key" | "EC Private Key" | "PGP Private Key" | "SSH Private Key" => Some(0),
            "Generic Private Key" => Some(1),
            "Multi-line Private Key" => Some(2),
            _ => None,
        }
    }

    /// True when the line opts out of scanning via `secretscan:allow`
    /// (or the gitleaks-compatible `gitleaks:allow`).
    pub fn has_inline_allow(line: &str) -> bool {
        line.contains("secretscan:allow") || line.contains("gitleaks:allow")
    }

    /// Remove redundant findings that describe the same secret on the same line.
    ///
    /// Four surgical rules, applied per (file, line):
    ///   1. Generic catch-all patterns (Suspicious Base64/Hex, Generic Secret, …) are
    ///      dropped when a specific pattern already matched overlapping text.
    ///   2. "Firebase API Key" is dropped when "Google API Key" matched the identical
    ///      text — the two formats are byte-identical (Firebase keys ARE Google keys).
    ///   3. The contextual "AWS Access Key" match is dropped when the bare
    ///      "AWS Access Key ID" already reported the key it contains.
    ///   4. A private key is reported once, under its most specific rule.
    fn dedupe_overlapping_findings(findings: &mut Vec<Finding>) {
        const GENERIC: [&str; 5] = [
            "Suspicious Base64",
            "Suspicious Hex",
            "Generic Secret",
            "Generic OAuth Secret",
            "Generic Client ID",
        ];
        let snapshot: Vec<(std::path::PathBuf, usize, String, String)> = findings
            .iter()
            .map(|f| (f.file_path.clone(), f.line_number, f.pattern_name.clone(), f.matched_text.clone()))
            .collect();
        findings.retain(|f| {
            let same_line = |other: &(std::path::PathBuf, usize, String, String)| {
                other.0 == f.file_path && other.1 == f.line_number
            };
            // Rule 1: drop generic finding overlapped by any specific finding
            if GENERIC.contains(&f.pattern_name.as_str()) {
                let overlapped = snapshot.iter().any(|o| {
                    same_line(o)
                        && !GENERIC.contains(&o.2.as_str())
                        && (f.matched_text.contains(&o.3) || o.3.contains(&f.matched_text))
                });
                if overlapped {
                    return false;
                }
            }
            // Rule 2: Firebase shadowed by identical Google match
            if f.pattern_name == "Firebase API Key" {
                let shadowed = snapshot
                    .iter()
                    .any(|o| same_line(o) && o.2 == "Google API Key" && o.3 == f.matched_text);
                if shadowed {
                    return false;
                }
            }
            // Rule 4: one private key, one finding. A PEM header matches the
            // specific rule, the generic rule and (when the whole block is on
            // one line) the multi-line rule; keep only the most specific.
            if let Some(rank) = Self::private_key_rank(&f.pattern_name) {
                let outranked = snapshot.iter().any(|o| {
                    same_line(o)
                        && Self::private_key_rank(&o.2).is_some_and(|other| other < rank)
                });
                if outranked {
                    return false;
                }
            }
            // Rule 3: contextual AWS match shadowed by the bare key it contains
            if f.pattern_name == "AWS Access Key" {
                let shadowed = snapshot.iter().any(|o| {
                    same_line(o) && o.2 == "AWS Access Key ID" && f.matched_text.contains(&o.3)
                });
                if shadowed {
                    return false;
                }
            }
            true
        });
    }

    /// Optimized parallel scanning with rayon
    pub fn scan_directory_optimized(&self, path: &Path) -> Result<Vec<Finding>, ScannerError> {
        // Build file list with improved file type coverage
        let walker = WalkBuilder::new(path)
            .hidden(false)
            .git_ignore(true)
            .git_exclude(true)
            .git_global(false)
            .parents(true)
            .ignore(true)
            .build()
            .filter_map(|e| e.ok())
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter(|entry| {
                // Skip .git directory files
                if entry.path().components().any(|c| c.as_os_str() == ".git") {
                    return false;
                }
                
                // Enhanced file type filtering - ensure we scan important file types
                let _path_str = entry.path().to_string_lossy().to_lowercase();
                let is_scannable_file = self.is_scannable_file_type(entry.path());
                
                // Apply context filtering only if file type is scannable
                if !is_scannable_file {
                    return false;
                }
                
                !self.context_filter.should_skip_path(entry.path())
            })
            .map(|entry| entry.path().to_path_buf())
            .collect::<Vec<_>>();

        // Create owned copies for thread safety
        let patterns = Arc::clone(&self.matcher);
        let context_filter = Arc::new(self.context_filter.clone());

        // Process files in parallel using rayon
        let all_findings: Vec<Finding> = walker
            .par_iter()
            .filter_map(|file_path| {
                Self::scan_file_static(file_path, &patterns, &context_filter).ok()
            })
            .flatten()
            .collect();

        Ok(all_findings)
    }

    /// Enhanced file type filtering to ensure we scan all relevant files
    fn is_scannable_file_type(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        
        // Always scan text-based files regardless of extension
        let text_extensions = [
            ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf",
            ".env", ".properties", ".toml", ".log", ".sql", ".sh", ".bat", ".ps1",
            ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".cs", ".go",
            ".rs", ".c", ".cpp", ".h", ".hpp", ".swift", ".kt", ".scala", ".clj",
            ".html", ".css", ".scss", ".less", ".vue", ".svelte", ".dockerfile",
            ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks"
        ];
        
        // Check for known text extensions
        for ext in &text_extensions {
            if path_str.ends_with(ext) {
                return true;
            }
        }
        
        // Handle files without extensions - check if they're likely text files
        if let Some(filename) = path.file_name() {
            let filename_str = filename.to_string_lossy().to_lowercase();
            
            // Common config files without extensions
            let config_files = [
                "dockerfile", "makefile", "rakefile", "gemfile", "procfile",
                "vagrantfile", "gruntfile", "gulpfile", "webpack", "babel",
                ".gitignore", ".dockerignore", ".env", ".envrc", ".bashrc",
                ".zshrc", ".profile", ".vimrc", ".tmux", "config", "settings"
            ];
            
            for config in &config_files {
                if filename_str == *config || filename_str.contains(config) {
                    return true;
                }
            }
            
            // If no extension, try to detect if it's a text file by reading first few bytes
            if !filename_str.contains('.') {
                return self.is_likely_text_file(path);
            }
        }
        
        // Skip binary files
        let binary_extensions = [
            ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj",
            ".zip", ".tar", ".gz", ".7z", ".rar", ".jar", ".war", ".ear",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".tiff",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".wav", ".ogg",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"
        ];
        
        for ext in &binary_extensions {
            if path_str.ends_with(ext) {
                return false;
            }
        }
        
        // Default to scanning unknown files
        true
    }
    
    /// Detect if a file without extension is likely a text file
    fn is_likely_text_file(&self, path: &Path) -> bool {
        match std::fs::File::open(path) {
            Ok(mut file) => {
                let mut buffer = [0; 512];
                match file.read(&mut buffer) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        // Check if the first 512 bytes are mostly printable ASCII/UTF-8
                        let text_bytes = buffer[..bytes_read].iter()
                            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                            .count();
                        let ratio = text_bytes as f32 / bytes_read as f32;
                        ratio > 0.7 // If more than 70% are text characters, consider it text
                    }
                    _ => false
                }
            }
            Err(_) => false
        }
    }

    /// Scan one file, line by line.
    ///
    /// Lines are read as bytes and decoded lossily, so a file containing a few
    /// invalid UTF-8 bytes is still scanned (invalid bytes become U+FFFD)
    /// rather than skipped. Memory use is bounded by the longest line, whatever
    /// the file size, so there is a single code path for all files.
    fn scan_file_static(
        file_path: &Path,
        patterns: &PatternSet,
        context_filter: &ContextFilter,
    ) -> Result<Vec<Finding>, ScannerError> {
        let mut reader = BufReader::with_capacity(64 * 1024, File::open(file_path)?);
        let mut findings = Vec::new();
        let mut raw = Vec::new();
        let mut line_number = 0;

        loop {
            raw.clear();
            if reader.read_until(b'\n', &mut raw)? == 0 {
                break;
            }
            line_number += 1;
            if raw.last() == Some(&b'\n') {
                raw.pop();
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }
            }
            let line = String::from_utf8_lossy(&raw);
            Self::scan_line(&line, line_number, file_path, patterns, context_filter, &mut findings);
        }

        Ok(findings)
    }

    /// Run every candidate rule, then the obfuscation analysis, on one line.
    fn scan_line(
        line: &str,
        line_number: usize,
        file_path: &Path,
        patterns: &PatternSet,
        context_filter: &ContextFilter,
        findings: &mut Vec<Finding>,
    ) {
        for (pattern_name, pattern) in patterns.candidates(line) {
            let Some(captures) = pattern.captures(line) else {
                continue;
            };
            let matched_text = captures[0].to_string();

            // For the generic, name-based rules the value is the last capture
            // group; documentation stand-ins ("changeme", "<your-key>",
            // "${VAR}") are not findings.
            if crate::placeholder::applies_to(pattern_name) {
                let value = captures
                    .iter()
                    .skip(1)
                    .flatten()
                    .last()
                    .map(|group| group.as_str())
                    .unwrap_or(&matched_text);
                if crate::placeholder::is_placeholder(value) {
                    continue;
                }
            }

            if context_filter.should_skip_line(line, &matched_text) {
                continue;
            }

            let entropy = shannon_entropy(&matched_text);
            if Self::should_include_by_entropy_static(pattern_name, &matched_text, entropy, line) {
                findings.push(Finding {
                    file_path: file_path.to_path_buf(),
                    line_number,
                    line_content: line.to_string(),
                    pattern_name: pattern_name.clone(),
                    matched_text,
                    entropy: Some(entropy),
                });
            }
        }

        findings.extend(Self::analyze_obfuscated_secrets_static(
            line,
            line_number,
            file_path,
            context_filter,
        ));
    }

    /// Get estimated memory usage for scanning a given number of files
    pub fn estimate_memory_usage(num_files: usize, avg_file_size: usize) -> (f64, String) {
        // Base memory for patterns and context filter (roughly 50KB)
        let base_memory = 50.0 * 1024.0;

        // Per-file overhead in parallel processing (roughly 16KB per thread)
        let thread_overhead = 16.0 * 1024.0 * rayon::current_num_threads() as f64;

        // Buffer memory per thread (8KB buffer * num_threads)
        let buffer_memory = 8.0 * 1024.0 * rayon::current_num_threads() as f64;

        // Estimated findings storage (assume 1% of files have findings, avg 200 bytes per finding)
        let findings_memory = (num_files as f64 * 0.01) * 200.0;

        // Large file chunking overhead (1MB buffer if any large files)
        let large_file_overhead = if avg_file_size > 10 * 1024 * 1024 {
            1024.0 * 1024.0 // 1MB chunk buffer
        } else {
            0.0
        };

        let total_bytes =
            base_memory + thread_overhead + buffer_memory + findings_memory + large_file_overhead;
        let total_mb = total_bytes / (1024.0 * 1024.0);

        let status = if total_mb > 100.0 {
            "WARNING: Estimated memory usage exceeds 100MB target".to_string()
        } else {
            "✓ Memory usage within target (<100MB)".to_string()
        };

        (total_mb, status)
    }

    /// Monitor actual memory usage during scanning (requires external memory monitoring)
    pub fn get_memory_stats() -> Option<(f64, f64)> {
        // This would require external crates like `psutil` or system calls
        // For now, return None to indicate it's not implemented
        // In a real implementation, this would return (current_mb, peak_mb)
        None
    }
    
    /// Static version of entropy filtering for use in parallel processing
    fn should_include_by_entropy_static(pattern_name: &str, matched_text: &str, entropy: f64, line: &str) -> bool {
        // Format-exact credentials (AKIA…, ghp_…, AIza…, secret_access_key=…) are
        // reported regardless of entropy: the format is the signal, and real keys
        // can be low-entropy (e.g. mostly-numeric AWS key IDs).
        if crate::context::is_high_confidence_format(matched_text) {
            return true;
        }

        // Pattern-specific entropy thresholds
        let entropy_threshold = match pattern_name {
            // High-entropy patterns that should always be included
            "AWS Access Key" | "AWS Access Key ID" | "GitHub Token" | "Google API Key" 
            | "OpenAI API Key" | "Stripe API Key" | "SendGrid API Key" | "Slack Token" 
            | "Twilio API Key" | "Mailgun API Key" | "Firebase API Key" | "DigitalOcean Token"
            | "Discord Token" | "Shopify Token" | "GitLab Token"
            | "GitHub Fine-Grained PAT" | "Anthropic API Key" | "OpenAI Project Key"
            | "Hugging Face Token" | "npm Access Token" | "PyPI Upload Token"
            | "Slack App Token" | "Stripe Restricted Key" => 2.5,
            
            // JWT tokens should have high entropy but allow some variation
            "JWT Token" => 3.0,
            
            // Database URLs and connection strings can have mixed entropy
            "PostgreSQL URL" | "MySQL URL" | "MongoDB URL" | "Redis URL" 
            | "Connection String" | "Database URL" => 2.0,
            
            // Password patterns need context-aware filtering
            "Password in JSON" | "Password in YAML" | "Password Environment Variable" 
            | "Password in URL" => {
                // Check if it looks like a real password vs test data
                if Self::looks_like_real_password(matched_text, line) {
                    1.5 // Lower threshold for contextual passwords
                } else {
                    4.0 // Higher threshold to filter test data
                }
            },
            
            // Generic secrets need higher entropy to avoid noise
            "Generic Secret" | "Generic OAuth Secret" | "Generic Client ID" => 3.0,
            
            // Private keys - pattern matching is usually sufficient
            "RSA Private Key" | "EC Private Key" | "PGP Private Key" | "SSH Private Key" 
            | "Generic Private Key" | "Multi-line Private Key" => 1.0,
            
            // Azure and cloud provider patterns
            "Azure Tenant ID" | "Azure Client Secret" => 2.5,
            "PayPal Client ID" | "PayPal Secret" => 2.5,
            
            // Built-in rules without a specific threshold.
            _ if crate::patterns::is_builtin_rule(pattern_name) => 3.0,

            // Custom rules: the author wrote the regex for exactly these
            // strings, so every match is reported regardless of entropy.
            _ => 0.0,
        };
        
        // Always include if entropy meets threshold
        if entropy >= entropy_threshold {
            return true;
        }
        
        // Additional context checks for borderline cases
        Self::has_strong_context_indicators(pattern_name, matched_text, line)
    }
    
    /// Check if a password looks real based on context and structure
    fn looks_like_real_password(password: &str, line: &str) -> bool {
        let line_lower = line.to_lowercase();
        let password_lower = password.to_lowercase();
        
        // Skip obvious test passwords
        let test_indicators = [
            "test", "dummy", "fake", "example", "sample", "placeholder",
            "password123", "secret123", "changeme", "default", "admin"
        ];
        
        for indicator in &test_indicators {
            if password_lower.contains(indicator) || line_lower.contains(indicator) {
                return false;
            }
        }
        
        // Look for production environment indicators
        let prod_indicators = [
            "prod", "production", "live", "staging", "config", "env",
            "secret", "password", "key", "auth", "token"
        ];
        
        let has_prod_context = prod_indicators.iter().any(|&indicator| {
            line_lower.contains(indicator) && !line_lower.contains("test")
        });
        
        // Check password complexity
        let has_mixed_case = password.chars().any(char::is_uppercase) && password.chars().any(char::is_lowercase);
        let has_numbers = password.chars().any(char::is_numeric);
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        let is_long_enough = password.len() >= 8;
        
        // Consider it real if it has production context or decent complexity
        has_prod_context || (is_long_enough && (has_mixed_case || has_numbers || has_special))
    }
    
    /// Check for strong context indicators that suggest a real secret
    fn has_strong_context_indicators(pattern_name: &str, matched_text: &str, line: &str) -> bool {
        let line_lower = line.to_lowercase();
        
        // Strong positive indicators
        let positive_indicators = [
            "production", "prod", "live", "staging", "config", "env",
            "secret", "private", "credential", "auth", "api", "token",
            "database", "db", "server", "host", "endpoint"
        ];
        
        // Strong negative indicators (test/example context)
        let negative_indicators = [
            "test", "spec", "example", "sample", "dummy", "fake",
            "placeholder", "mock", "fixture", "demo"
        ];
        
        // Check for negative indicators first
        for indicator in &negative_indicators {
            if line_lower.contains(indicator) {
                return false;
            }
        }
        
        // Check for positive indicators
        let has_positive = positive_indicators.iter().any(|&indicator| {
            line_lower.contains(indicator)
        });
        
        if has_positive {
            return true;
        }
        
        // Pattern-specific context checks
        match pattern_name {
            "GitHub OAuth" => {
                // GitHub OAuth tokens are 40 char hex strings, but need to be in right context
                matched_text.len() == 40 && matched_text.chars().all(|c| c.is_ascii_hexdigit())
                    && (line_lower.contains("github") || line_lower.contains("oauth") || line_lower.contains("token"))
            },
            "Azure Tenant ID" => {
                // UUID format in Azure context
                line_lower.contains("azure") || line_lower.contains("tenant") || line_lower.contains("directory")
            },
            "Heroku API Key" => {
                // UUID format in Heroku context
                line_lower.contains("heroku") || line_lower.contains("app") || line_lower.contains("dyno")
            },
            _ => false,
        }
    }
    
    /// Static version of obfuscated secret analysis
    fn analyze_obfuscated_secrets_static(line: &str, line_number: usize, file_path: &Path, context_filter: &ContextFilter) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Analyze suspicious base64 strings
        let base64_regex = &*OBFUSCATED_BASE64;
        for cap in base64_regex.captures_iter(line) {
            if let Some(b64_match) = cap.get(1) {
                let b64_string = b64_match.as_str();
                
                if is_suspicious_base64(b64_string, line) {
                    let decoded_secrets = analyze_base64_for_secrets(b64_string);
                    for (pattern_name, decoded_value) in decoded_secrets {
                        // Apply context filtering
                        if !context_filter.should_skip_line(line, &decoded_value) {
                            let entropy = shannon_entropy(b64_string);
                            
                            findings.push(Finding {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                line_content: line.to_string(),
                                pattern_name,
                                matched_text: format!("{} (base64: {})", decoded_value, b64_string),
                                entropy: Some(entropy),
                            });
                        }
                    }
                }
            }
        }
        
        // Analyze suspicious hex strings
        let hex_regex = &*OBFUSCATED_HEX;
        for cap in hex_regex.captures_iter(line) {
            if let Some(hex_match) = cap.get(1) {
                let hex_string = hex_match.as_str();
                
                if is_suspicious_hex(hex_string, line) {
                    let decoded_secrets = analyze_hex_for_secrets(hex_string);
                    for (pattern_name, decoded_value) in decoded_secrets {
                        // Apply context filtering
                        if !context_filter.should_skip_line(line, &decoded_value) {
                            let entropy = shannon_entropy(hex_string);
                            
                            findings.push(Finding {
                                file_path: file_path.to_path_buf(),
                                line_number,
                                line_content: line.to_string(),
                                pattern_name,
                                matched_text: format!("{} (hex: {})", decoded_value, hex_string),
                                entropy: Some(entropy),
                            });
                        }
                    }
                }
            }
        }
        
        // Analyze URL encoded strings
        let url_encoded_regex = &*OBFUSCATED_URL_ENCODED;
        for cap in url_encoded_regex.captures_iter(line) {
            if let Some(url_match) = cap.get(1) {
                let url_string = url_match.as_str();
                
                let decoded_secrets = analyze_url_encoded_for_secrets(url_string);
                for (pattern_name, decoded_value) in decoded_secrets {
                    // Apply context filtering
                    if !context_filter.should_skip_line(line, &decoded_value) {
                        let entropy = shannon_entropy(url_string);
                        
                        findings.push(Finding {
                            file_path: file_path.to_path_buf(),
                            line_number,
                            line_content: line.to_string(),
                            pattern_name,
                            matched_text: format!("{} (url-encoded: {})", decoded_value, url_string),
                            entropy: Some(entropy),
                        });
                    }
                }
            }
        }
        
        // Analyze character arrays
        let char_array_regex = &*OBFUSCATED_CHAR_ARRAY;
        for mat in char_array_regex.find_iter(line) {
            let array_string = mat.as_str();
            
            let decoded_secrets = analyze_character_array_for_secrets(array_string);
            for (pattern_name, decoded_value) in decoded_secrets {
                // Apply context filtering
                if !context_filter.should_skip_line(line, &decoded_value) {
                    let entropy = shannon_entropy(array_string);
                    
                    findings.push(Finding {
                        file_path: file_path.to_path_buf(),
                        line_number,
                        line_content: line.to_string(),
                        pattern_name,
                        matched_text: format!("{} (char-array: {})", decoded_value, array_string),
                        entropy: Some(entropy),
                    });
                }
            }
        }
        
        findings
    }
}