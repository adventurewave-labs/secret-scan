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
use regex::Regex;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
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

pub struct Scanner {
    patterns: HashMap<String, Regex>,
    context_filter: ContextFilter,
}

impl Scanner {
    pub fn new() -> Result<Self, ScannerError> {
        Ok(Scanner {
            patterns: get_all_patterns_owned(),
            context_filter: ContextFilter::new(),
        })
    }

    pub fn with_patterns(patterns: Vec<(String, Regex)>) -> Result<Self, ScannerError> {
        let mut pattern_map = HashMap::new();
        for (name, pattern) in patterns {
            pattern_map.insert(name, pattern);
        }

        Ok(Scanner {
            patterns: pattern_map,
            context_filter: ContextFilter::new(),
        })
    }

    /// Create scanner with custom context filter
    pub fn with_context_filter(context_filter: ContextFilter) -> Result<Self, ScannerError> {
        Ok(Scanner {
            patterns: get_all_patterns_owned(),
            context_filter,
        })
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
        Self::dedupe_overlapping_findings(&mut findings);
        Ok(findings)
    }

    /// Remove redundant findings that describe the same secret on the same line.
    ///
    /// Three surgical rules, applied per (file, line):
    ///   1. Generic catch-all patterns (Suspicious Base64/Hex, Generic Secret, …) are
    ///      dropped when a specific pattern already matched overlapping text.
    ///   2. "Firebase API Key" is dropped when "Google API Key" matched the identical
    ///      text — the two formats are byte-identical (Firebase keys ARE Google keys).
    ///   3. The contextual "AWS Access Key" match is dropped when the bare
    ///      "AWS Access Key ID" already reported the key it contains.
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
        let patterns = Arc::new(self.patterns.clone());
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

    /// Legacy parallel scanning method (for comparison)
    pub fn scan_directory_rayon(&self, path: &Path) -> Result<Vec<Finding>, ScannerError> {
        let mut findings = Vec::new();

        // Use ignore crate to respect .gitignore
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
            .collect::<Vec<_>>();

        // Process files in parallel with rayon
        let parallel_findings: Vec<Vec<Finding>> = walker
            .par_iter()
            .filter(|entry| {
                // Skip .git directory files
                if entry.path().components().any(|c| c.as_os_str() == ".git") {
                    return false;
                }

                // Apply context filtering
                !self.context_filter.should_skip_path(entry.path())
            })
            .map(|entry| self.scan_file(entry.path()).unwrap_or_else(|_| Vec::new()))
            .collect();

        // Flatten results
        for file_findings in parallel_findings {
            findings.extend(file_findings);
        }

        Ok(findings)
    }

    fn scan_file(&self, file_path: &Path) -> Result<Vec<Finding>, ScannerError> {
        self.scan_file_streaming(file_path)
    }

    /// Memory-optimized file scanning using BufReader and streaming
    fn scan_file_streaming(&self, file_path: &Path) -> Result<Vec<Finding>, ScannerError> {
        let file = File::open(file_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // For very large files (>10MB), use chunked streaming
        if file_size > 10 * 1024 * 1024 {
            self.scan_large_file_chunked(file_path, file)
        } else {
            self.scan_file_buffered(file_path, file)
        }
    }

    /// Scan regular files with BufReader for memory efficiency
    fn scan_file_buffered(
        &self,
        file_path: &Path,
        file: File,
    ) -> Result<Vec<Finding>, ScannerError> {
        let reader = BufReader::with_capacity(8192, file); // 8KB buffer
        let mut findings = Vec::new();

        for (line_number, line_result) in reader.lines().enumerate() {
            let line_number = line_number + 1; // Convert to 1-indexed
            let line = line_result?;

            // Check against all patterns
            for (pattern_name, pattern) in &self.patterns {
                // Debug logging for AWS patterns when enabled
                if pattern_name.contains("AWS") && std::env::var("SECRETSCAN_DEBUG").is_ok() {
                    eprintln!("[DEBUG] Testing AWS pattern '{}' against line: {}", pattern_name, line.trim());
                }
                
                if let Some(mat) = pattern.find(&line) {
                    let matched_text = mat.as_str().to_string();
                    
                    // Debug logging for successful matches
                    if pattern_name.contains("AWS") && std::env::var("SECRETSCAN_DEBUG").is_ok() {
                        eprintln!("[DEBUG] AWS pattern '{}' MATCHED: '{}'", pattern_name, matched_text);
                    }

                    // Apply context filtering for line content
                    if self.context_filter.should_skip_line(&line, &matched_text) {
                        if pattern_name.contains("AWS") && std::env::var("SECRETSCAN_DEBUG").is_ok() {
                            eprintln!("[DEBUG] AWS match skipped by context filter");
                        }
                        continue;
                    }

                    let entropy = shannon_entropy(&matched_text);
                    
                    // Apply adaptive entropy filtering based on pattern type and context
                    if Self::should_include_by_entropy_static(pattern_name, &matched_text, entropy, &line) {
                        if pattern_name.contains("AWS") && std::env::var("SECRETSCAN_DEBUG").is_ok() {
                            eprintln!("[DEBUG] AWS finding added: {} in {}", matched_text, file_path.display());
                        }
                        findings.push(Finding {
                            file_path: file_path.to_path_buf(),
                            line_number,
                            line_content: line.clone(),
                            pattern_name: pattern_name.clone(),
                            matched_text,
                            entropy: Some(entropy),
                        });
                    } else if pattern_name.contains("AWS") && std::env::var("SECRETSCAN_DEBUG").is_ok() {
                        eprintln!("[DEBUG] AWS match rejected by entropy filter: {} (entropy: {:.2})", matched_text, entropy);
                    }
                }
            }
            
            // Additional analysis for obfuscated secrets
            let additional_findings = self.analyze_obfuscated_secrets(&line, line_number, file_path);
            findings.extend(additional_findings);
        }

        Ok(findings)
    }

    /// Scan very large files in chunks to minimize memory usage
    fn scan_large_file_chunked(
        &self,
        file_path: &Path,
        mut file: File,
    ) -> Result<Vec<Finding>, ScannerError> {
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

        let mut findings = Vec::new();
        let mut global_line_number = 0;
        let mut buffer = vec![0; CHUNK_SIZE];
        let mut overlap_buffer = String::new();

        loop {
            // Read chunk
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break; // EOF
            }

            // Convert to string, handling potential UTF-8 boundary issues
            let chunk = match std::str::from_utf8(&buffer[..bytes_read]) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    // Handle UTF-8 boundary issues by truncating at last valid UTF-8 boundary
                    let valid_up_to = e.valid_up_to();
                    if valid_up_to > 0 {
                        // Seek back to handle remaining bytes in next iteration
                        let seek_back = bytes_read - valid_up_to;
                        file.seek(SeekFrom::Current(-(seek_back as i64)))?;
                        String::from_utf8_lossy(&buffer[..valid_up_to]).into_owned()
                    } else {
                        continue; // Skip malformed chunk
                    }
                }
            };

            // Prepend overlap from previous chunk
            let content = if overlap_buffer.is_empty() {
                chunk
            } else {
                format!("{}{}", overlap_buffer, chunk)
            };

            // Process lines in this chunk
            let lines: Vec<&str> = content.lines().collect();
            let lines_to_process = if bytes_read < CHUNK_SIZE {
                // Last chunk, process all lines
                lines.len()
            } else {
                // Not last chunk, save last line for overlap
                lines.len().saturating_sub(1)
            };

            for line in lines.iter().take(lines_to_process) {
                global_line_number += 1;

                // Check against all patterns
                for (pattern_name, pattern) in &self.patterns {
                    if let Some(mat) = pattern.find(line) {
                        let matched_text = mat.as_str().to_string();

                        // Apply context filtering for line content
                        if self.context_filter.should_skip_line(line, &matched_text) {
                            continue;
                        }

                        let entropy = shannon_entropy(&matched_text);
                        
                        // Apply adaptive entropy filtering
                        if self.should_include_by_entropy(pattern_name, &matched_text, entropy, line) {
                            findings.push(Finding {
                                file_path: file_path.to_path_buf(),
                                line_number: global_line_number,
                                line_content: line.to_string(),
                                pattern_name: pattern_name.clone(),
                                matched_text,
                                entropy: Some(entropy),
                            });
                        }
                    }
                }
            }

            // Prepare overlap for next chunk
            overlap_buffer = if lines_to_process < lines.len() {
                lines[lines_to_process].to_string()
            } else {
                String::new()
            };

            // If we read less than chunk size, we've reached EOF
            if bytes_read < CHUNK_SIZE {
                // Process the final overlap line if it exists
                if !overlap_buffer.is_empty() {
                    global_line_number += 1;

                    for (pattern_name, pattern) in &self.patterns {
                        if let Some(mat) = pattern.find(&overlap_buffer) {
                            let matched_text = mat.as_str().to_string();

                            if !self
                                .context_filter
                                .should_skip_line(&overlap_buffer, &matched_text)
                            {
                                let entropy = shannon_entropy(&matched_text);
                                
                                // Apply adaptive entropy filtering
                                if Self::should_include_by_entropy_static(pattern_name, &matched_text, entropy, &overlap_buffer) {
                                    findings.push(Finding {
                                        file_path: file_path.to_path_buf(),
                                        line_number: global_line_number,
                                        line_content: overlap_buffer.clone(),
                                        pattern_name: pattern_name.clone(),
                                        matched_text,
                                        entropy: Some(entropy),
                                    });
                                }
                            }
                        }
                    }
                }
                break;
            }
        }

        Ok(findings)
    }

    /// Static version of scan_file for use with Arc references in parallel processing
    fn scan_file_static(
        file_path: &Path,
        patterns: &HashMap<String, Regex>,
        context_filter: &ContextFilter,
    ) -> Result<Vec<Finding>, ScannerError> {
        Self::scan_file_static_streaming(file_path, patterns, context_filter)
    }

    /// Memory-optimized static scan_file method
    fn scan_file_static_streaming(
        file_path: &Path,
        patterns: &HashMap<String, Regex>,
        context_filter: &ContextFilter,
    ) -> Result<Vec<Finding>, ScannerError> {
        let file = File::open(file_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // For very large files (>10MB), use chunked streaming
        if file_size > 10 * 1024 * 1024 {
            Self::scan_file_static_chunked(file_path, file, patterns, context_filter)
        } else {
            Self::scan_file_static_buffered(file_path, file, patterns, context_filter)
        }
    }

    /// Static buffered file scanning
    fn scan_file_static_buffered(
        file_path: &Path,
        file: File,
        patterns: &HashMap<String, Regex>,
        context_filter: &ContextFilter,
    ) -> Result<Vec<Finding>, ScannerError> {
        let reader = BufReader::with_capacity(8192, file);
        let mut findings = Vec::new();

        for (line_number, line_result) in reader.lines().enumerate() {
            let line_number = line_number + 1; // Convert to 1-indexed
            let line = line_result?;

            // Check against all patterns
            for (pattern_name, pattern) in patterns {
                if let Some(mat) = pattern.find(&line) {
                    let matched_text = mat.as_str().to_string();

                    // Apply context filtering for line content
                    if context_filter.should_skip_line(&line, &matched_text) {
                        continue;
                    }

                    let entropy = shannon_entropy(&matched_text);
                    
                    // Apply adaptive entropy filtering based on pattern type and context
                    if Self::should_include_by_entropy_static(pattern_name, &matched_text, entropy, &line) {
                        findings.push(Finding {
                            file_path: file_path.to_path_buf(),
                            line_number,
                            line_content: line.clone(),
                            pattern_name: pattern_name.clone(),
                            matched_text,
                            entropy: Some(entropy),
                        });
                    }
                }
            }
            
            // Additional analysis for obfuscated secrets
            let additional_findings = Self::analyze_obfuscated_secrets_static(&line, line_number, file_path, context_filter);
            findings.extend(additional_findings);
        }

        Ok(findings)
    }

    /// Static chunked file scanning for very large files
    fn scan_file_static_chunked(
        file_path: &Path,
        mut file: File,
        patterns: &HashMap<String, Regex>,
        context_filter: &ContextFilter,
    ) -> Result<Vec<Finding>, ScannerError> {
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

        let mut findings = Vec::new();
        let mut global_line_number = 0;
        let mut buffer = vec![0; CHUNK_SIZE];
        let mut overlap_buffer = String::new();

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let chunk = match std::str::from_utf8(&buffer[..bytes_read]) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    let valid_up_to = e.valid_up_to();
                    if valid_up_to > 0 {
                        let seek_back = bytes_read - valid_up_to;
                        file.seek(SeekFrom::Current(-(seek_back as i64)))?;
                        String::from_utf8_lossy(&buffer[..valid_up_to]).into_owned()
                    } else {
                        continue;
                    }
                }
            };

            let content = if overlap_buffer.is_empty() {
                chunk
            } else {
                format!("{}{}", overlap_buffer, chunk)
            };

            let lines: Vec<&str> = content.lines().collect();
            let lines_to_process = if bytes_read < CHUNK_SIZE {
                lines.len()
            } else {
                lines.len().saturating_sub(1)
            };

            for line in lines.iter().take(lines_to_process) {
                global_line_number += 1;

                for (pattern_name, pattern) in patterns {
                    if let Some(mat) = pattern.find(line) {
                        let matched_text = mat.as_str().to_string();

                        if !context_filter.should_skip_line(line, &matched_text) {
                            let entropy = shannon_entropy(&matched_text);

                            findings.push(Finding {
                                file_path: file_path.to_path_buf(),
                                line_number: global_line_number,
                                line_content: line.to_string(),
                                pattern_name: pattern_name.clone(),
                                matched_text,
                                entropy: Some(entropy),
                            });
                        }
                    }
                }
                
                // Additional analysis for obfuscated secrets
                let additional_findings = Self::analyze_obfuscated_secrets_static(line, global_line_number, file_path, context_filter);
                findings.extend(additional_findings);
            }

            overlap_buffer = if lines_to_process < lines.len() {
                lines[lines_to_process].to_string()
            } else {
                String::new()
            };

            if bytes_read < CHUNK_SIZE {
                if !overlap_buffer.is_empty() {
                    global_line_number += 1;

                    for (pattern_name, pattern) in patterns {
                        if let Some(mat) = pattern.find(&overlap_buffer) {
                            let matched_text = mat.as_str().to_string();

                            if !context_filter.should_skip_line(&overlap_buffer, &matched_text) {
                                let entropy = shannon_entropy(&matched_text);
                                
                                // Apply adaptive entropy filtering
                                if Self::should_include_by_entropy_static(pattern_name, &matched_text, entropy, &overlap_buffer) {
                                    findings.push(Finding {
                                        file_path: file_path.to_path_buf(),
                                        line_number: global_line_number,
                                        line_content: overlap_buffer.clone(),
                                        pattern_name: pattern_name.clone(),
                                        matched_text,
                                        entropy: Some(entropy),
                                    });
                                }
                            }
                        }
                    }
                    
                    // Additional analysis for obfuscated secrets in overlap buffer
                    let additional_findings = Self::analyze_obfuscated_secrets_static(&overlap_buffer, global_line_number, file_path, context_filter);
                    findings.extend(additional_findings);
                }
                break;
            }
        }

        Ok(findings)
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
    
    /// Adaptive entropy filtering based on pattern type and context
    fn should_include_by_entropy(&self, pattern_name: &str, matched_text: &str, entropy: f64, line: &str) -> bool {
        Self::should_include_by_entropy_static(pattern_name, matched_text, entropy, line)
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
            | "Discord Token" | "Shopify Token" | "GitLab Token" => 2.5,
            
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
            
            // Default threshold for unknown patterns
            _ => 3.0,
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
    
    /// Analyze line for obfuscated/encoded secrets
    fn analyze_obfuscated_secrets(&self, line: &str, line_number: usize, file_path: &Path) -> Vec<Finding> {
        Self::analyze_obfuscated_secrets_static(line, line_number, file_path, &self.context_filter)
    }
    
    /// Static version of obfuscated secret analysis
    fn analyze_obfuscated_secrets_static(line: &str, line_number: usize, file_path: &Path, context_filter: &ContextFilter) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Analyze suspicious base64 strings
        let base64_regex = regex::Regex::new(r#"["']([A-Za-z0-9+/]{20,}={0,2})["']"#).unwrap();
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
        let hex_regex = regex::Regex::new(r#"["']([a-fA-F0-9]{40,})["']"#).unwrap();
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
        let url_encoded_regex = regex::Regex::new(r#"["']([^"']*%[0-9A-Fa-f]{2}[^"']*)["']"#).unwrap();
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
        let char_array_regex = regex::Regex::new(r"\[(?:\s*\d+\s*,?\s*){10,}\]").unwrap();
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