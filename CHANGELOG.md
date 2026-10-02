# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Severity (`low`, `medium`, `high`, `critical`) on every rule, shown in text output, JSON and SARIF (`level` and `security-severity`)
- `--min-severity <level>` to report, and fail on, only findings at or above a severity
- JSON output now includes `rule_id`, `severity` and `fingerprint` for each finding
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning and other CI dashboards; results carry a stable fingerprint and never include secret text
- `--redact` flag to mask secret values in text and JSON output
- Inline suppression with `secretscan:allow` / `gitleaks:allow`
- Eight modern token formats: GitHub fine-grained PAT, Anthropic, OpenAI project/service-account keys, Hugging Face, npm, PyPI, Slack app tokens, Stripe restricted keys and webhook secrets
- `rule_id` and `fingerprint` helpers in the library API

### Changed
- One scan path for all files regardless of size; removed the separate chunked path for files over 10 MB, the legacy `scan_directory_rayon` and the `SECRETSCAN_DEBUG` output
- Built-in rules are defined once, in a single `RULE_DEFS` table; `patterns::rules()` exposes them with stable ids. Detection behaviour is unchanged

### Performance
- A `RegexSet` prefilter runs each rule's regex only on lines it can match
- Four regexes used for obfuscation analysis were recompiled for every scanned line; they are now compiled once

### Fixed
- The per-rule summary in text output was listed in a different order on every run
- A file containing any invalid UTF-8 byte was skipped entirely; it is now scanned, with invalid bytes replaced
- A single private key produced up to three findings (specific, generic and multi-line rules); it is now reported once under its most specific rule
- Unlabelled PKCS#8 keys (`BEGIN PRIVATE KEY`) were reported as "RSA Private Key"; they are now "Generic Private Key"
- "Heroku API Key" and "Azure Tenant ID" reported every UUID in a codebase, twice; both now require the provider name in the variable being assigned
- Entropy values differed in the last bits from run to run (hash-map iteration order); they are now reproducible
- Entropy divided by byte length instead of character count, under-reporting non-ASCII text
- Findings came back in a different order on every run; they are now sorted by file, line and rule
- `--version` reported 0.2.1 regardless of the crate version

## [0.2.1] - 2025-07-02

## [0.2.0] - 2025-07-02

## [0.1.0] - 2025-01-02

### Added
- Initial release of secretscan
- Core scanning functionality with pattern-based secret detection
- Support for 20+ secret patterns including API keys, tokens, and credentials
- Entropy-based detection for high-entropy strings
- Git-aware scanning with .gitignore support
- Parallel file processing for improved performance
- Multiple output formats: JSON and human-readable
- Progress indicators and colored output for better UX
- Configurable confidence thresholds
- Context extraction for better secret identification
- Comprehensive test suite with >90% code coverage

### Features
- Fast parallel scanning using Rayon
- Respects .gitignore patterns
- Multiple output formats (JSON, YAML, human-readable)
- Entropy-based detection
- Configurable thresholds
- Progress indicators
- Colored terminal output

[0.1.0]: https://github.com/adventurewave-labs/secret-scan/releases/tag/v0.1.0