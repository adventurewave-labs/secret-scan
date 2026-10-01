# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning and other CI dashboards; results carry a stable fingerprint and never include secret text
- `--redact` flag to mask secret values in text and JSON output
- Inline suppression with `secretscan:allow` / `gitleaks:allow`
- Eight modern token formats: GitHub fine-grained PAT, Anthropic, OpenAI project/service-account keys, Hugging Face, npm, PyPI, Slack app tokens, Stripe restricted keys and webhook secrets
- `rule_id` and `fingerprint` helpers in the library API

### Changed
- Built-in rules are defined once, in a single `RULE_DEFS` table; `patterns::rules()` exposes them with stable ids. Detection behaviour is unchanged

### Fixed
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