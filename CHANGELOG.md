# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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