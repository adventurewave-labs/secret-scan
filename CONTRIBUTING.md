# Contributing to Secretscan

Thank you for your interest in contributing to secretscan! We welcome contributions from the community and are grateful for any help you can provide.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct. Please be respectful and considerate in all interactions.

## How to Contribute

### Reporting Issues

- Check if the issue has already been reported
- Use the issue template when creating new issues
- Provide as much detail as possible, including:
  - Your operating system and version
  - Rust version (`rustc --version`)
  - Steps to reproduce the issue
  - Expected vs actual behavior

### Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install Rust** (latest stable version)
3. **Run tests** to ensure everything works: `cargo test`
4. **Make your changes** following our coding standards
5. **Add tests** for any new functionality
6. **Update documentation** as needed
7. **Run the full test suite**: 
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```
8. **Submit a pull request** with a clear description of your changes

### Development Setup

```bash
# Clone your fork
git clone https://github.com/adventurewave-labs/secret-scan.git
cd secretscan

# Install dependencies and build
cargo build

# Run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run -- scan .

# Run benchmarks
cargo bench
```

### Coding Standards

- Follow Rust's official style guidelines
- Use `cargo fmt` to format your code
- Use `cargo clippy` to check for common mistakes
- Write descriptive commit messages
- Add comments for complex logic
- Update documentation for public APIs

### Testing

- Write unit tests for new functionality
- Add integration tests for new features
- Ensure all tests pass before submitting PR
- Aim for high test coverage
- Test edge cases and error conditions

### Documentation

- Update README.md if adding new features
- Add rustdoc comments for public functions
- Update CHANGELOG.md following Keep a Changelog format
- Include examples in documentation

### Performance Considerations

Since secretscan is performance-critical:
- Profile your changes with `cargo bench`
- Avoid unnecessary allocations
- Use parallel processing where appropriate
- Consider memory usage for large codebases

## Development Guidelines

### Adding New Secret Patterns

1. Add pattern to `src/patterns.rs`
2. Add test cases in `tests/pattern_test.rs`
3. Update documentation with new pattern
4. Consider entropy requirements

### Improving Performance

1. Run benchmarks before and after changes
2. Use flamegraphs to identify bottlenecks
3. Consider parallelization opportunities
4. Minimize regex compilations

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create a PR with version bump
4. After merge, tag the release
5. Publish to crates.io

## Getting Help

- Check the documentation
- Look through existing issues
- Ask questions in discussions
- Reach out to maintainers

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- GitHub contributors page

Thank you for contributing to secretscan!