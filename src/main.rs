use clap::{Arg, ArgAction, Command};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use secretscan::config::Config;
use secretscan::patterns::{get_all_patterns_owned, register_custom_severity, Severity};
use secretscan::{output::*, ContextFilter, Scanner};
use std::fs;
use secretscan::baseline::Baseline;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Clone)]
enum OutputFormat {
    Json,
    Sarif,
    Text,
}

impl From<&str> for OutputFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "sarif" => OutputFormat::Sarif,
            "text" => OutputFormat::Text,
            _ => OutputFormat::Text,
        }
    }
}

/// Exit status for anything that prevented a trustworthy result: bad
/// arguments, unreadable config or baseline, a failed scan or write. Distinct
/// from the findings status so CI can tell "secrets found" from "scan broken".
const EXIT_ERROR: i32 = 2;

fn main() {
    let matches = Command::new("secretscan")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Secretscan Team")
        .about("A Rust CLI tool for detecting secrets in codebases")
        .arg(
            Arg::new("path")
                .help("Path to scan for secrets")
                .value_name("PATH")
                .default_value(".")
                .index(1),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .help("Output format")
                .value_name("FORMAT")
                .value_parser(["json", "sarif", "text"])
                .default_value("text"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Output file (default: stdout)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .help("Suppress progress bar")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-tests")
                .long("skip-tests")
                .help("Skip test files and test-related patterns to reduce false positives")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("min-severity")
                .long("min-severity")
                .help("Report only findings at or above this severity")
                .value_name("LEVEL")
                .value_parser(["low", "medium", "high", "critical"])
                .default_value("low"),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .help("Config file (default: .secretscan.toml in the scanned directory, if present)")
                .value_name("FILE")
                .conflicts_with("no-config"),
        )
        .arg(
            Arg::new("no-config")
                .long("no-config")
                .help("Ignore any .secretscan.toml")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("baseline")
                .long("baseline")
                .help("Suppress findings recorded in this baseline file; only new findings are reported")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("write-baseline")
                .long("write-baseline")
                .help("Record every finding of this scan in a baseline file and exit 0")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("exit-code")
                .long("exit-code")
                .help("Exit status when findings are reported")
                .value_name("CODE")
                .value_parser(clap::value_parser!(u8))
                .default_value("1")
                .conflicts_with("no-fail"),
        )
        .arg(
            Arg::new("no-fail")
                .long("no-fail")
                .help("Exit 0 even when findings are reported (report-only mode); errors still exit 2")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("redact")
                .long("redact")
                .help("Mask secret values in the output (safe for CI logs and shared reports)")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let scan_path = PathBuf::from(matches.get_one::<String>("path").unwrap());
    let format = OutputFormat::from(matches.get_one::<String>("format").unwrap().as_str());
    let output_file = matches.get_one::<String>("output");
    let quiet = matches.get_flag("quiet");
    let skip_tests = matches.get_flag("skip-tests");
    let redact = matches.get_flag("redact");
    let findings_exit_code: i32 = if matches.get_flag("no-fail") {
        0
    } else {
        i32::from(*matches.get_one::<u8>("exit-code").unwrap())
    };
    let baseline_path = matches.get_one::<String>("baseline");
    let write_baseline_path = matches.get_one::<String>("write-baseline");

    // Load the baseline before scanning: a bad path should fail immediately.
    let baseline = baseline_path.map(|path| match Baseline::load(Path::new(path)) {
        Ok(baseline) => baseline,
        Err(e) => {
            eprintln!("{} Cannot read baseline {}: {}", "Error:".red().bold(), path, e);
            process::exit(EXIT_ERROR);
        }
    });
    let min_severity = matches
        .get_one::<String>("min-severity")
        .and_then(|level| Severity::parse(level))
        .unwrap_or(Severity::Low);

    // Validate scan path
    if !scan_path.exists() {
        eprintln!(
            "{} Path does not exist: {}",
            "Error:".red().bold(),
            scan_path.display()
        );
        process::exit(EXIT_ERROR);
    }

    // An explicit --config must exist; a discovered one is optional.
    let config_path = match matches.get_one::<String>("config") {
        Some(path) => Some(PathBuf::from(path)),
        None if matches.get_flag("no-config") => None,
        None => Config::discover(&scan_path),
    };
    let config = match &config_path {
        Some(path) => match Config::load(path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "{} Invalid config {}: {}",
                    "Error:".red().bold(),
                    path.display(),
                    e
                );
                process::exit(EXIT_ERROR);
            }
        },
        None => Config::default(),
    };

    // Create scanner with appropriate context filter
    let scanner_result = if config.custom_rules().is_empty() {
        Scanner::new()
    } else {
        let mut patterns: Vec<(String, regex::Regex)> =
            get_all_patterns_owned().into_iter().collect();
        for rule in config.custom_rules() {
            register_custom_severity(&rule.name, rule.severity);
            patterns.push((rule.name.clone(), rule.regex.clone()));
        }
        Scanner::with_patterns(patterns)
    };
    let mut scanner = match scanner_result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} Failed to create scanner: {}", "Error:".red().bold(), e);
            process::exit(EXIT_ERROR);
        }
    };

    // Configure context filter based on CLI flags
    if skip_tests {
        scanner.set_context_filter(ContextFilter::new());
    } else {
        scanner.set_context_filter(ContextFilter::none());
    }

    // Setup progress bar
    let progress = if !quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message(format!("Scanning {}", scan_path.display()));
        Some(pb)
    } else {
        None
    };

    // Perform scan
    let mut findings = match scanner.scan_directory(&scan_path) {
        Ok(findings) => findings,
        Err(e) => {
            if let Some(pb) = &progress {
                pb.finish_with_message(format!("{} Scan failed", "✗".red().bold()));
            }
            eprintln!("{} Scan failed: {}", "Error:".red().bold(), e);
            process::exit(EXIT_ERROR);
        }
    };

    config.apply(&mut findings);
    // The config file holds allowlist patterns and rule regexes, which can
    // look like the secrets they describe; it is not itself scanned.
    if let Some(config_file) = config_path.as_ref().and_then(|p| fs::canonicalize(p).ok()) {
        findings.retain(|f| fs::canonicalize(&f.file_path).ok().as_ref() != Some(&config_file));
    }

    // Applied before anything is reported, so the summary line, the output
    // and the exit code all describe the same set of findings.
    filter_by_severity(&mut findings, min_severity);

    if let Some(path) = write_baseline_path {
        let recorded = Baseline::from_findings(&findings);
        if let Err(e) = recorded.save(Path::new(path)) {
            eprintln!("{} Cannot write baseline {}: {}", "Error:".red().bold(), path, e);
            process::exit(EXIT_ERROR);
        }
        if let Some(pb) = &progress {
            pb.finish_and_clear();
        }
        if !quiet {
            println!(
                "{} Recorded {} findings in {}",
                "✓".green().bold(),
                recorded.len(),
                path
            );
        }
        process::exit(0);
    }

    let suppressed = baseline
        .as_ref()
        .map(|baseline| baseline.suppress(&mut findings))
        .unwrap_or(0);

    if let Some(pb) = &progress {
        let note = if baseline.is_some() {
            format!(" ({} suppressed by baseline)", suppressed)
        } else {
            String::new()
        };
        pb.finish_with_message(format!(
            "{} Found {} potential secrets{}",
            "✓".green().bold(),
            findings.len(),
            note
        ));
    }

    // Fingerprints identify the real secret, so take them before redaction.
    let fingerprints: Vec<String> = findings.iter().map(fingerprint).collect();

    // SARIF is rendered before redaction: its fingerprints are derived from
    // the real secret, and SARIF output never contains secret text anyway.
    let sarif = match format {
        OutputFormat::Sarif => match format_as_sarif(&findings, env!("CARGO_PKG_VERSION")) {
            Ok(sarif) => Some(sarif),
            Err(e) => {
                eprintln!("{} Failed to format SARIF: {}", "Error:".red().bold(), e);
                process::exit(EXIT_ERROR);
            }
        },
        _ => None,
    };

    if redact {
        redact_findings(&mut findings);
    }

    // Format output
    let output_content = match format {
        OutputFormat::Sarif => sarif.unwrap_or_default(),
        OutputFormat::Json => match format_as_json_with_fingerprints(&findings, &fingerprints) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("{} Failed to format JSON: {}", "Error:".red().bold(), e);
                process::exit(EXIT_ERROR);
            }
        },
        OutputFormat::Text => {
            if findings.is_empty() {
                format!("{} No secrets found! 🎉", "Success:".green().bold())
            } else {
                format!(
                    "{}\n\n{}{}",
                    format!(
                        "{} Found {} potential secrets:",
                        "Warning:".yellow().bold(),
                        findings.len()
                    )
                    .bold(),
                    format_as_text(&findings),
                    generate_summary(&findings).bright_blue()
                )
            }
        }
    };

    // Write output
    if let Some(file_path) = output_file {
        if let Err(e) = fs::write(file_path, &output_content) {
            eprintln!(
                "{} Failed to write to file {}: {}",
                "Error:".red().bold(),
                file_path,
                e
            );
            process::exit(EXIT_ERROR);
        }
        if !quiet {
            println!("{} Results written to {}", "✓".green().bold(), file_path);
        }
    } else {
        println!("{}", output_content);
    }

    // Exit with appropriate code
    if findings.is_empty() {
        process::exit(0);
    } else {
        process::exit(findings_exit_code);
    }
}
