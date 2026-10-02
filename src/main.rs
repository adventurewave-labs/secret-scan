use clap::{Arg, ArgAction, Command};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use secretscan::patterns::Severity;
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
    let baseline_path = matches.get_one::<String>("baseline");
    let write_baseline_path = matches.get_one::<String>("write-baseline");

    // Load the baseline before scanning: a bad path should fail immediately.
    let baseline = baseline_path.map(|path| match Baseline::load(Path::new(path)) {
        Ok(baseline) => baseline,
        Err(e) => {
            eprintln!("{} Cannot read baseline {}: {}", "Error:".red().bold(), path, e);
            process::exit(2);
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
        process::exit(1);
    }

    // Create scanner with appropriate context filter
    let mut scanner = match Scanner::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} Failed to create scanner: {}", "Error:".red().bold(), e);
            process::exit(1);
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
            process::exit(1);
        }
    };

    // Applied before anything is reported, so the summary line, the output
    // and the exit code all describe the same set of findings.
    filter_by_severity(&mut findings, min_severity);

    if let Some(path) = write_baseline_path {
        let recorded = Baseline::from_findings(&findings);
        if let Err(e) = recorded.save(Path::new(path)) {
            eprintln!("{} Cannot write baseline {}: {}", "Error:".red().bold(), path, e);
            process::exit(2);
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
                process::exit(1);
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
                process::exit(1);
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
            process::exit(1);
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
        process::exit(1); // Non-zero exit code when secrets are found
    }
}
