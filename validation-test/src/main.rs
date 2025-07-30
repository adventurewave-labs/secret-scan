use clap::{Arg, ArgAction, Command};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use secretscan::{output::*, ContextFilter, Scanner};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Clone)]
enum OutputFormat {
    Json,
    Text,
}

impl From<&str> for OutputFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "text" => OutputFormat::Text,
            _ => OutputFormat::Text,
        }
    }
}

fn main() {
    let matches = Command::new("secretscan")
        .version("0.2.1")
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
                .value_parser(["json", "text"])
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
        .get_matches();

    let scan_path = PathBuf::from(matches.get_one::<String>("path").unwrap());
    let format = OutputFormat::from(matches.get_one::<String>("format").unwrap().as_str());
    let output_file = matches.get_one::<String>("output");
    let quiet = matches.get_flag("quiet");
    let skip_tests = matches.get_flag("skip-tests");

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
    let findings = match scanner.scan_directory(&scan_path) {
        Ok(findings) => {
            if let Some(pb) = &progress {
                pb.finish_with_message(format!(
                    "{} Found {} potential secrets",
                    "✓".green().bold(),
                    findings.len()
                ));
            }
            findings
        }
        Err(e) => {
            if let Some(pb) = &progress {
                pb.finish_with_message(format!("{} Scan failed", "✗".red().bold()));
            }
            eprintln!("{} Scan failed: {}", "Error:".red().bold(), e);
            process::exit(1);
        }
    };

    // Format output
    let output_content = match format {
        OutputFormat::Json => match format_as_json(&findings) {
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
