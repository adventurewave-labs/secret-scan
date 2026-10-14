use std::process::Command;

/// `--version` must report the real package version. The 0.2.4 tarball shipped
/// a binary that claimed 0.2.1 because the string was hardcoded; keep this
/// pinned so it cannot regress.
#[test]
fn version_reports_package_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_secretscan"))
        .arg("--version")
        .output()
        .expect("failed to run secretscan --version");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "--version exited with an error");
    assert_eq!(
        stdout.trim(),
        concat!("secretscan ", env!("CARGO_PKG_VERSION")),
        "--version must equal the Cargo.toml package version"
    );
}
