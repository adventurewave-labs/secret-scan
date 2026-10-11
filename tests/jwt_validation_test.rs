//! JWT findings are structurally validated: lookalikes are not reported.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use secretscan::{ContextFilter, Finding, Scanner};
use std::fs;
use tempfile::TempDir;

fn scan(content: &str) -> Vec<Finding> {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("settings.txt"), content).unwrap();
    let mut scanner = Scanner::new().unwrap();
    scanner.set_context_filter(ContextFilter::none());
    scanner.scan_directory(dir.path()).unwrap()
}

fn jwt_findings(content: &str) -> Vec<String> {
    scan(content)
        .into_iter()
        .filter(|f| f.pattern_name == "JWT Token")
        .map(|f| f.matched_text)
        .collect()
}

fn token(header: &str, payload: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload),
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
}

#[test]
fn a_real_shaped_jwt_is_reported() {
    let jwt = token(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"1234567890","admin":true}"#);
    assert_eq!(jwt_findings(&format!("session = \"{jwt}\"\n")), vec![jwt]);
}

#[test]
fn strings_that_only_look_like_jwts_are_not_reported() {
    // Each starts with "eyJ" and has three long dot-separated segments, so
    // the regex matches all of them.
    let no_alg = token(r#"{"typ":"JWT","kid":"abc"}"#, r#"{"sub":"1234567890"}"#);
    let payload_not_json = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode("just some text, not json"),
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let garbage = "eyJabcdefghijklmnop.qrstuvwxyzABCDEF.GHIJKLMNOPQRSTUV".to_string();

    for lookalike in [no_alg, payload_not_json, garbage] {
        let found = jwt_findings(&format!("value = \"{lookalike}\"\n"));
        assert!(found.is_empty(), "reported a non-JWT: {found:?}");
    }
}
