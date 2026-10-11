//! Structural validation that needs no network access.
//!
//! Some token formats can be checked beyond their regex: the text either
//! decodes to what the format requires or it does not. A match that fails is
//! not a credential, so it is dropped.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Whether `text` has the structure of a JSON Web Token: three dot-separated
/// base64url segments, of which the first decodes to a JSON object with a
/// string `alg` and the second decodes to a JSON object.
///
/// The regex for JWTs matches any `eyJ….….…` string. Base64 of `{"` always
/// begins `eyJ`, so that also matches arbitrary encoded JSON fragments and
/// truncated tokens; decoding separates real tokens from lookalikes. The
/// signature is not verified — that would need the key — so this says the
/// token is well-formed, not that it is live.
pub fn is_well_formed_jwt(text: &str) -> bool {
    let mut segments = text.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (segments.next(), segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    if signature.is_empty() {
        return false;
    }
    let decode_object = |segment: &str| -> Option<serde_json::Map<String, serde_json::Value>> {
        let bytes = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()?;
        match serde_json::from_slice(&bytes).ok()? {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        }
    };
    let Some(header) = decode_object(header) else {
        return false;
    };
    header.get("alg").is_some_and(|alg| alg.is_string()) && decode_object(payload).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(json: &str) -> String {
        URL_SAFE_NO_PAD.encode(json)
    }

    fn jwt(header: &str, payload: &str) -> String {
        format!("{}.{}.{}", segment(header), segment(payload), "c2lnbmF0dXJlLWJ5dGVz")
    }

    #[test]
    fn well_formed_tokens_are_accepted() {
        assert!(is_well_formed_jwt(&jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"1234567890","iat":1516239022}"#
        )));
        assert!(is_well_formed_jwt(&jwt(r#"{"alg":"RS256","kid":"k1"}"#, r#"{}"#)));
        // Unsecured JWTs still declare an algorithm.
        assert!(is_well_formed_jwt(&jwt(r#"{"alg":"none"}"#, r#"{"a":1}"#)));
    }

    #[test]
    fn lookalikes_are_rejected() {
        let good_header = segment(r#"{"alg":"HS256"}"#);
        let good_payload = segment(r#"{"sub":"x"}"#);
        for text in [
            // header is JSON but has no alg
            jwt(r#"{"typ":"JWT"}"#, r#"{"sub":"x"}"#),
            // alg is not a string
            jwt(r#"{"alg":256}"#, r#"{"sub":"x"}"#),
            // payload is not an object
            jwt(r#"{"alg":"HS256"}"#, r#"["a","b"]"#),
            // payload is not JSON
            format!("{good_header}.{}.c2ln", URL_SAFE_NO_PAD.encode("plain text here")),
            // header is truncated JSON
            format!("{}.{good_payload}.c2ln", URL_SAFE_NO_PAD.encode(r#"{"alg":"HS25"#)),
            // not base64url at all
            format!("eyJ!!!!!!!!!!.{good_payload}.c2ln"),
            // wrong number of segments
            format!("{good_header}.{good_payload}"),
            format!("{good_header}.{good_payload}.c2ln.extra"),
            // empty signature
            format!("{good_header}.{good_payload}."),
            String::new(),
        ] {
            assert!(!is_well_formed_jwt(&text), "accepted {text:?}");
        }
    }
}
