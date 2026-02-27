//! HMAC-SHA256 integrity helpers.
//!
//! The HMAC is computed over the **compact JSON serialisation of the `algorithms` map**.
//! Because [`serde_json::Map`] uses `BTreeMap` internally, keys are always sorted
//! alphabetically, guaranteeing byte-for-byte identical serialisation on every writer
//! and reader regardless of insertion order.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of `algorithms_json` using `secret`, returned as a lowercase
/// hex string.
///
/// # Example
///
/// ```rust
/// use hmac_circuit_breaker::integrity::compute_hmac;
///
/// let mac = compute_hmac(r#"{"svc":{"status":"closed","consecutive_failures":0}}"#, "s3cr3t");
/// assert_eq!(mac.len(), 64); // 32 bytes → 64 hex chars
/// ```
pub fn compute_hmac(algorithms_json: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(algorithms_json.as_bytes());
    let result = mac.finalize().into_bytes();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify that `expected_hex` matches the HMAC of the `algorithms` block inside
/// `raw_json`.
///
/// Returns:
/// * `true`  – HMAC valid, file not tampered.
/// * `false` – HMAC invalid or JSON cannot be parsed (treat as tampered).
///
/// Note: if `raw_json` contains no `algorithms` key this returns `false`.
pub fn verify_file_hmac(raw_json: &str, expected_hex: &str, secret: &str) -> bool {
    let root: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let algorithms = match root.get("algorithms") {
        Some(a) => a,
        None => return false,
    };

    // Re-serialise through serde_json to get the same sorted-key compact form that
    // the writer used.
    let algorithms_json = match serde_json::to_string(algorithms) {
        Ok(j) => j,
        Err(_) => return false,
    };

    let computed = compute_hmac(&algorithms_json, secret);

    // Constant-time comparison to resist timing side-channels.
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

/// Constant-time byte-slice equality.  Returns `true` iff `a == b`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hmac() {
        let json = r#"{"svc":{"consecutive_failures":0,"status":"closed"}}"#;
        let secret = "test-secret";
        let mac = compute_hmac(json, secret);
        assert!(verify_file_hmac(
            &format!(r#"{{"algorithms":{json},"integrity_hash":"{mac}"}}"#),
            &mac,
            secret
        ));
    }

    #[test]
    fn wrong_secret_fails() {
        let json = r#"{"svc":{"consecutive_failures":0,"status":"closed"}}"#;
        let mac = compute_hmac(json, "correct-secret");
        assert!(!verify_file_hmac(
            &format!(r#"{{"algorithms":{json},"integrity_hash":"{mac}"}}"#),
            &mac,
            "wrong-secret"
        ));
    }

    #[test]
    fn tampered_body_fails() {
        let original = r#"{"svc":{"consecutive_failures":0,"status":"closed"}}"#;
        let tampered = r#"{"svc":{"consecutive_failures":0,"status":"tripped"}}"#;
        let mac = compute_hmac(original, "secret");
        assert!(!verify_file_hmac(
            &format!(r#"{{"algorithms":{tampered},"integrity_hash":"{mac}"}}"#),
            &mac,
            "secret"
        ));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }
}
