//! State file writer — the "producer" side of the circuit breaker.
//!
//! Health-check processes call [`write_state`] after probing services. The function
//! computes the HMAC, serialises the state to a temp file, then atomically renames
//! it into place so readers never see a partial write.

use crate::{
    integrity::compute_hmac,
    state::{AlgorithmCircuitState, CircuitBreakerFile, CircuitStatus},
};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur while writing the state file.
#[derive(Debug, Error)]
pub enum WriteError {
    #[error("Failed to serialise state: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("Failed to write temp file: {0}")]
    Io(#[from] std::io::Error),
}

/// Input for a single service's health observation.
pub struct ServiceObservation {
    /// Service name (used as the map key).
    pub name: String,
    /// Whether the most recent health check passed.
    pub passed: bool,
    /// Human-readable error from the most recent failure, if any.
    pub error: Option<String>,
}

/// Compute new circuit states from health observations and a previous state snapshot,
/// then write an HMAC-signed JSON file atomically.
///
/// # Arguments
///
/// * `path` – destination file path (parent directory must exist and be writable).
/// * `observations` – health-check results for each service.
/// * `previous` – the existing circuit states (used to accumulate consecutive failures).
/// * `threshold` – number of consecutive failures before a circuit trips.
/// * `secret` – HMAC signing secret (same value used by the middleware/loader).
///
/// # Atomic write
///
/// The function writes to `{path}.tmp` and then renames it to `path`.  On POSIX
/// systems this rename is atomic, so readers will never observe a partial write.
///
/// # Example
///
/// ```rust,no_run
/// use hmac_circuit_breaker::writer::{write_state, ServiceObservation};
/// use std::collections::BTreeMap;
/// use std::path::Path;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let observations = vec![
///     ServiceObservation { name: "payments".to_string(), passed: true, error: None },
///     ServiceObservation { name: "auth".to_string(), passed: false,
///                          error: Some("connection refused".to_string()) },
/// ];
///
/// write_state(
///     Path::new("/var/run/myapp/circuit_breaker.json"),
///     &observations,
///     &BTreeMap::new(),   // no prior state on first run
///     3,
///     "my-hmac-secret",
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn write_state(
    path: &Path,
    observations: &[ServiceObservation],
    previous: &BTreeMap<String, AlgorithmCircuitState>,
    threshold: u32,
    secret: &str,
) -> Result<(), WriteError> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut new_algorithms: BTreeMap<String, AlgorithmCircuitState> = BTreeMap::new();

    for obs in observations {
        let prev_failures = previous
            .get(&obs.name)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0);

        let state = if obs.passed {
            AlgorithmCircuitState {
                status: CircuitStatus::Closed,
                consecutive_failures: 0,
                since: None,
                reason: None,
            }
        } else {
            let new_failures = prev_failures + 1;
            if new_failures >= threshold {
                let trip_since = previous
                    .get(&obs.name)
                    .and_then(|s| s.since.clone())
                    .unwrap_or_else(|| now.clone());
                AlgorithmCircuitState {
                    status: CircuitStatus::Tripped,
                    consecutive_failures: new_failures,
                    since: Some(trip_since),
                    reason: obs.error.clone(),
                }
            } else {
                AlgorithmCircuitState {
                    status: CircuitStatus::Open,
                    consecutive_failures: new_failures,
                    since: None,
                    reason: obs.error.clone(),
                }
            }
        };

        new_algorithms.insert(obs.name.clone(), state);
    }

    // Compute HMAC over the compact JSON of the algorithms map.
    //
    // Round-trip through `serde_json::Value` before serialising. serde_json::Value
    // uses BTreeMap at every level, so all object keys (including struct fields) are
    // sorted alphabetically. The verifier does the same thing when it parses the file
    // as a Value and re-serialises the `algorithms` block, ensuring both sides produce
    // the identical byte string for the HMAC input.
    let algorithms_value: serde_json::Value = serde_json::to_value(&new_algorithms)?;
    let algorithms_json = serde_json::to_string(&algorithms_value)?;
    let integrity_hash = compute_hmac(&algorithms_json, secret);

    let file = CircuitBreakerFile {
        updated_at: now,
        threshold,
        integrity_hash: Some(integrity_hash),
        algorithms: new_algorithms,
    };

    let pretty = serde_json::to_string_pretty(&file)?;

    // Write to a temp file first, then atomically rename.
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &pretty)?;
    std::fs::rename(&tmp_path, path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_read_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cb.json");

        let obs = vec![
            ServiceObservation {
                name: "svc-a".to_string(),
                passed: true,
                error: None,
            },
            ServiceObservation {
                name: "svc-b".to_string(),
                passed: false,
                error: Some("timeout".to_string()),
            },
        ];

        write_state(&path, &obs, &BTreeMap::new(), 3, "test-secret").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: CircuitBreakerFile = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.algorithms["svc-a"].status, CircuitStatus::Closed);
        assert_eq!(
            parsed.algorithms["svc-b"].status,
            CircuitStatus::Open // 1 failure < threshold of 3
        );
        assert!(parsed.integrity_hash.is_some());
    }

    #[test]
    fn trip_after_threshold() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cb.json");

        // Simulate two previous failures
        let mut prev = BTreeMap::new();
        prev.insert(
            "svc-c".to_string(),
            AlgorithmCircuitState {
                status: CircuitStatus::Open,
                consecutive_failures: 2,
                since: None,
                reason: None,
            },
        );

        let obs = vec![ServiceObservation {
            name: "svc-c".to_string(),
            passed: false,
            error: Some("error".to_string()),
        }];

        write_state(&path, &obs, &prev, 3, "test-secret").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: CircuitBreakerFile = serde_json::from_str(&content).unwrap();

        // 2 prev + 1 new = 3 = threshold → Tripped
        assert_eq!(parsed.algorithms["svc-c"].status, CircuitStatus::Tripped);
        assert_eq!(parsed.algorithms["svc-c"].consecutive_failures, 3);
        assert!(parsed.algorithms["svc-c"].since.is_some());
    }
}
