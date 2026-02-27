//! Async file loader: reads the JSON state file and updates the shared in-memory state.
//!
//! **Fail-open semantics**: if the HMAC integrity check fails, all circuits are cleared
//! (not blocked) and the failure is logged at `WARN` level.

use crate::{config::CircuitBreakerConfig, state::CircuitBreakerFile, SharedState};
use std::sync::Arc;
use tracing::{debug, warn};

/// Load the circuit breaker state file into `state`, respecting HMAC integrity.
///
/// # HMAC behaviour
///
/// | `integrity_hash` in file | `strict_hmac` | Result |
/// |---|---|---|
/// | Present and valid | any | State is loaded normally |
/// | Present but **invalid** | any | State is **cleared** (fail-open); `WARN` emitted |
/// | Absent (legacy file) | `false` | State is loaded; `WARN` emitted |
/// | Absent (legacy file) | `true` | State is **cleared** (fail-open); `WARN` emitted |
///
/// File-not-found is silently ignored (first-run case).  All other I/O errors are
/// logged at `WARN`.
pub async fn load_into(state: &SharedState, config: &Arc<CircuitBreakerConfig>) {
    let content = match tokio::fs::read_to_string(&config.state_file).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!("Circuit breaker state file not found — starting with empty state");
            return;
        }
        Err(e) => {
            warn!("Failed to read circuit breaker state file: {e}");
            return;
        }
    };

    let cb_file: CircuitBreakerFile = match serde_json::from_str(&content) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to parse circuit breaker state file: {e}");
            return;
        }
    };

    let hmac_ok = match &cb_file.integrity_hash {
        Some(expected) => crate::integrity::verify_file_hmac(&content, expected, &config.secret),
        None => {
            // Legacy file without HMAC.
            if config.strict_hmac {
                warn!(
                    "Circuit breaker state file has no integrity_hash and strict_hmac is enabled \
                     — clearing all circuits (fail-open) to prevent accepting an unsigned file."
                );
                false
            } else {
                warn!(
                    "Circuit breaker state file has no integrity_hash; accepting without \
                     verification (legacy mode). Enable strict_hmac to reject unsigned files."
                );
                true
            }
        }
    };

    if hmac_ok {
        let mut guard = state.write().await;
        *guard = cb_file.algorithms.into_iter().collect();
        debug!(
            "Circuit breaker state loaded: {} services tracked",
            guard.len()
        );
    } else {
        warn!(
            "Circuit breaker HMAC integrity check FAILED — state file may be tampered. \
             Clearing all circuits (fail-open) to prevent self-DoS."
        );
        state.write().await.clear();
    }
}
