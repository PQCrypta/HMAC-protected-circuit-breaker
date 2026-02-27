//! Circuit state types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The three states a circuit can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitStatus {
    /// Normal operation — requests pass through.
    Closed,
    /// One or more failures observed but below the trip threshold.
    Open,
    /// Consecutive failures reached the threshold — requests are rejected.
    Tripped,
}

impl std::fmt::Display for CircuitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitStatus::Closed => write!(f, "closed"),
            CircuitStatus::Open => write!(f, "open"),
            CircuitStatus::Tripped => write!(f, "tripped"),
        }
    }
}

/// Per-service circuit breaker state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmCircuitState {
    /// Current circuit status.
    pub status: CircuitStatus,

    /// Number of consecutive failures observed at the time this state was written.
    pub consecutive_failures: u32,

    /// RFC 3339 timestamp of when the circuit was first tripped (present only when
    /// `status == Tripped`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Human-readable reason for the trip (e.g. the last error message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AlgorithmCircuitState {
    /// Construct a closed (healthy) state.
    pub fn closed() -> Self {
        Self {
            status: CircuitStatus::Closed,
            consecutive_failures: 0,
            since: None,
            reason: None,
        }
    }
}

/// The on-disk JSON structure written by the health-check producer and read by this crate.
#[derive(Debug, Serialize, Deserialize)]
pub struct CircuitBreakerFile {
    /// RFC 3339 timestamp of the last write.
    pub updated_at: String,
    /// Failure count that causes a circuit to trip.
    pub threshold: u32,
    /// HMAC-SHA256 of the compact JSON serialisation of the `algorithms` map.
    /// Absent in legacy files (treated as valid for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_hash: Option<String>,
    /// Per-service circuit states. Uses `BTreeMap` to guarantee sorted key order,
    /// which is required for deterministic HMAC computation.
    pub algorithms: BTreeMap<String, AlgorithmCircuitState>,
}
