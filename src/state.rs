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

// ── In-process runtime state (never persisted) ───────────────────────────────

/// Status of the in-process runtime circuit.
///
/// Complements the file-based [`CircuitStatus`] by tracking failures that
/// occur within the **current process lifetime** — no external producer needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeStatus {
    /// No in-process failures recorded; requests pass through normally.
    #[default]
    Closed,
    /// In-process failure threshold reached; requests are rejected.
    ///
    /// After [`CircuitBreakerConfig::half_open_timeout`] elapses, exactly one
    /// probe request is allowed through.  A successful probe closes the circuit;
    /// a failed probe resets the cooldown and stays tripped.
    Tripped,
    /// Cooldown has elapsed; one probe is in flight.
    HalfOpen,
}

/// In-process per-service circuit state owned by the middleware.
///
/// Never written to disk.  Complements the HMAC-verified file-based state by
/// detecting failures within the current process (e.g. while the health-check
/// cron is between runs).
#[derive(Debug, Default)]
pub struct RuntimeServiceState {
    /// Current runtime circuit status.
    pub status: RuntimeStatus,
    /// Consecutive 5xx responses since the last reset.
    pub consecutive_failures: u32,
    /// Consecutive successful probes while [`HalfOpen`](RuntimeStatus::HalfOpen).
    pub consecutive_successes: u32,
    /// Monotonic timestamp of when the runtime circuit was tripped.
    pub tripped_at: Option<std::time::Instant>,
    /// `true` while a half-open probe is in flight.
    pub probe_in_flight: bool,
    /// When the current (or most recent) probe was started; used to detect
    /// dropped connections so the probe slot is eventually freed.
    pub probe_started_at: Option<std::time::Instant>,
}
