//! # hmac-circuit-breaker
//!
//! An HMAC-protected circuit breaker with **fail-open semantics** for service resilience.
//!
//! ## The Problem
//!
//! Standard circuit breakers that persist failure state to disk introduce an
//! attack surface: an adversary with write access to the state file can trip every
//! circuit—causing a denial-of-service without touching the services themselves.
//!
//! ## The Solution
//!
//! This crate computes **HMAC-SHA256** over the circuit state and embeds it in the
//! state file. On every reload the HMAC is verified before any state is trusted.
//!
//! ### Why Fail-Open on HMAC Mismatch?
//!
//! When the HMAC doesn't match, the crate **clears** all circuit state (fail-open)
//! rather than blocking all traffic (fail-closed). This is a deliberate security
//! decision:
//!
//! | On-tamper response | What the attacker achieves |
//! |---|---|
//! | **Fail-closed** (block all) | Full self-DoS — attacker writes bad MAC, every circuit trips |
//! | **Fail-open** (clear all) | Temporary removal of protection — worst case is the baseline behaviour *without* a circuit breaker |
//!
//! Fail-open means an attacker can at most *remove* circuit protection for one reload
//! cycle, not weaponise it. The integrity violation is logged as a warning so operators
//! are alerted immediately.
//!
//! ## State Machines
//!
//! ### File-based state (written by external producer)
//!
//! ```text
//!                        pass
//! ┌──────────┐  fail   ┌──────┐  fail×N  ┌─────────┐
//! │  Closed  │────────►│ Open │─────────►│ Tripped │
//! │ (normal) │         │      │          │(blocked)│
//! └──────────┘         └──┬───┘          └────┬────┘
//!      ▲                  │ pass               │ pass (next health cycle)
//!      └──────────────────┴────────────────────┘
//! ```
//!
//! ### In-process runtime state (managed by the axum middleware)
//!
//! ```text
//!                 fail×N           cooldown elapsed
//! ┌──────────┐  ────────►  ┌─────────┐  ──────────►  ┌──────────┐
//! │  Closed  │             │ Tripped │               │ HalfOpen │
//! │ (normal) │  ◄────────  │(blocked)│  ◄──────────  │ (1 probe)│
//! └──────────┘   recover   └─────────┘  probe fail   └────┬─────┘
//!                                                         │ probe ok
//!      ▲──────────────────────────────────────────────────┘
//! ```
//!
//! * **Closed** – no in-process failures; requests pass through.
//! * **Tripped** – `threshold` consecutive 5xx responses from the inner service.
//!   Requests are rejected with 503 until the cooldown elapses.
//! * **HalfOpen** – one probe request is allowed through.  Success → Closed;
//!   failure → Tripped (cooldown restarts).
//!
//! ## Architecture
//!
//! Circuit state is tracked in two complementary layers:
//!
//! 1. **On disk** — a JSON file written by an external producer (health-check
//!    cron, monitoring daemon) with an embedded HMAC-SHA256 tag.
//!    Verified on every reload; mismatch → fail-open.
//! 2. **In memory** — two `Arc<RwLock<HashMap>>` maps:
//!    * `SharedState` — reloaded from disk every *N* seconds; reflects the
//!      external producer's view of each service.
//!    * `RuntimeState` — managed entirely by the axum middleware; trips
//!      immediately when the **current process** observes consecutive failures,
//!      then auto-recovers via half-open probing without waiting for the next
//!      health-check cycle.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = CircuitBreakerConfig::builder()
//!         .state_file(PathBuf::from("/var/run/myapp/circuit_breaker.json"))
//!         .secret("my-hmac-secret")
//!         .threshold(3)
//!         .reload_interval(Duration::from_secs(60))
//!         .build();
//!
//!     let handle = CircuitBreakerHandle::new(config);
//!     handle.spawn_reload(); // background reload every 60 s
//!
//!     // Check before dispatching work
//!     if handle.is_tripped("payment-service").await {
//!         eprintln!("payment-service is currently unavailable");
//!     }
//! }
//! ```
//!
//! ## Features
//!
//! | Feature | Default | Description |
//! |---|---|---|
//! | `reload` | yes | Enables `CircuitBreakerHandle::spawn_reload()` (requires tokio) |
//! | `axum` | no | Enables `circuit_breaker_layer()` axum middleware |

pub mod config;
pub mod integrity;
pub mod loader;
pub mod state;
pub mod writer;

#[cfg(feature = "axum")]
pub mod middleware;

pub use config::{CircuitBreakerConfig, CircuitBreakerConfigBuilder};
pub use state::{AlgorithmCircuitState, CircuitStatus, RuntimeServiceState, RuntimeStatus};
pub use writer::write_state;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared in-memory file-based circuit state, cheaply cloneable.
pub type SharedState = Arc<RwLock<HashMap<String, AlgorithmCircuitState>>>;

/// Shared in-process runtime circuit state, cheaply cloneable.
///
/// Managed entirely by the axum middleware — never persisted to disk.
pub type RuntimeState = Arc<RwLock<HashMap<String, RuntimeServiceState>>>;

/// High-level handle that owns the shared state and the config.
///
/// Clone it freely — all clones share the same underlying `Arc`.
#[derive(Clone)]
pub struct CircuitBreakerHandle {
    pub(crate) state: SharedState,
    pub(crate) runtime: RuntimeState,
    pub(crate) config: Arc<CircuitBreakerConfig>,
}

impl CircuitBreakerHandle {
    /// Create a new handle. The initial in-memory state is empty (all circuits closed).
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            runtime: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    /// Load state from the configured file once, verifying HMAC integrity.
    ///
    /// On HMAC mismatch the in-memory state is cleared (fail-open) and a `tracing::warn`
    /// is emitted.  This is safe to call at startup and before spawning the reload task.
    pub async fn load(&self) {
        loader::load_into(&self.state, &self.config).await;
    }

    /// Spawn a background tokio task that calls [`load`](Self::load) every
    /// `config.reload_interval`.
    ///
    /// Returns the [`tokio::task::JoinHandle`] so callers can await or abort
    /// the reload task on shutdown.  The handle can be safely dropped — the
    /// task will continue running until the tokio runtime shuts down.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
    /// # #[tokio::main]
    /// # async fn main() {
    /// let handle = CircuitBreakerHandle::new(CircuitBreakerConfig::default());
    /// let reload_task = handle.spawn_reload();
    ///
    /// // ... run application ...
    ///
    /// // Graceful shutdown: stop the reload task.
    /// reload_task.abort();
    /// # }
    /// ```
    #[cfg(feature = "reload")]
    pub fn spawn_reload(&self) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        let config = self.config.clone();
        tokio::spawn(async move {
            loop {
                loader::load_into(&state, &config).await;
                tokio::time::sleep(config.reload_interval).await;
            }
        })
    }

    /// Returns `true` if the named service has been tripped (consecutive failures ≥
    /// threshold).  Returns `false` for unknown services (fail-open default).
    pub async fn is_tripped(&self, service: &str) -> bool {
        let guard = self.state.read().await;
        guard
            .get(service)
            .map(|s| s.status == CircuitStatus::Tripped)
            .unwrap_or(false)
    }

    /// Returns the full circuit state for a service, or `None` if not tracked.
    pub async fn get(&self, service: &str) -> Option<AlgorithmCircuitState> {
        let guard = self.state.read().await;
        guard.get(service).cloned()
    }

    /// Returns a snapshot of the complete in-memory state.
    pub async fn snapshot(&self) -> HashMap<String, AlgorithmCircuitState> {
        self.state.read().await.clone()
    }

    /// Access the raw file-based shared state (e.g. to pass to the axum middleware).
    pub fn shared_state(&self) -> SharedState {
        self.state.clone()
    }

    /// Access the in-process runtime state (e.g. to pass to the axum middleware).
    ///
    /// Pass this alongside [`shared_state`](Self::shared_state) to
    /// [`circuit_breaker_layer`](crate::middleware::circuit_breaker_layer) to
    /// enable in-process failure detection and half-open probing.
    pub fn runtime_state(&self) -> RuntimeState {
        self.runtime.clone()
    }
}
