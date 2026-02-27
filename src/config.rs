//! Configuration for the circuit breaker.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the HMAC-protected circuit breaker.
///
/// Build with [`CircuitBreakerConfig::builder()`] or construct directly.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Path to the JSON state file written by the health-check producer.
    pub state_file: PathBuf,

    /// HMAC secret used to verify (and optionally sign) the state file.
    ///
    /// In production this should come from an environment variable or secrets
    /// manager — for example the database password, so the secret is only
    /// available to authorised processes.
    pub secret: String,

    /// How often the background task reloads the state file from disk.
    ///
    /// Default: 60 seconds.
    pub reload_interval: Duration,

    /// Number of consecutive failures required to trip a circuit.
    ///
    /// Default: 3.
    pub threshold: u32,

    /// HTTP request header that allows a caller to bypass a tripped circuit.
    ///
    /// The canonical use-case is the health-check cron itself: without a bypass
    /// the cron could never re-probe a tripped service to confirm recovery,
    /// creating a deadlock where tripped services can never be reset.
    ///
    /// Set to `None` to disable the bypass mechanism entirely.
    ///
    /// Default: `Some("x-health-check-bypass")`.
    pub bypass_header: Option<String>,

    /// How long after the **runtime** circuit trips before one probe request is
    /// allowed through to test recovery (half-open probing).
    ///
    /// After this duration the middleware lets exactly one request through.
    /// * If the probe succeeds → circuit closes.
    /// * If the probe fails → circuit stays tripped and the cooldown restarts.
    ///
    /// Default: 30 seconds.
    pub half_open_timeout: Duration,

    /// Consecutive successful probes in the half-open state required to close
    /// the runtime circuit.
    ///
    /// Default: 1 (a single success closes the circuit immediately).
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from("circuit_breaker.json"),
            secret: "circuit-breaker-integrity".to_string(),
            reload_interval: Duration::from_secs(60),
            threshold: 3,
            bypass_header: Some("x-health-check-bypass".to_string()),
            half_open_timeout: Duration::from_secs(30),
            success_threshold: 1,
        }
    }
}

impl CircuitBreakerConfig {
    /// Start building a config with sensible defaults.
    pub fn builder() -> CircuitBreakerConfigBuilder {
        CircuitBreakerConfigBuilder::default()
    }
}

/// Builder for [`CircuitBreakerConfig`].
#[derive(Default)]
pub struct CircuitBreakerConfigBuilder {
    inner: CircuitBreakerConfig,
}

impl CircuitBreakerConfigBuilder {
    /// Path to the on-disk state file.
    pub fn state_file(mut self, path: PathBuf) -> Self {
        self.inner.state_file = path;
        self
    }

    /// HMAC secret. Prefer sourcing this from an env var at runtime.
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.inner.secret = secret.into();
        self
    }

    /// Background reload interval.
    pub fn reload_interval(mut self, interval: Duration) -> Self {
        self.inner.reload_interval = interval;
        self
    }

    /// Consecutive failure threshold before a circuit trips.
    pub fn threshold(mut self, threshold: u32) -> Self {
        self.inner.threshold = threshold;
        self
    }

    /// Override the bypass header name.  Pass `None` to disable bypass.
    pub fn bypass_header(mut self, header: Option<impl Into<String>>) -> Self {
        self.inner.bypass_header = header.map(Into::into);
        self
    }

    /// Half-open cooldown duration after the runtime circuit trips.
    pub fn half_open_timeout(mut self, timeout: Duration) -> Self {
        self.inner.half_open_timeout = timeout;
        self
    }

    /// Consecutive successful probes in half-open state needed to close the circuit.
    pub fn success_threshold(mut self, threshold: u32) -> Self {
        self.inner.success_threshold = threshold;
        self
    }

    /// Consume the builder and return the validated config.
    pub fn build(self) -> CircuitBreakerConfig {
        self.inner
    }
}
