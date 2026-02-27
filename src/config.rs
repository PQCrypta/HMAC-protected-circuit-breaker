//! Configuration for the circuit breaker.

use std::path::PathBuf;
use std::time::Duration;

/// The built-in placeholder secret shipped for convenience in examples and tests.
/// Production builds must supply a different secret; [`CircuitBreakerConfigBuilder::build`]
/// emits a `tracing::warn!` if this value is still in use.
pub const DEFAULT_SECRET: &str = "circuit-breaker-integrity";

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

    /// Required value for the bypass header.
    ///
    /// When `Some`, the bypass header must carry exactly this value (compared
    /// in constant time) for the request to be allowed through.  When `None`
    /// the header is checked for *presence only* — any value is accepted.
    ///
    /// Strongly recommended in production: set this to a secret known only to
    /// the health-check process so that an attacker who learns the header *name*
    /// cannot bypass circuit protection.
    ///
    /// Default: `None` (presence-only, backward-compatible).
    pub bypass_header_secret: Option<String>,

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

    /// Reject state files that have no `integrity_hash` field (legacy files).
    ///
    /// When `false` (the default), files without an `integrity_hash` are
    /// accepted for backward compatibility and a `WARN` is emitted.
    ///
    /// When `true`, unsigned files are treated as tampered: all circuit state
    /// is cleared (fail-open) and a `WARN` is emitted.  Enable this once all
    /// producers have been upgraded to write signed files.
    ///
    /// Default: `false`.
    pub strict_hmac: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from("circuit_breaker.json"),
            secret: DEFAULT_SECRET.to_string(),
            reload_interval: Duration::from_secs(60),
            threshold: 3,
            bypass_header: Some("x-health-check-bypass".to_string()),
            bypass_header_secret: None,
            half_open_timeout: Duration::from_secs(30),
            success_threshold: 1,
            strict_hmac: false,
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

    /// Set a required secret value for the bypass header.
    ///
    /// When set, requests must present the bypass header with exactly this value
    /// (constant-time compared) to be allowed through a tripped circuit.
    /// Strongly recommended in production to prevent bypass via header-name disclosure.
    pub fn bypass_header_secret(mut self, secret: Option<impl Into<String>>) -> Self {
        self.inner.bypass_header_secret = secret.map(Into::into);
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

    /// Reject state files that have no `integrity_hash` (legacy unsigned files).
    ///
    /// Enable once all producers write HMAC-signed files.
    pub fn strict_hmac(mut self, strict: bool) -> Self {
        self.inner.strict_hmac = strict;
        self
    }

    /// Consume the builder and return the validated config.
    ///
    /// # Panics (never) / Warnings
    ///
    /// Emits a `tracing::warn!` if the HMAC secret is still the built-in
    /// default (`"circuit-breaker-integrity"`).  Override it with
    /// `.secret(std::env::var("HMAC_SECRET").expect("HMAC_SECRET must be set"))`
    /// before deploying to production.
    pub fn build(self) -> CircuitBreakerConfig {
        if self.inner.secret == DEFAULT_SECRET {
            tracing::warn!(
                "hmac-circuit-breaker: HMAC secret is the built-in default \
                 (\"circuit-breaker-integrity\"). Override it with a unique secret \
                 before deploying to production — e.g. \
                 `.secret(std::env::var(\"HMAC_SECRET\").expect(\"HMAC_SECRET must be set\"))`"
            );
        }
        self.inner
    }
}
