//! Axum/Tower middleware that enforces circuit breaker state per request.
//!
//! Enable with the `axum` Cargo feature.
//!
//! ## Two layers of protection
//!
//! The middleware checks two independent state maps on every request:
//!
//! 1. **File-based state** (`SharedState`) — written by an external health-check
//!    producer and reloaded from disk periodically.  Reflects the producer's view
//!    of each service.
//!
//! 2. **In-process runtime state** (`RuntimeState`) — managed entirely by this
//!    middleware.  Trips immediately when the **current process** observes
//!    `threshold` consecutive 5xx responses, without waiting for the next
//!    health-check cycle.
//!
//! If either layer says a service is tripped, the request is rejected with
//! `503 Service Unavailable`.
//!
//! ## Half-open probing
//!
//! After the in-process circuit trips, it enters a cooldown.  Once
//! `half_open_timeout` elapses, exactly one probe request is allowed through:
//!
//! * **Probe succeeds** → circuit closes; normal traffic resumes.
//! * **Probe fails** → circuit stays tripped; cooldown restarts.
//!
//! If a probe request is dropped mid-flight (client disconnect), the probe
//! slot is automatically freed after `half_open_timeout` elapses so the next
//! request can claim it.
//!
//! ## Bypass header
//!
//! Requests containing the configured bypass header always pass through, even
//! to tripped services.  This lets the health-check cron re-probe a tripped
//! service without triggering a deadlock.
//!
//! ## Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::post};
//! use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
//! use hmac_circuit_breaker::middleware::circuit_breaker_layer;
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! async fn encrypt() -> &'static str { "ok" }
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = CircuitBreakerConfig::builder()
//!         .state_file(PathBuf::from("/var/run/myapp/circuit_breaker.json"))
//!         .secret(std::env::var("HMAC_SECRET").unwrap_or_default())
//!         .threshold(3)
//!         .half_open_timeout(Duration::from_secs(30))
//!         .build();
//!
//!     let handle = CircuitBreakerHandle::new(config.clone());
//!     handle.load().await;
//!     handle.spawn_reload();
//!
//!     let extractor = |path: &str| -> Option<String> {
//!         let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
//!         if segs.first() == Some(&"encrypt") {
//!             segs.get(1).map(|s| s.to_string())
//!         } else {
//!             None
//!         }
//!     };
//!
//!     let app = Router::new()
//!         .route("/encrypt/:service", post(encrypt))
//!         .layer(circuit_breaker_layer(
//!             handle.shared_state(),
//!             handle.runtime_state(),
//!             config,
//!             extractor,
//!         ));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```

use crate::{
    config::CircuitBreakerConfig,
    state::{CircuitStatus, RuntimeStatus},
    RuntimeState, SharedState,
};
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{info, warn};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

// ── Layer ────────────────────────────────────────────────────────────────────

/// Tower [`Layer`] that wraps an inner service with circuit-breaker enforcement.
///
/// Constructed via [`circuit_breaker_layer`].
#[derive(Clone)]
pub struct CircuitBreakerLayer<F> {
    state: SharedState,
    runtime: RuntimeState,
    config: Arc<CircuitBreakerConfig>,
    extractor: Arc<F>,
}

impl<F, S> Layer<S> for CircuitBreakerLayer<F>
where
    F: Clone,
{
    type Service = CircuitBreakerService<F, S>;

    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreakerService {
            inner,
            state: self.state.clone(),
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            extractor: self.extractor.clone(),
        }
    }
}

// ── Service ──────────────────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`CircuitBreakerLayer`].
#[derive(Clone)]
pub struct CircuitBreakerService<F, S> {
    inner: S,
    state: SharedState,
    runtime: RuntimeState,
    config: Arc<CircuitBreakerConfig>,
    extractor: Arc<F>,
}

impl<F, S> Service<axum::http::Request<Body>> for CircuitBreakerService<F, S>
where
    F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    S: Service<axum::http::Request<Body>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<Body>) -> Self::Future {
        let cb_state = self.state.clone();
        let runtime = self.runtime.clone();
        let config = self.config.clone();
        let extractor = self.extractor.clone();
        // Clone the inner service for the async block; poll_ready was already
        // called on `self.inner` so `self.inner` is ready, but we move it into
        // the future via clone (standard Tower pattern for stateless middleware).
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // ── Bypass header — always passes through tripped circuits ────────
            if let Some(ref header_name) = config.bypass_header {
                if req.headers().contains_key(header_name.as_str()) {
                    return inner.call(req).await;
                }
            }

            let path = req.uri().path().to_string();

            let Some(service) = extractor(&path) else {
                return inner.call(req).await;
            };

            // ── File-based state check ────────────────────────────────────────
            {
                let guard = cb_state.read().await;
                if let Some(svc_state) = guard.get(&service) {
                    if svc_state.status == CircuitStatus::Tripped {
                        let reason = svc_state
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Consecutive health check failures".to_string());
                        let since = svc_state.since.clone().unwrap_or_default();
                        let failures = svc_state.consecutive_failures;
                        drop(guard);

                        warn!(
                            service = %service,
                            failures,
                            since = %since,
                            "Circuit breaker TRIPPED (file) — rejecting request"
                        );

                        return Ok((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "error": "service_unavailable",
                                "message": format!(
                                    "Service '{}' is temporarily unavailable due to \
                                     {} consecutive failures",
                                    service, failures
                                ),
                                "service": service,
                                "consecutive_failures": failures,
                                "tripped_since": since,
                                "reason": reason,
                                "source": "health_check",
                                "retry_after": "Check back after the next health cycle",
                            })),
                        )
                            .into_response());
                    }
                }
            }

            // ── In-process runtime state check ────────────────────────────────
            //
            // Atomically determine whether this request should be allowed through
            // (Closed or allowed probe) or rejected (Tripped / HalfOpen with
            // probe already in flight).
            let allow = {
                let mut guard = runtime.write().await;
                let status = guard.get(&service).map(|e| e.status);

                match status {
                    // Unknown service or healthy — pass through.
                    None | Some(RuntimeStatus::Closed) => true,

                    Some(RuntimeStatus::Tripped) => {
                        let entry = guard.get_mut(&service).unwrap();
                        let past_cooldown = entry
                            .tripped_at
                            .map(|at| at.elapsed() >= config.half_open_timeout)
                            .unwrap_or(false);
                        if past_cooldown {
                            // Transition to half-open and claim the probe slot.
                            entry.status = RuntimeStatus::HalfOpen;
                            entry.probe_in_flight = true;
                            entry.probe_started_at = Some(std::time::Instant::now());
                            warn!(
                                service = %service,
                                "In-process circuit entering half-open — allowing probe"
                            );
                            true
                        } else {
                            false
                        }
                    }

                    Some(RuntimeStatus::HalfOpen) => {
                        let entry = guard.get_mut(&service).unwrap();
                        // Free a stale probe slot if the probe was dropped
                        // (e.g. client disconnected) before completing.
                        let probe_stale = entry
                            .probe_started_at
                            .map(|at| at.elapsed() >= config.half_open_timeout)
                            .unwrap_or(false);
                        if probe_stale {
                            entry.probe_in_flight = false;
                        }
                        if !entry.probe_in_flight {
                            entry.probe_in_flight = true;
                            entry.probe_started_at = Some(std::time::Instant::now());
                            true
                        } else {
                            false
                        }
                    }
                }
            };

            if !allow {
                let (failures, half_open) = {
                    let guard = runtime.read().await;
                    let e = guard.get(&service);
                    (
                        e.map(|e| e.consecutive_failures).unwrap_or(0),
                        e.map(|e| e.status == RuntimeStatus::HalfOpen)
                            .unwrap_or(false),
                    )
                };

                let retry_msg = if half_open {
                    "A probe is already in flight; try again shortly"
                } else {
                    "Circuit is in cooldown; a probe will be attempted automatically"
                };

                warn!(
                    service = %service,
                    failures,
                    "In-process circuit TRIPPED — rejecting request"
                );

                return Ok((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "service_unavailable",
                        "message": format!(
                            "Service '{}' is temporarily unavailable (in-process detection)",
                            service
                        ),
                        "service": service,
                        "consecutive_failures": failures,
                        "source": "in_process",
                        "retry_after": retry_msg,
                    })),
                )
                    .into_response());
            }

            // ── Forward to inner service ──────────────────────────────────────
            let resp = inner.call(req).await?;
            let is_failure = resp.status().is_server_error();

            // ── Update runtime state based on response ────────────────────────
            {
                let mut guard = runtime.write().await;
                let entry = guard.entry(service.clone()).or_default();

                match entry.status {
                    RuntimeStatus::Closed => {
                        if is_failure {
                            entry.consecutive_failures += 1;
                            if entry.consecutive_failures >= config.threshold {
                                entry.status = RuntimeStatus::Tripped;
                                entry.tripped_at = Some(std::time::Instant::now());
                                warn!(
                                    service = %service,
                                    failures = entry.consecutive_failures,
                                    "In-process circuit TRIPPED after consecutive failures"
                                );
                            }
                        } else {
                            entry.consecutive_failures = 0;
                        }
                    }

                    RuntimeStatus::HalfOpen => {
                        entry.probe_in_flight = false;
                        entry.probe_started_at = None;

                        if is_failure {
                            entry.status = RuntimeStatus::Tripped;
                            entry.tripped_at = Some(std::time::Instant::now());
                            entry.consecutive_successes = 0;
                            warn!(service = %service, "Half-open probe FAILED — re-tripping");
                        } else {
                            entry.consecutive_successes += 1;
                            if entry.consecutive_successes >= config.success_threshold {
                                entry.status = RuntimeStatus::Closed;
                                entry.consecutive_failures = 0;
                                entry.consecutive_successes = 0;
                                entry.tripped_at = None;
                                info!(
                                    service = %service,
                                    "In-process circuit RECOVERED — half-open probe succeeded"
                                );
                            }
                        }
                    }

                    // Shouldn't be reached (we rejected above); clear stale flag.
                    RuntimeStatus::Tripped => {
                        entry.probe_in_flight = false;
                    }
                }
            }

            Ok(resp)
        })
    }
}

// ── Constructor ───────────────────────────────────────────────────────────────

/// Create a [`CircuitBreakerLayer`] that enforces circuit breaker state.
///
/// * `state` – file-based circuit state (from
///   [`CircuitBreakerHandle::shared_state()`](crate::CircuitBreakerHandle::shared_state)).
/// * `runtime` – in-process runtime state (from
///   [`CircuitBreakerHandle::runtime_state()`](crate::CircuitBreakerHandle::runtime_state)).
/// * `config` – configuration (thresholds, bypass header, half-open timeout, etc.).
/// * `extractor` – closure mapping a request path to a service name, or `None`
///   if the path should not be circuit-checked.
pub fn circuit_breaker_layer<F>(
    state: SharedState,
    runtime: RuntimeState,
    config: CircuitBreakerConfig,
    extractor: F,
) -> CircuitBreakerLayer<F>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
{
    CircuitBreakerLayer {
        state,
        runtime,
        config: Arc::new(config),
        extractor: Arc::new(extractor),
    }
}
