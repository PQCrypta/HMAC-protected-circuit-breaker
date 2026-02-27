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
//! ## How service names are resolved
//!
//! Supply a **extractor function** that maps a request path to a service name:
//!
//! ```rust,ignore
//! fn my_extractor(path: &str) -> Option<String> {
//!     // e.g. "/encrypt/hybrid" → Some("hybrid")
//!     path.trim_start_matches('/').splitn(2, '/').nth(1).map(str::to_string)
//! }
//! ```
//!
//! ## Bypass header
//!
//! Requests containing the configured bypass header are always passed through,
//! even to tripped services.  This allows health-check processes to re-probe a
//! tripped service and confirm recovery.
//!
//! ## Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::post};
//! use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
//! use hmac_circuit_breaker::middleware::circuit_breaker_layer;
//! use std::path::PathBuf;
//!
//! async fn encrypt() -> &'static str { "ok" }
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = CircuitBreakerConfig::builder()
//!         .state_file(PathBuf::from("/var/run/myapp/circuit_breaker.json"))
//!         .secret(std::env::var("DB_PASSWORD").unwrap_or_default())
//!         .build();
//!
//!     let handle = CircuitBreakerHandle::new(config.clone());
//!     handle.load().await;
//!     handle.spawn_reload();
//!
//!     let extractor = |path: &str| -> Option<String> {
//!         let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
//!         if segs.first() == Some(&"encrypt") { segs.get(1).map(|s| s.to_string()) }
//!         else { None }
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
    state::{CircuitStatus, RuntimeServiceState, RuntimeStatus},
    RuntimeState, SharedState,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tower::{Layer, Service};
use tracing::{info, warn};

// ── Layer ─────────────────────────────────────────────────────────────────────

/// Tower [`Layer`] returned by [`circuit_breaker_layer`].
///
/// Wraps any inner service with circuit-breaker enforcement — both file-based
/// and in-process runtime state are checked before forwarding each request.
#[derive(Clone)]
pub struct CircuitBreakerLayer<F> {
    state: SharedState,
    runtime: RuntimeState,
    config: Arc<CircuitBreakerConfig>,
    extractor: Arc<F>,
}

impl<F, S> Layer<S> for CircuitBreakerLayer<F>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
    S: Service<Request<Body>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
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

// ── Service ───────────────────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`CircuitBreakerLayer`].
///
/// Enforces both file-based and in-process circuit state on every request.
#[derive(Clone)]
pub struct CircuitBreakerService<F, S> {
    inner: S,
    state: SharedState,
    runtime: RuntimeState,
    config: Arc<CircuitBreakerConfig>,
    extractor: Arc<F>,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<F, S> Service<Request<Body>> for CircuitBreakerService<F, S>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let file_state = self.state.clone();
        let runtime = self.runtime.clone();
        let config = self.config.clone();
        let extractor = self.extractor.clone();
        // Clone inner before the async block so `self` stays ready for the
        // next call (Tower contract: `call` must not be invoked again until
        // `poll_ready` returns `Ok`).
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // ── Bypass header — always pass through ──────────────────────────
            if let Some(ref header_name) = config.bypass_header {
                if request.headers().contains_key(header_name.as_str()) {
                    return inner.call(request).await;
                }
            }

            let path = request.uri().path().to_string();
            let service_name = match extractor(&path) {
                Some(s) => s,
                None => return inner.call(request).await,
            };

            // ── File-based circuit check ─────────────────────────────────────
            {
                let guard = file_state.read().await;
                if let Some(svc) = guard.get(&service_name) {
                    if svc.status == CircuitStatus::Tripped {
                        let reason = svc
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Consecutive health check failures".to_string());
                        let since = svc.since.clone().unwrap_or_default();
                        let failures = svc.consecutive_failures;
                        drop(guard);

                        warn!(
                            service = %service_name,
                            failures = failures,
                            since = %since,
                            "Circuit breaker (file-based) TRIPPED — rejecting request"
                        );

                        return Ok((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "error": "service_unavailable",
                                "message": format!(
                                    "Service '{}' is temporarily unavailable due to {} consecutive failures",
                                    service_name, failures
                                ),
                                "service": service_name,
                                "consecutive_failures": failures,
                                "tripped_since": since,
                                "reason": reason,
                                "retry_after": "Check back after the next health cycle",
                            })),
                        )
                            .into_response());
                    }
                }
            }

            // ── In-process runtime circuit check ────────────────────────────
            let is_probe;
            {
                let mut guard = runtime.write().await;
                let rt = guard
                    .entry(service_name.clone())
                    .or_insert_with(RuntimeServiceState::default);

                match rt.status {
                    RuntimeStatus::Closed => {
                        is_probe = false;
                    }
                    RuntimeStatus::Tripped => {
                        let elapsed = rt
                            .tripped_at
                            .map(|t| t.elapsed())
                            .unwrap_or(std::time::Duration::MAX);

                        if elapsed >= config.half_open_timeout {
                            // Cooldown elapsed → enter half-open, send this request as probe
                            rt.status = RuntimeStatus::HalfOpen;
                            rt.probe_in_flight = true;
                            rt.probe_started_at = Some(Instant::now());
                            is_probe = true;
                        } else {
                            // Still cooling down → reject
                            drop(guard);
                            warn!(
                                service = %service_name,
                                "Circuit breaker (in-process) TRIPPED — rejecting request"
                            );
                            return Ok((
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({
                                    "error": "service_unavailable",
                                    "message": format!(
                                        "Service '{}' circuit is tripped; retry after cooldown",
                                        service_name
                                    ),
                                    "service": service_name,
                                    "source": "in_process",
                                    "retry_after": "Check back after the cooldown period",
                                })),
                            )
                                .into_response());
                        }
                    }
                    RuntimeStatus::HalfOpen => {
                        // Allow a probe only when none is in flight (or the
                        // in-flight probe has been running longer than the
                        // half-open timeout, indicating a dropped connection).
                        let probe_stale = rt
                            .probe_started_at
                            .map(|t| t.elapsed() >= config.half_open_timeout)
                            .unwrap_or(true);

                        if rt.probe_in_flight && !probe_stale {
                            // Another probe is already in flight → reject
                            drop(guard);
                            return Ok((
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({
                                    "error": "service_unavailable",
                                    "message": format!(
                                        "Service '{}' circuit is half-open; probe already in flight",
                                        service_name
                                    ),
                                    "service": service_name,
                                    "source": "in_process",
                                    "retry_after": "Check back after the probe completes",
                                })),
                            )
                                .into_response());
                        }

                        // Allow through as probe
                        rt.probe_in_flight = true;
                        rt.probe_started_at = Some(Instant::now());
                        is_probe = true;
                    }
                }
            }

            // ── Forward to inner service ─────────────────────────────────────
            let response = inner.call(request).await?;
            let status = response.status();

            // ── Update in-process runtime state based on response ────────────
            {
                let mut guard = runtime.write().await;
                let rt = guard
                    .entry(service_name.clone())
                    .or_insert_with(RuntimeServiceState::default);

                if status.is_server_error() {
                    if is_probe {
                        // Probe failed → re-trip the circuit
                        rt.status = RuntimeStatus::Tripped;
                        rt.consecutive_failures = 1;
                        rt.consecutive_successes = 0;
                        rt.tripped_at = Some(Instant::now());
                        rt.probe_in_flight = false;
                        rt.probe_started_at = None;

                        warn!(
                            service = %service_name,
                            "Half-open probe failed — circuit (in-process) re-tripped"
                        );
                    } else {
                        rt.consecutive_failures += 1;
                        rt.consecutive_successes = 0;

                        if rt.consecutive_failures >= config.threshold {
                            rt.status = RuntimeStatus::Tripped;
                            rt.tripped_at = Some(Instant::now());

                            warn!(
                                service = %service_name,
                                failures = rt.consecutive_failures,
                                "Circuit breaker (in-process) tripped after consecutive failures"
                            );
                        }
                    }
                } else {
                    // Non-5xx response → success
                    if is_probe {
                        rt.consecutive_successes += 1;
                        if rt.consecutive_successes >= config.success_threshold {
                            rt.status = RuntimeStatus::Closed;
                            rt.consecutive_failures = 0;
                            rt.consecutive_successes = 0;
                            rt.probe_in_flight = false;
                            rt.probe_started_at = None;

                            info!(
                                service = %service_name,
                                "Circuit breaker (in-process) closed after successful probe"
                            );
                        } else {
                            rt.probe_in_flight = false;
                            rt.probe_started_at = None;
                        }
                    } else {
                        // Non-probe success resets the failure counter
                        rt.consecutive_failures = 0;
                    }
                }
            }

            Ok(response)
        })
    }
}

// ── Constructor ───────────────────────────────────────────────────────────────

/// Create an axum-compatible [`Layer`] that enforces circuit breaker state.
///
/// * `state` – file-based shared state from [`CircuitBreakerHandle::shared_state()`].
/// * `runtime` – in-process runtime state from [`CircuitBreakerHandle::runtime_state()`].
/// * `config` – configuration (threshold, bypass header, half-open timeout, etc.).
/// * `service_extractor` – maps a request path to a service name, or `None` to skip checking.
///
/// Returns a concrete [`CircuitBreakerLayer<F>`] that can be passed directly to
/// axum's `Router::layer()`.
pub fn circuit_breaker_layer<F>(
    state: SharedState,
    runtime: RuntimeState,
    config: CircuitBreakerConfig,
    service_extractor: F,
) -> CircuitBreakerLayer<F>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
{
    CircuitBreakerLayer {
        state,
        runtime,
        config: Arc::new(config),
        extractor: Arc::new(service_extractor),
    }
}
