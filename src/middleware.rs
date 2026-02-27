//! Axum middleware that rejects requests to tripped services with `503 Service Unavailable`.
//!
//! Enable with the `axum` Cargo feature.
//!
//! # How service names are resolved
//!
//! The middleware needs to map an incoming request URL to a service name tracked in the
//! circuit breaker state.  It does this via a user-supplied **extractor function**:
//!
//! ```rust,ignore
//! fn my_extractor(path: &str) -> Option<String> {
//!     // e.g. "/encrypt/hybrid" → Some("hybrid")
//!     path.trim_start_matches('/').splitn(2, '/').nth(1).map(str::to_string)
//! }
//! ```
//!
//! Pass this function (or closure) to [`circuit_breaker_layer`].
//!
//! # Bypass header
//!
//! Requests containing the configured bypass header are always passed through,
//! even to tripped services.  This allows health-check processes to re-probe a
//! tripped service and confirm recovery.  Without the bypass, a tripped circuit
//! creates a deadlock: the circuit blocks the probe that would reset it.
//!
//! # Example
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
//!     // Map "/encrypt/{service}" → "{service}"
//!     let extractor = |path: &str| -> Option<String> {
//!         let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
//!         if segs.first() == Some(&"encrypt") { segs.get(1).map(|s| s.to_string()) }
//!         else { None }
//!     };
//!
//!     let app = Router::new()
//!         .route("/encrypt/:service", post(encrypt))
//!         .layer(circuit_breaker_layer(handle.shared_state(), config, extractor));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```

use crate::{config::CircuitBreakerConfig, state::CircuitStatus, SharedState};
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
};
use tower::{Layer, Service};
use tracing::warn;

/// Tower [`Layer`] returned by [`circuit_breaker_layer`].
///
/// Wraps any inner service that handles `Request<Body>` and injects circuit
/// breaker enforcement before the inner service is called.
#[derive(Clone)]
pub struct CircuitBreakerLayer<F> {
    state: SharedState,
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
            config: self.config.clone(),
            extractor: self.extractor.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`CircuitBreakerLayer`].
///
/// Checks the circuit breaker state for each request before forwarding to the
/// inner service, short-circuiting with a `503` when the circuit is tripped.
#[derive(Clone)]
pub struct CircuitBreakerService<F, S> {
    inner: S,
    state: SharedState,
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
        let state = self.state.clone();
        let config = self.config.clone();
        let extractor = self.extractor.clone();
        // Clone inner so the original `self.inner` stays ready for the next call
        // (tower contract: call must not be invoked again until poll_ready returns Ok).
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Allow health-check bypass to pass through tripped circuits
            if let Some(ref header_name) = config.bypass_header {
                if request.headers().contains_key(header_name.as_str()) {
                    return inner.call(request).await;
                }
            }

            let path = request.uri().path().to_string();

            if let Some(service_name) = extractor(&path) {
                let guard = state.read().await;
                if let Some(svc_state) = guard.get(&service_name) {
                    if svc_state.status == CircuitStatus::Tripped {
                        let reason = svc_state
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Consecutive health check failures".to_string());
                        let since = svc_state.since.clone().unwrap_or_default();
                        let failures = svc_state.consecutive_failures;
                        drop(guard); // release read lock before returning

                        warn!(
                            service = %service_name,
                            failures = failures,
                            since = %since,
                            "Circuit breaker TRIPPED — rejecting request"
                        );

                        let response = (
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
                                "retry_after": "Check back after the next health cycle"
                            })),
                        )
                        .into_response();

                        return Ok(response);
                    }
                }
            }

            inner.call(request).await
        })
    }
}

/// Create an axum-compatible [`Layer`] that enforces circuit breaker state.
///
/// * `state` – shared in-memory circuit state (from [`CircuitBreakerHandle::shared_state()`]).
/// * `config` – configuration (bypass header name, etc.).
/// * `service_extractor` – function that maps a request path to a service name, or `None`
///   if the path should not be checked.
///
/// Returns a concrete [`CircuitBreakerLayer<F>`] that can be passed directly to
/// axum's `Router::layer()`.
pub fn circuit_breaker_layer<F>(
    state: SharedState,
    config: CircuitBreakerConfig,
    service_extractor: F,
) -> CircuitBreakerLayer<F>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
{
    CircuitBreakerLayer {
        state,
        config: Arc::new(config),
        extractor: Arc::new(service_extractor),
    }
}
