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
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

/// Create an axum [`tower::Layer`] that enforces circuit breaker state.
///
/// * `state` – shared in-memory circuit state (from [`CircuitBreakerHandle::shared_state()`]).
/// * `config` – configuration (bypass header name, etc.).
/// * `service_extractor` – function that maps a request path to a service name, or `None`
///   if the path should not be checked.
pub fn circuit_breaker_layer<F>(
    state: SharedState,
    config: CircuitBreakerConfig,
    service_extractor: F,
) -> axum::middleware::FromFnLayer<
    impl Fn(axum::extract::State<(SharedState, Arc<CircuitBreakerConfig>, Arc<F>)>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
        + Clone,
    (),
    (axum::extract::State<(SharedState, Arc<CircuitBreakerConfig>, Arc<F>)>, Request, Next),
>
where
    F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
{
    let config = Arc::new(config);
    let extractor = Arc::new(service_extractor);

    axum::middleware::from_fn_with_state(
        (state, config, extractor),
        move |axum::extract::State((cb_state, cfg, extractor)): axum::extract::State<(
            SharedState,
            Arc<CircuitBreakerConfig>,
            Arc<F>,
        )>,
              request: Request,
              next: Next| {
            Box::pin(async move {
                handle_request(cb_state, cfg, extractor, request, next).await
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
        },
    )
}

async fn handle_request<F>(
    cb_state: SharedState,
    config: Arc<CircuitBreakerConfig>,
    extractor: Arc<F>,
    request: Request,
    next: Next,
) -> Response
where
    F: Fn(&str) -> Option<String> + Send + Sync,
{
    // Allow health-check bypass
    if let Some(ref header_name) = config.bypass_header {
        if request.headers().contains_key(header_name.as_str()) {
            return next.run(request).await;
        }
    }

    let path = request.uri().path().to_string();

    if let Some(service) = extractor(&path) {
        let guard = cb_state.read().await;
        if let Some(svc_state) = guard.get(&service) {
            if svc_state.status == CircuitStatus::Tripped {
                let reason = svc_state
                    .reason
                    .clone()
                    .unwrap_or_else(|| "Consecutive health check failures".to_string());
                let since = svc_state.since.clone().unwrap_or_default();
                let failures = svc_state.consecutive_failures;

                warn!(
                    service = %service,
                    failures = failures,
                    since = %since,
                    "Circuit breaker TRIPPED — rejecting request"
                );

                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "service_unavailable",
                        "message": format!(
                            "Service '{}' is temporarily unavailable due to {} consecutive failures",
                            service, failures
                        ),
                        "service": service,
                        "consecutive_failures": failures,
                        "tripped_since": since,
                        "reason": reason,
                        "retry_after": "Check back after the next health cycle"
                    })),
                )
                    .into_response();
            }
        }
    }

    next.run(request).await
}
