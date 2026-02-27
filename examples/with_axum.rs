//! axum middleware example.
//!
//! Run with: cargo run --example with_axum --features axum
//!
//! Then test:
//!   curl http://localhost:3000/encrypt/payments   # 200 OK (closed)
//!   curl http://localhost:3000/encrypt/auth       # 503 (tripped)
//!   curl -H "x-health-check-bypass: 1" http://localhost:3000/encrypt/auth  # bypass → 200

use axum::{routing::get, Router};
use hmac_circuit_breaker::{
    middleware::circuit_breaker_layer,
    writer::{write_state, ServiceObservation},
    CircuitBreakerConfig, CircuitBreakerHandle,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

async fn handler() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let state_file = PathBuf::from("/tmp/axum_example_cb.json");

    // Write initial state: payments=ok, auth=tripped (3 consecutive failures)
    let prev_auth = hmac_circuit_breaker::state::AlgorithmCircuitState {
        status: hmac_circuit_breaker::state::CircuitStatus::Open,
        consecutive_failures: 2,
        since: None,
        reason: None,
    };
    let mut prev = BTreeMap::new();
    prev.insert("auth".to_string(), prev_auth);

    let obs = vec![
        ServiceObservation {
            name: "payments".to_string(),
            passed: true,
            error: None,
        },
        ServiceObservation {
            name: "auth".to_string(),
            passed: false,
            error: Some("DB connection pool exhausted".to_string()),
        },
    ];
    write_state(&state_file, &obs, &prev, 3, "example-secret")?;

    let config = CircuitBreakerConfig::builder()
        .state_file(state_file.clone())
        .secret("example-secret")
        .threshold(3)
        .reload_interval(Duration::from_secs(10))
        .bypass_header(Some("x-health-check-bypass"))
        .build();

    let handle = CircuitBreakerHandle::new(config.clone());
    handle.load().await;
    handle.spawn_reload();

    // Extract service name from "/encrypt/{service}" and "/decrypt/{service}"
    let extractor = |path: &str| -> Option<String> {
        let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
        match segs.first() {
            Some(&"encrypt") | Some(&"decrypt") => segs.get(1).map(|s| s.to_string()),
            _ => None,
        }
    };

    let app = Router::new()
        .route("/encrypt/:service", get(handler))
        .route("/decrypt/:service", get(handler))
        .layer(circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        ));

    println!("Listening on http://0.0.0.0:3000");
    println!("  GET /encrypt/payments   → 200 (circuit closed)");
    println!("  GET /encrypt/auth       → 503 (circuit tripped)");
    println!("  GET /encrypt/auth  -H 'x-health-check-bypass: 1'  → 200 (bypass)");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    let _ = std::fs::remove_file(&state_file);
    Ok(())
}
