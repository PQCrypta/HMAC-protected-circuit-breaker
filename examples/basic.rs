//! Basic usage example: write a state file with the producer, then read it with the
//! consumer handle.

use hmac_circuit_breaker::{
    writer::{write_state, ServiceObservation},
    CircuitBreakerConfig, CircuitBreakerHandle,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let state_file = PathBuf::from("/tmp/example_circuit_breaker.json");

    // ── Producer side ────────────────────────────────────────────────────────
    // Typically this is a health-check cron process, not the API server itself.

    let observations = vec![
        ServiceObservation {
            name: "payments".to_string(),
            passed: true,
            error: None,
        },
        ServiceObservation {
            name: "auth".to_string(),
            passed: false,
            error: Some("connection refused: 127.0.0.1:5432".to_string()),
        },
        ServiceObservation {
            name: "notifications".to_string(),
            passed: false,
            error: Some("timeout after 5s".to_string()),
        },
    ];

    write_state(
        &state_file,
        &observations,
        &BTreeMap::new(),
        3,
        "example-secret",
    )?;
    println!("Wrote state to {state_file:?}");

    // ── Consumer side ────────────────────────────────────────────────────────
    // The API server loads this file and checks circuits before handling requests.

    let config = CircuitBreakerConfig::builder()
        .state_file(state_file.clone())
        .secret("example-secret")
        .threshold(3)
        .reload_interval(Duration::from_secs(60))
        .build();

    let handle = CircuitBreakerHandle::new(config);

    // Load once at startup
    handle.load().await;

    // Start background reload
    handle.spawn_reload();

    // Check service availability
    let services = ["payments", "auth", "notifications", "unknown"];
    for svc in &services {
        let tripped = handle.is_tripped(svc).await;
        let state = handle.get(svc).await;
        println!(
            "  {svc:20} tripped={tripped}  state={:?}",
            state.map(|s| s.status)
        );
    }

    // Simulate two more failures for auth, then write again to trip it
    let mut prev = handle
        .snapshot()
        .await
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    // Give auth 2 more failures (prev had 1, threshold is 3 → trip at 3rd)
    let obs2 = vec![ServiceObservation {
        name: "auth".to_string(),
        passed: false,
        error: Some("still down".to_string()),
    }];
    write_state(&state_file, &obs2, &prev, 3, "example-secret")?;

    // Reload
    handle.load().await;
    prev = handle.snapshot().await.into_iter().collect();

    write_state(&state_file, &obs2, &prev, 3, "example-secret")?;
    handle.load().await;

    println!("\nAfter simulating 3 consecutive failures for 'auth':");
    for svc in &["auth", "payments"] {
        let tripped = handle.is_tripped(svc).await;
        println!("  {svc:20} tripped={tripped}");
    }

    // Cleanup
    let _ = std::fs::remove_file(&state_file);

    Ok(())
}
