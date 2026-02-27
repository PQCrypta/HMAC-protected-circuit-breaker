use hmac_circuit_breaker::{
    loader::load_into,
    state::{CircuitBreakerFile, CircuitStatus},
    writer::{write_state, ServiceObservation},
    CircuitBreakerConfig, CircuitBreakerHandle,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::RwLock;

fn config_for(path: &std::path::Path) -> CircuitBreakerConfig {
    CircuitBreakerConfig::builder()
        .state_file(path.to_path_buf())
        .secret("integration-test-secret")
        .threshold(2)
        .reload_interval(Duration::from_secs(999))
        .build()
}

#[tokio::test]
async fn load_valid_file_updates_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cb.json");
    let config = Arc::new(config_for(&path));

    let obs = vec![ServiceObservation {
        name: "svc".to_string(),
        passed: true,
        error: None,
    }];
    write_state(&path, &obs, &BTreeMap::new(), 2, &config.secret).unwrap();

    let state = Arc::new(RwLock::new(Default::default()));
    load_into(&state, &config).await;

    let guard = state.read().await;
    assert_eq!(guard["svc"].status, CircuitStatus::Closed);
}

#[tokio::test]
async fn hmac_mismatch_clears_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cb.json");

    // Write file with correct HMAC
    let obs = vec![ServiceObservation {
        name: "svc".to_string(),
        passed: true,
        error: None,
    }];
    write_state(&path, &obs, &BTreeMap::new(), 2, "correct-secret").unwrap();

    // Pre-populate state so we can confirm it gets cleared
    let state = Arc::new(RwLock::new({
        let mut m = std::collections::HashMap::new();
        m.insert(
            "pre-existing".to_string(),
            hmac_circuit_breaker::state::AlgorithmCircuitState::closed(),
        );
        m
    }));

    // Load with wrong secret — HMAC mismatch → fail-open → state cleared
    let config = Arc::new(config_for(&path));
    let bad_config = Arc::new(
        CircuitBreakerConfig::builder()
            .state_file(path.clone())
            .secret("wrong-secret")
            .build(),
    );

    load_into(&state, &bad_config).await;

    let guard = state.read().await;
    assert!(
        guard.is_empty(),
        "State should be cleared on HMAC mismatch (fail-open)"
    );
    let _ = config; // suppress unused warning
}

#[tokio::test]
async fn legacy_file_without_hmac_is_accepted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cb.json");

    // Write a legacy file with no integrity_hash
    let file = CircuitBreakerFile {
        updated_at: "2025-01-01T00:00:00Z".to_string(),
        threshold: 2,
        integrity_hash: None,
        algorithms: {
            let mut m = BTreeMap::new();
            m.insert(
                "legacy-svc".to_string(),
                hmac_circuit_breaker::state::AlgorithmCircuitState::closed(),
            );
            m
        },
    };
    let json = serde_json::to_string_pretty(&file).unwrap();
    std::fs::write(&path, &json).unwrap();

    let config = Arc::new(config_for(&path));
    let state = Arc::new(RwLock::new(Default::default()));
    load_into(&state, &config).await;

    let guard = state.read().await;
    assert!(
        guard.contains_key("legacy-svc"),
        "Legacy file should be accepted"
    );
}

#[tokio::test]
async fn circuit_trips_after_threshold() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cb.json");
    let config = config_for(&path);
    let handle = CircuitBreakerHandle::new(config.clone());

    // First failure (1/2) — should be Open, not Tripped
    let obs = vec![ServiceObservation {
        name: "svc".to_string(),
        passed: false,
        error: Some("err".to_string()),
    }];
    write_state(&path, &obs, &BTreeMap::new(), 2, &config.secret).unwrap();
    handle.load().await;
    assert!(
        !handle.is_tripped("svc").await,
        "Should not trip on first failure"
    );

    // Second failure (2/2 = threshold) — should trip
    let prev = handle.snapshot().await.into_iter().collect();
    write_state(&path, &obs, &prev, 2, &config.secret).unwrap();
    handle.load().await;
    assert!(handle.is_tripped("svc").await, "Should trip at threshold");

    // Recovery
    let prev2 = handle.snapshot().await.into_iter().collect();
    let recovery = vec![ServiceObservation {
        name: "svc".to_string(),
        passed: true,
        error: None,
    }];
    write_state(&path, &recovery, &prev2, 2, &config.secret).unwrap();
    handle.load().await;
    assert!(
        !handle.is_tripped("svc").await,
        "Should close after recovery"
    );
}

#[tokio::test]
async fn file_not_found_is_silently_ignored() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("does_not_exist.json");
    let config = Arc::new(config_for(&path));
    let state = Arc::new(RwLock::new(Default::default()));
    // Should not panic or return an error
    load_into(&state, &config).await;
    assert!(state.read().await.is_empty());
}
