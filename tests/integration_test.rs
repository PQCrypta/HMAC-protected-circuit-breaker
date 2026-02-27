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

// ── Helpers shared by the in-process middleware tests ────────────────────────

#[cfg(feature = "axum")]
mod middleware_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::{IntoResponse, Response},
    };
    use hmac_circuit_breaker::middleware::circuit_breaker_layer;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    use tower::{Layer, Service};

    /// A minimal tower service that returns a configurable HTTP status code.
    /// Clones share the same `Arc<Mutex<StatusCode>>` so the code can be
    /// changed between requests.
    #[derive(Clone)]
    struct FixedStatusService(Arc<Mutex<StatusCode>>);

    impl FixedStatusService {
        fn new(code: StatusCode) -> Self {
            Self(Arc::new(Mutex::new(code)))
        }
        fn set(&self, code: StatusCode) {
            *self.0.lock().unwrap() = code;
        }
    }

    impl Service<Request<Body>> for FixedStatusService {
        type Response = Response;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Response, Infallible>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Request<Body>) -> Self::Future {
            let code = *self.0.lock().unwrap();
            std::future::ready(Ok(code.into_response()))
        }
    }

    fn make_req(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    /// Poll the service ready, then call it.  Avoids depending on `ServiceExt`
    /// (which has conflicting impls from the two tower versions in the dep graph).
    async fn call<S>(svc: &mut S, req: Request<Body>) -> Response
    where
        S: Service<Request<Body>, Response = Response, Error = Infallible>,
    {
        std::future::poll_fn(|cx| svc.poll_ready(cx)).await.unwrap();
        svc.call(req).await.unwrap()
    }

    fn cfg(threshold: u32, half_open_ms: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig::builder()
            .state_file("/tmp/nonexistent_cb.json".into())
            .threshold(threshold)
            .half_open_timeout(Duration::from_millis(half_open_ms))
            .success_threshold(1)
            .build()
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn in_process_trips_after_threshold() {
        let config = cfg(2, 5000);
        let handle = CircuitBreakerHandle::new(config.clone());
        let backend = FixedStatusService::new(StatusCode::INTERNAL_SERVER_ERROR);
        let extractor = |p: &str| -> Option<String> {
            p.trim_start_matches('/')
                .split('/')
                .next()
                .map(String::from)
        };

        let mut svc = circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        )
        .layer(backend);

        // First failure — below threshold, inner response passes through.
        let r1 = call(&mut svc, make_req("/svc")).await;
        assert_eq!(r1.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Second failure — reaches threshold; response still from inner but
        // circuit is now tripped for the *next* request.
        let r2 = call(&mut svc, make_req("/svc")).await;
        assert_eq!(r2.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Third request — circuit is tripped, middleware rejects it.
        let r3 = call(&mut svc, make_req("/svc")).await;
        assert_eq!(r3.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn success_resets_failure_counter() {
        let config = cfg(3, 5000);
        let handle = CircuitBreakerHandle::new(config.clone());
        let backend = FixedStatusService::new(StatusCode::INTERNAL_SERVER_ERROR);
        let extractor = |p: &str| -> Option<String> {
            p.trim_start_matches('/')
                .split('/')
                .next()
                .map(String::from)
        };

        let mut svc = circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        )
        .layer(backend.clone());

        // Two failures (threshold = 3) — circuit stays closed.
        call(&mut svc, make_req("/svc")).await;
        call(&mut svc, make_req("/svc")).await;

        // One success — resets the failure counter.
        backend.set(StatusCode::OK);
        call(&mut svc, make_req("/svc")).await;

        // Two more failures should NOT trip (counter was reset to 0).
        backend.set(StatusCode::INTERNAL_SERVER_ERROR);
        call(&mut svc, make_req("/svc")).await;
        call(&mut svc, make_req("/svc")).await;

        // Still open — one more failure would trip (3rd in a row), but we
        // confirm we're not blocked yet.
        let r = call(&mut svc, make_req("/svc")).await;
        assert_eq!(
            r.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Should still be passing through on the 2nd failure after reset"
        );
    }

    #[tokio::test]
    async fn half_open_probe_recovers_circuit() {
        let config = cfg(1, 5); // trip on first failure; 5 ms cooldown
        let handle = CircuitBreakerHandle::new(config.clone());
        let backend = FixedStatusService::new(StatusCode::INTERNAL_SERVER_ERROR);
        let extractor = |p: &str| -> Option<String> {
            p.trim_start_matches('/')
                .split('/')
                .next()
                .map(String::from)
        };

        let mut svc = circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        )
        .layer(backend.clone());

        // Trip the circuit.
        call(&mut svc, make_req("/svc")).await;

        // Immediately blocked.
        let blocked = call(&mut svc, make_req("/svc")).await;
        assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Wait for half-open cooldown.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Switch backend to healthy.
        backend.set(StatusCode::OK);

        // Probe passes through and succeeds.
        let probe = call(&mut svc, make_req("/svc")).await;
        assert_eq!(probe.status(), StatusCode::OK);

        // Circuit is now closed — normal traffic passes.
        let normal = call(&mut svc, make_req("/svc")).await;
        assert_eq!(normal.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn half_open_probe_failure_retrips_circuit() {
        let config = cfg(1, 5);
        let handle = CircuitBreakerHandle::new(config.clone());
        let backend = FixedStatusService::new(StatusCode::INTERNAL_SERVER_ERROR);
        let extractor = |p: &str| -> Option<String> {
            p.trim_start_matches('/')
                .split('/')
                .next()
                .map(String::from)
        };

        let mut svc = circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        )
        .layer(backend.clone());

        // Trip.
        call(&mut svc, make_req("/svc")).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Probe — still returns 500, so circuit re-trips.
        let probe = call(&mut svc, make_req("/svc")).await;
        assert_eq!(
            probe.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Probe itself passes through even though it fails"
        );

        // Circuit is tripped again — next request is blocked.
        let blocked = call(&mut svc, make_req("/svc")).await;
        assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn per_service_isolation() {
        let config = cfg(1, 5000);
        let handle = CircuitBreakerHandle::new(config.clone());
        let backend = FixedStatusService::new(StatusCode::INTERNAL_SERVER_ERROR);
        let extractor = |p: &str| -> Option<String> {
            p.trim_start_matches('/')
                .split('/')
                .next()
                .map(String::from)
        };

        let mut svc = circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        )
        .layer(backend.clone());

        // Trip circuit for "alpha".
        call(&mut svc, make_req("/alpha")).await;
        let blocked = call(&mut svc, make_req("/alpha")).await;
        assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);

        // "beta" is on a healthy path — should not be affected.
        backend.set(StatusCode::OK);
        let ok = call(&mut svc, make_req("/beta")).await;
        assert_eq!(ok.status(), StatusCode::OK);
    }
}

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
