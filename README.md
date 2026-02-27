# hmac-circuit-breaker

> An HMAC-protected circuit breaker with **fail-open semantics** for service resilience.

[![Crates.io](https://img.shields.io/crates/v/hmac-circuit-breaker.svg)](https://crates.io/crates/hmac-circuit-breaker)
[![docs.rs](https://img.shields.io/docsrs/hmac-circuit-breaker)](https://docs.rs/hmac-circuit-breaker)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The Problem with Persistent Circuit Breakers

A circuit breaker that only lives in memory resets on every restart — useful for
transient faults but blind to persistent failures that survive reboots. Persisting
circuit state to disk solves that, but it introduces a new attack surface:

> **If an adversary can write to the state file, they can trip every circuit — causing
> a denial-of-service without ever touching the services themselves.**

## The Solution

This crate computes **HMAC-SHA256** over the circuit state map and embeds the tag in
the state file. On every reload the tag is verified before the state is trusted.

### Why Fail-Open on HMAC Mismatch?

The natural instinct is to fail-closed when integrity breaks: "invalid file → block
everything." That instinct is wrong here. Consider what each choice gives an attacker:

| Response to tampered file | What the attacker achieves |
|---|---|
| **Fail-closed** — block all traffic | Full self-DoS. Attacker writes a plausible-but-MAC-invalid file; every circuit trips immediately. |
| **Fail-open** — clear all circuits | Temporary removal of circuit protection for one reload cycle. Worst case is the baseline behaviour *without* a circuit breaker. |

Fail-open means the attacker can at most *remove* protection for ~60 seconds — and
the tamper attempt is logged as a `WARN`. They cannot **weaponise** the circuit
breaker to block legitimate traffic.

The secret for the HMAC should be sourced from the same credential store as the
service (e.g. the database password), so an attacker who can write the file but
not read secrets still cannot forge a valid tag.

---

## Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │  Health-check process (producer)                        │
 │                                                         │
 │  1. Probe each service                                  │
 │  2. Accumulate consecutive failures per service         │
 │  3. Compute HMAC-SHA256 over sorted-key algorithms JSON │
 │  4. Write circuit_breaker.json atomically (tmp + rename)│
 └────────────────────────┬────────────────────────────────┘
                          │  on-disk JSON
 ┌────────────────────────▼────────────────────────────────┐
 │  API server (consumer)                                  │
 │                                                         │
 │  Background task reloads file every 60 s:               │
 │    • Verify HMAC — on mismatch: clear state (fail-open) │
 │    • Update Arc<RwLock<HashMap>> in-memory state        │
 │                                                         │
 │  Per-request middleware:                                 │
 │    • Extract service name from URL                      │
 │    • Check status in memory (O(1) read)                 │
 │    • If Tripped → 503; otherwise → pass through         │
 │    • bypass header → always pass through (health cron)  │
 └─────────────────────────────────────────────────────────┘
```

## State Machine

```text
                       pass
┌──────────┐  fail   ┌──────┐  fail×threshold  ┌─────────┐
│  Closed  │────────►│ Open │─────────────────►│ Tripped │
│ (normal) │         │      │                  │(blocked)│
└──────────┘         └──┬───┘                  └────┬────┘
     ▲                  │ pass                       │ pass
     └──────────────────┴───────────────────────────┘
```

- **Closed** — normal operation; requests pass through.
- **Open** — one or more failures below the threshold; requests still pass but the
  service is considered degraded.
- **Tripped** — consecutive failures reached the threshold; requests receive
  `503 Service Unavailable` until a health check passes.

## The Bypass Header

The health-check cron that writes the state file also needs to *read* through it.
Without a bypass, tripped circuits create a deadlock:

```
circuit tripped → health check blocked → circuit never resets → deadlock
```

The bypass header (default: `x-health-check-bypass`) lets the cron re-probe tripped
services. Only the health-check process knows to send this header; end-user requests
never include it.

---

## Installation

```toml
[dependencies]
hmac-circuit-breaker = "0.1"

# With axum middleware:
hmac-circuit-breaker = { version = "0.1", features = ["axum"] }
```

## Quick Start

### 1 — Health-check producer (writes state file)

```rust
use hmac_circuit_breaker::writer::{write_state, ServiceObservation};
use std::collections::BTreeMap;
use std::path::Path;

fn run_health_checks() -> Result<(), Box<dyn std::error::Error>> {
    // Results of probing your services
    let observations = vec![
        ServiceObservation { name: "payments".into(), passed: true,  error: None },
        ServiceObservation { name: "auth".into(),     passed: false,
                             error: Some("connection refused".into()) },
    ];

    // Load previous state to accumulate consecutive failure counts
    let prev = load_previous_state()?;

    write_state(
        Path::new("/var/run/myapp/circuit_breaker.json"),
        &observations,
        &prev,
        3,                  // trip after 3 consecutive failures
        &hmac_secret(),     // from env var / secrets manager
    )?;
    Ok(())
}
```

### 2 — API server consumer (reads state, checks circuits)

```rust
use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let config = CircuitBreakerConfig::builder()
        .state_file(PathBuf::from("/var/run/myapp/circuit_breaker.json"))
        .secret(std::env::var("DB_PASSWORD").unwrap_or_default())
        .threshold(3)
        .reload_interval(Duration::from_secs(60))
        .build();

    let handle = CircuitBreakerHandle::new(config);
    handle.load().await;    // initial load
    handle.spawn_reload();  // background refresh

    // Before dispatching to a service:
    if handle.is_tripped("auth").await {
        // return 503
    }
}
```

### 3 — axum middleware (`features = ["axum"]`)

```rust
use axum::{Router, routing::post};
use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};
use hmac_circuit_breaker::middleware::circuit_breaker_layer;

#[tokio::main]
async fn main() {
    let config = CircuitBreakerConfig::builder()
        .state_file("/var/run/myapp/circuit_breaker.json".into())
        .secret(std::env::var("DB_PASSWORD").unwrap_or_default())
        .build();

    let handle = CircuitBreakerHandle::new(config.clone());
    handle.load().await;
    handle.spawn_reload();

    // Map "/encrypt/{service}" → service name
    let extractor = |path: &str| -> Option<String> {
        let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
        if parts.first() == Some(&"encrypt") {
            parts.get(1).map(|s| s.to_string())
        } else {
            None
        }
    };

    let app = Router::new()
        .route("/encrypt/:service", post(my_handler))
        .layer(circuit_breaker_layer(handle.shared_state(), config, extractor));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

---

## State File Format

```json
{
  "updated_at": "2026-02-27T15:22:41Z",
  "threshold": 3,
  "integrity_hash": "7b1def6802fabaed287c41786162e5648f47010d…",
  "algorithms": {
    "auth": {
      "status": "tripped",
      "consecutive_failures": 3,
      "since": "2026-02-27T14:00:00Z",
      "reason": "connection refused: 127.0.0.1:5432"
    },
    "payments": {
      "status": "closed",
      "consecutive_failures": 0
    }
  }
}
```

`integrity_hash` is HMAC-SHA256 of the **compact JSON serialisation of the
`algorithms` map**. Because `serde_json::Map` is `BTreeMap`-backed, keys are always
sorted alphabetically — the same canonical form is produced by every writer and
verified by every reader regardless of insertion order.

---

## HMAC Secret Recommendations

| Environment | Recommended source |
|---|---|
| Development | Hard-coded fallback string (not secure but convenient) |
| Production | Database password / service account secret (same process boundary as the app) |
| Multi-service | Dedicated secret in Vault / AWS Secrets Manager |

The goal is that a process that can write the state file (but not read application
secrets) cannot forge a valid HMAC. This does not need to be a high-entropy random
key — it just needs to be **unavailable to the attacker** who might tamper with the
file.

---

## Cargo Features

| Feature | Default | Description |
|---|---|---|
| `reload` | **yes** | `CircuitBreakerHandle::spawn_reload()` tokio background task |
| `axum` | no | Axum middleware layer via `circuit_breaker_layer()` |

---

## Security Considerations

- **HMAC key rotation** — if you rotate the secret, update the health-check producer
  and the API consumer simultaneously. A brief window where the file has an old HMAC
  and the consumer has a new secret will trigger a fail-open (state cleared), not a
  crash.
- **File permissions** — restrict write access to the state file to the health-check
  process only. The HMAC is a second line of defence, not a replacement for OS-level
  access control.
- **Constant-time comparison** — the HMAC comparison uses a constant-time byte
  equality function to prevent timing side-channels.
- **Atomic writes** — the writer uses a temp-file + rename pattern to ensure readers
  never see a partial write.

---

## Running Examples

```bash
# Basic producer/consumer example
cargo run --example basic

# axum middleware (requires the axum feature)
cargo run --example with_axum --features axum
```

## Running Tests

```bash
cargo test
cargo test --features axum
```

---

## License

MIT — see [LICENSE](LICENSE).
