# hmac-circuit-breaker

> An HMAC-protected circuit breaker with **fail-open semantics** for service resilience.

[![Crates.io](https://img.shields.io/crates/v/hmac-circuit-breaker.svg)](https://crates.io/crates/hmac-circuit-breaker)
[![docs.rs](https://img.shields.io/docsrs/hmac-circuit-breaker)](https://docs.rs/hmac-circuit-breaker)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue)](https://www.rust-lang.org)

---

## Why this crate exists

Most circuit breaker crates keep state in memory and reset on restart. Some persist
state to disk to survive reboots — but none of them ask the question:

> *What happens if someone writes a plausible-looking state file with every circuit
> "tripped"?*

This crate answers that. It adds **HMAC-SHA256 integrity** to the on-disk state and
makes a deliberate architectural choice about what to do when the check fails: it
**fails open** (clears all circuits) rather than failing closed (blocking all traffic).

That single decision — fail-open on tamper, not fail-closed — prevents an attacker from
weaponising the circuit breaker as a denial-of-service amplifier.

Designed for:
- Security-sensitive services where the circuit state file is on shared or
  world-writable storage
- Systems with a separate health-check process that writes state (monitoring daemon,
  cron job, sidecar)
- Axum-based APIs that need per-service circuit enforcement as a middleware layer

---

## Hello World

```rust
use hmac_circuit_breaker::{CircuitBreakerConfig, CircuitBreakerHandle};

#[tokio::main]
async fn main() {
    let handle = CircuitBreakerHandle::new(CircuitBreakerConfig::default());
    handle.load().await;       // load state file once at startup
    handle.spawn_reload();     // reload in background every 60 s

    if handle.is_tripped("payments").await {
        eprintln!("payments circuit is open — skipping");
    }
}
```

---

## When to use this crate

**Use it when:**
- A separate process (cron, monitoring daemon) observes service health and writes
  results to a shared file — and you can't trust the file won't be tampered with
- You need the circuit state to survive application restarts
- You're running on Axum and want circuit enforcement as a `tower::Layer`

**Skip it when:**
- Your circuit breaker only needs in-process, in-memory state (use
  [`failsafe`](https://crates.io/crates/failsafe) or similar)
- The producer and consumer are the same process and share memory directly
- You don't need per-service granularity

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

Fail-open means the attacker can at most *remove* protection for ~60 seconds — and the
tamper attempt is logged as a `WARN`. They cannot **weaponise** the circuit breaker to
block legitimate traffic.

The HMAC secret should be sourced from the same credential store as the service (e.g.
the database password), so an attacker who can write the file but not read secrets
still cannot forge a valid tag.

### Canonical JSON: Why It Matters for Producers

The HMAC is computed over the **compact JSON of the `algorithms` map**. To get a
stable byte string both the writer and verifier round-trip the map through
`serde_json::Value` before serialising. This matters because:

- A Rust struct serialises fields in **declaration order** (e.g. `status` before
  `consecutive_failures`)
- `serde_json::Value` uses `BTreeMap` at **every level**, so all keys are sorted
  **alphabetically** regardless of how the struct was declared

Both sides must use the same canonical form. If you're implementing a third-party
producer in another language, sort all JSON object keys alphabetically at every
nesting level before computing the HMAC.

---

## Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │  Health-check process (producer)                        │
 │                                                         │
 │  1. Probe each service                                  │
 │  2. Load previous state from disk (accumulate failures) │
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
- **Unknown service** — `is_tripped()` returns `false` for any service not in the
  state file. This is intentional: fail-open is the default for untracked services.

## The Bypass Header

The health-check cron that writes the state file also needs to *read* through it.
Without a bypass, tripped circuits create a deadlock:

```
circuit tripped → health check blocked → circuit never resets → deadlock
```

The bypass header (default: `x-health-check-bypass`) lets the cron re-probe tripped
services. Only the health-check process sends this header; end-user requests never
include it.

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

The producer runs as a separate process (cron job, sidecar, etc.). It needs the
previous state to accumulate consecutive failure counts correctly. Read it from the
same file using `CircuitBreakerFile`:

```rust
use hmac_circuit_breaker::{
    state::CircuitBreakerFile,
    writer::{write_state, ServiceObservation},
};
use std::collections::BTreeMap;
use std::path::Path;

fn run_health_checks() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("/var/run/myapp/circuit_breaker.json");
    let secret = std::env::var("HMAC_SECRET").unwrap_or_default();

    // Load previous state to accumulate consecutive failure counts.
    // Returns empty map on first run or if the file doesn't exist yet.
    let previous: BTreeMap<_, _> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<CircuitBreakerFile>(&s).ok())
        .map(|f| f.algorithms)
        .unwrap_or_default();

    // Results of probing your services
    let observations = vec![
        ServiceObservation { name: "payments".into(), passed: true,  error: None },
        ServiceObservation { name: "auth".into(),     passed: false,
                             error: Some("connection refused".into()) },
    ];

    write_state(path, &observations, &previous, 3, &secret)?;
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
        .secret(std::env::var("HMAC_SECRET").unwrap_or_default())
        .threshold(3)
        .reload_interval(Duration::from_secs(60))
        .build();

    let handle = CircuitBreakerHandle::new(config);
    handle.load().await;    // initial load at startup
    handle.spawn_reload();  // background refresh every 60 s

    // Before dispatching to a service:
    if handle.is_tripped("auth").await {
        // return 503 — circuit is tripped
    }

    // Full state inspection:
    if let Some(state) = handle.get("payments").await {
        println!("{}: {} failures", state.status, state.consecutive_failures);
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
        .secret(std::env::var("HMAC_SECRET").unwrap_or_default())
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

## Configuration Reference

All fields have sensible defaults — only `state_file` and `secret` need to be set in
production.

| Field | Default | Description |
|---|---|---|
| `state_file` | `"circuit_breaker.json"` | Path to the on-disk JSON state file |
| `secret` | `"circuit-breaker-integrity"` | **Override in production** — HMAC signing secret |
| `threshold` | `3` | Consecutive failures before a circuit trips |
| `reload_interval` | `60s` | How often the background task reloads from disk |
| `bypass_header` | `"x-health-check-bypass"` | Request header that bypasses tripped circuits; set to `None` to disable |

```rust
// Minimal production config
let config = CircuitBreakerConfig::builder()
    .state_file("/var/run/myapp/circuit_breaker.json".into())
    .secret(std::env::var("HMAC_SECRET").expect("HMAC_SECRET must be set"))
    .build();

// Disable the bypass header entirely
let config = CircuitBreakerConfig::builder()
    .bypass_header(None::<&str>)
    .build();
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
      "consecutive_failures": 3,
      "reason": "connection refused: 127.0.0.1:5432",
      "since": "2026-02-27T14:00:00Z",
      "status": "tripped"
    },
    "payments": {
      "consecutive_failures": 0,
      "status": "closed"
    }
  }
}
```

Note that the service map key is called `"algorithms"` — a naming convention from the
original use case (per-algorithm circuit protection in a cryptographic API). The crate
accepts any string key; `"algorithms"` is just the field name in the JSON schema.

`integrity_hash` is HMAC-SHA256 of the **compact, alphabetically sorted JSON of the
`algorithms` map**. Keys at every nesting level are sorted because the crate uses
`serde_json::Value` (BTreeMap-backed) rather than the struct serialiser. Files without
`integrity_hash` are accepted for backward compatibility with legacy producers.

---

## HMAC Secret Recommendations

| Environment | Recommended source |
|---|---|
| Development | Hard-coded fallback string (not secure, but convenient) |
| Production | Database password / service account secret — same process boundary as the app |
| Multi-service | Dedicated secret in Vault / AWS Secrets Manager |

The goal is that a process that can write the state file (but cannot read application
secrets) cannot forge a valid HMAC. The secret does not need to be high-entropy — it
just needs to be **unavailable to the attacker** who might tamper with the file.

---

## Cargo Features

| Feature | Default | Description |
|---|---|---|
| `reload` | **yes** | `CircuitBreakerHandle::spawn_reload()` — requires tokio |
| `axum` | no | `circuit_breaker_layer()` axum middleware — implies `reload` |

---

## Security Considerations

- **HMAC key rotation** — update the health-check producer and API consumer
  simultaneously. A brief window where the file has an old HMAC and the consumer
  has a new secret triggers fail-open (state cleared), not a crash.
- **File permissions** — restrict write access to the state file to the health-check
  process. The HMAC is a second line of defence, not a replacement for OS-level ACLs.
- **Constant-time comparison** — HMAC tags are compared with a constant-time function
  to prevent timing side-channels.
- **Atomic writes** — the writer uses a temp-file + `rename` pattern so readers never
  observe a partial write.
- **Unknown services are fail-open** — `is_tripped()` returns `false` for any service
  not present in the state file. Newly deployed services are never accidentally blocked.
- **No state = no block** — if the state file doesn't exist yet (first run), all
  circuits are treated as closed. The background task silently waits for the file to
  appear.

---

## Running the Examples

```bash
# Producer + consumer round-trip
cargo run --example basic

# axum middleware (needs the axum feature)
cargo run --example with_axum --features axum
```

## Running Tests

```bash
# All unit + integration + doc tests
cargo test

# Include axum middleware tests
cargo test --features axum
```

---

## License

MIT — see [LICENSE](LICENSE).
