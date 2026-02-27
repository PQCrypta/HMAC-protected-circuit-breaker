# hmac-circuit-breaker

> A **focused, security-aware** circuit breaker for Rust — HMAC-protected on-disk state
> with fail-open semantics. Designed for systems where the state file cannot be trusted.

[![CI](https://github.com/PQCrypta/HMAC-protected-circuit-breaker/actions/workflows/ci.yml/badge.svg)](https://github.com/PQCrypta/HMAC-protected-circuit-breaker/actions/workflows/ci.yml)
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

This crate is the answer. It adds **HMAC-SHA256 integrity** to the on-disk state and
makes a deliberate, security-first choice about what to do when the check fails: it
**fails open** (clears all circuits) rather than failing closed (blocking all traffic).

That single decision — fail-open on tamper, not fail-closed — prevents an attacker
from weaponising the circuit breaker as a denial-of-service amplifier.

**Scope:** This is a focused security tool, not a general-purpose circuit breaker
framework. It does one thing: verify that the state file your health-check process
writes hasn't been tampered with, and enforce that state at the request boundary.

Designed for:
- Security-sensitive services where the circuit state file is on shared or
  world-writable storage
- Systems with a separate health-check process that writes state (cron job,
  monitoring daemon, sidecar)
- Axum-based APIs that need per-service circuit enforcement as a `tower::Layer`
- Environments where a self-DoS via state-file manipulation is a credible threat

---

## Hello World: the complete loop in ~10 lines

```rust
use hmac_circuit_breaker::{
    CircuitBreakerConfig, CircuitBreakerHandle,
    writer::{write_state, ServiceObservation},
    state::CircuitBreakerFile,
};
use std::{collections::BTreeMap, path::Path};

// ── Producer (health-check cron) ──────────────────────────────────────────────
let path = Path::new("/run/app/cb.json");
let prev = std::fs::read_to_string(path).ok()
    .and_then(|s| serde_json::from_str::<CircuitBreakerFile>(&s).ok())
    .map(|f| f.algorithms).unwrap_or_default();

write_state(path, &[
    ServiceObservation { name: "db".into(), passed: false, error: Some("timeout".into()) },
], &prev, 3, "my-secret")?;

// ── Consumer (API server) ─────────────────────────────────────────────────────
let handle = CircuitBreakerHandle::new(
    CircuitBreakerConfig::builder().state_file(path.into()).secret("my-secret").build()
);
handle.load().await;
handle.spawn_reload(); // background reload every 60 s

if handle.is_tripped("db").await { /* reject request with 503 */ }
```

---

## When to use this crate

**Use it when:**
- A separate process observes service health and writes results to a shared file,
  and you cannot trust that file won't be tampered with
- You need circuit state to survive application restarts
- You're on Axum and want per-service circuit enforcement as a middleware layer
- You need cryptographic proof that your circuit state hasn't been forged

**Skip it when:**
- Your circuit breaker needs in-process, in-memory detection only and you
  have no shared state file — use [`failsafe`](https://crates.io/crates/failsafe) instead
- The producer and consumer are the same process sharing memory directly

---

## Features

- **In-process failure detection** — middleware counts consecutive 5xx responses and trips the circuit immediately, without waiting for the next health-check cycle.
- **Automatic half-open probing** — after a configurable cooldown, one probe request is allowed through; success closes the circuit, failure restarts the cooldown.
- **HMAC-protected persistence** — circuit state is written to disk with an embedded HMAC-SHA256 tag; every reload verifies the tag before trusting any state.
- **Fail-open on tamper** — a bad HMAC clears all in-memory state rather than tripping every circuit; an attacker with write access can at most temporarily remove protection, not weaponise it.
- **Atomic file writes** — state is written to a `.tmp` file and renamed into place; readers never see a partial write.
- **Constant-time MAC comparison** — the HMAC tag is compared with an XOR-fold; no early exit, no timing oracle.
- **External producer model** — a separate health-check process (cron, sidecar, etc.) writes the state file; the API server only reads it.
- **Per-service granularity** — each named service has independent circuit state; one tripped service does not affect others.
- **Axum / Tower middleware** — drop-in `circuit_breaker_layer` wraps any axum `Router` with zero boilerplate.
- **Bypass header** — a configurable header lets the health-check cron re-probe tripped services without deadlocking.

---

## Design guarantees

These properties are explicitly enforced by the implementation:

| Guarantee | How it is implemented |
|---|---|
| **HMAC is deterministic across languages** | Both writer and verifier round-trip through `serde_json::Value` (BTreeMap-backed), producing alphabetically sorted keys at every nesting level — not just the outer map |
| **State file writes are atomic** | Writer outputs to `{path}.json.tmp` then calls `rename(2)` — readers never observe a partial write |
| **HMAC comparison is constant-time** | Custom `constant_time_eq` XOR-folds the byte slices; no early exit |
| **Tampered file fails open, not closed** | HMAC mismatch clears all in-memory state; no circuit is left tripped from a forged file |
| **Unknown services are open by default** | `is_tripped()` returns `false` for any name not in the state file; new services are never accidentally blocked |
| **First-run safe** | Missing state file is silently ignored; all circuits begin closed |
| **Legacy files are accepted** | Files without `integrity_hash` are loaded without HMAC verification for backward compatibility |
| **In-memory reads are lock-free contention-minimal** | State is `Arc<RwLock<HashMap>>` — concurrent reads never block each other |

---

## The Problem with Persistent Circuit Breakers

A circuit breaker that only lives in memory resets on every restart — useful for
transient faults but blind to persistent failures that survive reboots. Persisting
circuit state to disk solves that, but introduces a new attack surface:

> **If an adversary can write to the state file, they can trip every circuit — a
> denial-of-service without ever touching the services themselves.**

### Why Fail-Open on HMAC Mismatch?

| Response to tampered file | What the attacker achieves |
|---|---|
| **Fail-closed** — block all traffic | Full self-DoS. Attacker writes a plausible-but-MAC-invalid file; every circuit trips immediately. |
| **Fail-open** — clear all circuits | Temporary removal of protection for one reload cycle. Worst case is baseline behaviour *without* a circuit breaker. |

Fail-open means an attacker can at most *remove* protection for ~60 seconds — and the
tamper attempt is logged as a `WARN`. They cannot **weaponise** the circuit breaker.

The HMAC secret should come from the same credential store as the service (e.g. the
database password), so a process that can write the file but not read secrets cannot
forge a valid tag.

### Canonical JSON: The Cross-Language Contract

The HMAC input is the **compact, alphabetically sorted JSON of the `algorithms` map**.
This is the contract any third-party producer must follow:

```
Sort all JSON object keys alphabetically at every nesting level.
Compact serialisation (no whitespace).
UTF-8 encoding.
HMAC-SHA256 with the shared secret.
Hex-encode the output (lowercase).
```

Example canonical form for the HMAC input:
```json
{"auth":{"consecutive_failures":1,"reason":"timeout","status":"open"},"db":{"consecutive_failures":0,"status":"closed"}}
```

---

## Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │  Health-check process (producer)                        │
 │                                                         │
 │  1. Probe each service                                  │
 │  2. Load previous state from disk (accumulate failures) │
 │  3. Sort algorithms map, compact-serialise, HMAC-SHA256 │
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
 │    • Check status in memory (O(1) read, no contention)  │
 │    • If Tripped → 503; otherwise → pass through         │
 │    • bypass header → always pass through (health cron)  │
 └─────────────────────────────────────────────────────────┘
```

## State Machines

### File-based (written by external health-check producer)

```text
                       pass
┌──────────┐  fail   ┌──────┐  fail×threshold  ┌─────────┐
│  Closed  │────────►│ Open │─────────────────►│ Tripped │
│ (normal) │         │      │                  │(blocked)│
└──────────┘         └──┬───┘                  └────┬────┘
     ▲                  │ pass                       │ pass (next health cycle)
     └──────────────────┴───────────────────────────┘
```

- **Closed** — normal operation; all requests pass through.
- **Open** — failures below threshold; requests still pass.
- **Tripped** — consecutive failures ≥ threshold; requests get `503`.

### In-process runtime (managed by the axum middleware)

```text
              fail×threshold          half_open_timeout
┌──────────┐ ──────────────► ┌─────────┐ ──────────────► ┌──────────┐
│  Closed  │                 │ Tripped │                  │ HalfOpen │
│ (normal) │ ◄────────────── │(blocked)│ ◄─────────────── │ (1 probe)│
└──────────┘     recover     └─────────┘   probe failed   └────┬─────┘
     ▲                                                          │ probe ok
     └──────────────────────────────────────────────────────────┘
```

The middleware watches every response: `threshold` consecutive 5xx replies trip the
circuit immediately — no waiting for the next health-check run.  After
`half_open_timeout` one probe is allowed through:

- **Probe succeeds** → circuit closes, normal traffic resumes.
- **Probe fails** → circuit stays tripped, cooldown restarts.

If a probe request is cancelled mid-flight (client disconnect) the probe slot is
automatically freed after another `half_open_timeout` so the next request can claim it.

> **Both layers are independent.** Either one alone can block a request with `503`.
> The external producer handles planned downtime; the in-process detector catches
> transient failures between health-check cycles.

- **Unknown service** — `is_tripped()` returns `false`; untracked services are never blocked.

## The Bypass Header

The health-check cron needs to re-probe tripped services to confirm recovery. Without
a bypass, tripped circuits create a deadlock:

```
circuit tripped → health check blocked → circuit never resets → deadlock forever
```

The bypass header (default: `x-health-check-bypass`) lets the cron through. Only the
health-check process sends this header; end-user requests never include it.

---

## Installation

```toml
[dependencies]
hmac-circuit-breaker = "0.2"

# With axum middleware:
hmac-circuit-breaker = { version = "0.2", features = ["axum"] }
```

## Quick Start

### 1 — Health-check producer (writes state file)

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
    // Safe on first run — returns empty map if file doesn't exist yet.
    let previous: BTreeMap<_, _> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<CircuitBreakerFile>(&s).ok())
        .map(|f| f.algorithms)
        .unwrap_or_default();

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
    handle.spawn_reload();  // background refresh

    if handle.is_tripped("auth").await { /* return 503 */ }

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

    // Map "/encrypt/{service}" → service name for circuit lookup
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
        .layer(circuit_breaker_layer(
            handle.shared_state(),
            handle.runtime_state(),
            config,
            extractor,
        ));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

---

## Configuration Reference

Only `state_file` and `secret` need to be set in production.

| Field | Default | Description |
|---|---|---|
| `state_file` | `"circuit_breaker.json"` | Path to the on-disk JSON state file |
| `secret` | `"circuit-breaker-integrity"` | **Override in production** — HMAC signing secret |
| `threshold` | `3` | Consecutive failures before a circuit trips (file-based and in-process) |
| `reload_interval` | `60s` | How often the background task reloads from disk |
| `bypass_header` | `"x-health-check-bypass"` | Header that bypasses tripped circuits; `None` disables bypass |
| `half_open_timeout` | `30s` | Cooldown before a half-open probe is allowed after in-process trip |
| `success_threshold` | `1` | Consecutive successful probes needed to close the in-process circuit |

```rust
// Minimal production config
let config = CircuitBreakerConfig::builder()
    .state_file("/var/run/myapp/circuit_breaker.json".into())
    .secret(std::env::var("HMAC_SECRET").expect("HMAC_SECRET must be set"))
    .build();

// Disable bypass entirely (e.g. you handle recovery out-of-band)
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

The service map key is called `"algorithms"` — a naming convention from the original
use case (per-algorithm circuit protection in a cryptographic API). Any string key
works; `"algorithms"` is just the JSON field name. `integrity_hash` is absent in
legacy files, which are accepted without verification for backward compatibility.

---

## HMAC Secret Recommendations

| Environment | Recommended source |
|---|---|
| Development | Hard-coded fallback (convenient, not secure) |
| Production | Database password / service account secret |
| Multi-tenant | Dedicated secret per tenant in Vault / AWS Secrets Manager |

The secret does not need to be high-entropy — it just needs to be unavailable to the
process that might tamper with the file.

---

## Cargo Features

| Feature | Default | Description |
|---|---|---|
| `reload` | **yes** | `CircuitBreakerHandle::spawn_reload()` — requires tokio |
| `axum` | no | `circuit_breaker_layer()` axum middleware — implies `reload` |

---

## Versioning and stability

This crate follows [Semantic Versioning](https://semver.org). Releases in the `0.x`
series may include breaking API changes; every breaking change will be called out
explicitly in the changelog. The **on-disk JSON state file format** is considered
stable from `0.1` onward — a breaking change to the format will require a major
version bump so existing producers and consumers continue to interoperate.

---

## Security Considerations

- **HMAC key rotation** — update producer and consumer simultaneously. A brief window
  of mismatch triggers fail-open (circuits cleared), not a crash or outage.
- **File permissions** — restrict write access to the state file to the health-check
  process. HMAC is a second line of defence, not a replacement for OS-level ACLs.
- **Constant-time comparison** — HMAC tags are compared byte-by-byte with XOR folding;
  no early exit that could leak the tag length via timing.
- **Atomic writes** — `rename(2)` ensures readers never see a partial file.
- **Unknown services are fail-open** — newly deployed services are never accidentally
  blocked before their first health check.
- **No state = no block** — missing state file on first run is silently safe.

---

## Running the Examples

```bash
# Complete producer + consumer round-trip
cargo run --example basic

# axum middleware demo
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
