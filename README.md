# tokengate

**AI/LLM proxy with precise token accounting, rate limits and PII filtering.**

Pure Rust · Zero dependencies · Crash-safe by construction

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The problem it solves

Teams burning money on OpenAI / Anthropic / Claude usually lose budget because of:

- runaway agents and infinite retry loops
- missing or soft RPM / TPM limits
- PII (emails, phones, cards) leaking into prompts and logs
- no per-user or per-tenant isolation

`tokengate` is a tiny, embeddable gate you put in front of any LLM call.

## Features

| Feature | Description |
|---------|-------------|
| **Exact accounting** | `reserve` → call model → `commit` actual tokens |
| **Token-bucket limits** | RPM + TPM per user / tenant |
| **PII redaction** | email, phone, credit-card patterns (no regex crate) |
| **Idempotency-ready** | reservation IDs for safe retries |
| **Zero dependencies** | only `std` |
| **Embeddable** | library, not a separate process |

## Quick start

```toml
[dependencies]
tokengate = { git = "https://github.com/vantacorehq/tokengate" }
```

```rust
use tokengate::{Gate, Limit};

fn main() {
    let mut gate = Gate::new(Limit {
        rpm: 60,
        tpm: 100_000,
        max_tokens_per_request: 8_000,
    });

    // 1. Reserve before the expensive call
    let reservation = gate.reserve("user_42", 1_200)
        .expect("rate limit exceeded");

    // 2. Call your model (OpenAI, Anthropic, local…)
    // let response = call_llm(...);

    // 3. Commit real usage
    gate.commit(reservation, 980);

    // Bonus: scrub PII from any string
    let clean = tokengate::scrub_pii("email me at alice@example.com or +1-555-123-4567");
    assert!(clean.contains("[REDACTED_EMAIL]"));
    assert!(clean.contains("[REDACTED_PHONE]"));
}
```

## API surface

```rust
pub struct Limit {
    pub rpm: u32,
    pub tpm: u32,
    pub max_tokens_per_request: u32,
}

impl Gate {
    pub fn new(limit: Limit) -> Self;
    pub fn reserve(&mut self, user: &str, estimated: u32) -> Result<Reservation, &'static str>;
    pub fn commit(&mut self, res: Reservation, actual: u32);
    pub fn release(&mut self, res: Reservation);
}

pub fn scrub_pii(input: &str) -> String;
```

## Tests

```bash
cargo test
```

All tests pass with zero external crates.

## License

MIT
