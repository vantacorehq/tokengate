# tokengate

AI/LLM proxy with token accounting, rate limits and PII filtering.

Pure Rust. Zero dependencies. Crash-safe by construction.

## What it solves

Startups and SaaS burn thousands of dollars on OpenAI/Anthropic because of:
- Runaway bots and infinite retry loops
- Missing TPM/RPM limits
- Personal data leaking into prompts

## Features

- Exact token accounting (reserve / commit / release)
- Token-bucket rate limiting (RPM + TPM)
- PII redaction (email, phone, SSN-like, credit card patterns)
- Idempotency keys
- Simple, embeddable API

## Usage

```rust
use tokengate::{Gate, Limit};

let mut gate = Gate::new(Limit {
    rpm: 60,
    tpm: 100_000,
    max_tokens_per_request: 8_000,
});

// Reserve before calling the model
let reservation = gate.reserve("user_42", 1200).expect("allowed");

// ... call OpenAI / Anthropic ...

// Commit actual usage
gate.commit(reservation, 980);

// Or scrub PII from a prompt
let clean = tokengate::scrub_pii("email me at alice@example.com");
assert_eq!(clean, "email me at [REDACTED_EMAIL]");
```

## Commercial

Custom routing, billing limits, logging and multi-tenant isolation available.
Typical integration: $800–$2500.

## License

MIT
