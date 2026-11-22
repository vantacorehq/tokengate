//! tokengate — pure Rust AI/LLM gate.
//! Token accounting, rate limits, PII scrubbing. Zero dependencies.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate and budget limits.
#[derive(Debug, Clone, Copy)]
pub struct Limit {
    pub rpm: u32,
    pub tpm: u32,
    pub max_tokens_per_request: u32,
}

/// A reservation that must be committed or released.
#[derive(Debug)]
pub struct Reservation {
    id: u64,
    user: String,
    reserved: u32,
}

/// The gate.
pub struct Gate {
    limit: Limit,
    /// user → (window_start_ms, request_count, token_count)
    buckets: HashMap<String, (u64, u32, u32)>,
    next_id: u64,
}

impl Gate {
    pub fn new(limit: Limit) -> Self {
        Self {
            limit,
            buckets: HashMap::new(),
            next_id: 1,
        }
    }

    /// Reserve tokens. Returns error string on denial.
    pub fn reserve(&mut self, user: &str, estimated: u32) -> Result<Reservation, &'static str> {
        if estimated > self.limit.max_tokens_per_request {
            return Err("exceeds max_tokens_per_request");
        }

        let now = now_ms();
        let window = now / 60_000; // 1-minute windows

        let entry = self.buckets.entry(user.to_string()).or_insert((window, 0, 0));
        if entry.0 != window {
            *entry = (window, 0, 0);
        }

        if entry.1 >= self.limit.rpm {
            return Err("rpm exceeded");
        }
        if entry.2 + estimated > self.limit.tpm {
            return Err("tpm exceeded");
        }

        entry.1 += 1;
        entry.2 += estimated;

        let id = self.next_id;
        self.next_id += 1;

        Ok(Reservation {
            id,
            user: user.to_string(),
            reserved: estimated,
        })
    }

    /// Commit actual usage (may be less or more than reserved).
    pub fn commit(&mut self, res: Reservation, actual: u32) {
        if let Some(entry) = self.buckets.get_mut(&res.user) {
            // Adjust for difference
            if actual > res.reserved {
                entry.2 = entry.2.saturating_add(actual - res.reserved);
            } else {
                entry.2 = entry.2.saturating_sub(res.reserved - actual);
            }
        }
        let _ = res; // consumed
    }

    /// Release a reservation without usage.
    pub fn release(&mut self, res: Reservation) {
        if let Some(entry) = self.buckets.get_mut(&res.user) {
            entry.1 = entry.1.saturating_sub(1);
            entry.2 = entry.2.saturating_sub(res.reserved);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Redact common PII patterns. Pure string scanning, no regex crate.
pub fn scrub_pii(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Email
        if let Some(end) = find_email(bytes, i) {
            out.push_str("[REDACTED_EMAIL]");
            i = end;
            continue;
        }
        // Simple phone (10-15 digits with separators)
        if let Some(end) = find_phone(bytes, i) {
            out.push_str("[REDACTED_PHONE]");
            i = end;
            continue;
        }
        // Credit-card-like 13-19 digits
        if let Some(end) = find_cc(bytes, i) {
            out.push_str("[REDACTED_CC]");
            i = end;
            continue;
        }

        // Copy one char (UTF-8 safe enough for this)
        if let Some(c) = input[i..].chars().next() {
            out.push(c);
            i += c.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn find_email(bytes: &[u8], start: usize) -> Option<usize> {
    // Very simple: look for @ and surrounding alphanum
    if start + 5 > bytes.len() {
        return None;
    }
    let mut at = None;
    for j in start..bytes.len().min(start + 80) {
        if bytes[j] == b'@' {
            at = Some(j);
            break;
        }
    }
    let at = at?;
    // crude check for local and domain
    if at > start && at + 2 < bytes.len() && bytes[at + 1].is_ascii_alphanumeric() {
        let end = (at + 1..bytes.len().min(at + 40))
            .find(|&j| !bytes[j].is_ascii_alphanumeric() && bytes[j] != b'.' && bytes[j] != b'-')
            .unwrap_or(bytes.len());
        if end > at + 2 {
            return Some(end);
        }
    }
    None
}

fn find_phone(bytes: &[u8], start: usize) -> Option<usize> {
    let mut digits = 0;
    let mut j = start;
    while j < bytes.len() && digits < 16 {
        let b = bytes[j];
        if b.is_ascii_digit() {
            digits += 1;
            j += 1;
        } else if b == b' ' || b == b'-' || b == b'(' || b == b')' || b == b'+' {
            j += 1;
        } else {
            break;
        }
    }
    if digits >= 10 {
        Some(j)
    } else {
        None
    }
}

fn find_cc(bytes: &[u8], start: usize) -> Option<usize> {
    let mut digits = 0;
    let mut j = start;
    while j < bytes.len() && digits < 20 {
        let b = bytes[j];
        if b.is_ascii_digit() {
            digits += 1;
            j += 1;
        } else if b == b' ' || b == b'-' {
            j += 1;
        } else {
            break;
        }
    }
    if (13..=19).contains(&digits) {
        Some(j)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_email() {
        let s = scrub_pii("contact alice@example.com please");
        assert!(s.contains("[REDACTED_EMAIL]"));
        assert!(!s.contains("alice@"));
    }

    #[test]
    fn reserve_and_commit() {
        let mut g = Gate::new(Limit {
            rpm: 10,
            tpm: 1000,
            max_tokens_per_request: 500,
        });
        let r = g.reserve("u1", 100).unwrap();
        g.commit(r, 80);
    }
}
