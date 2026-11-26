//! Core of the agent: event model, hashes, diff/patch, snapshot cache,
//! redaction, policy (incl. fixed local blocklist) and processing.
//!
//! Spike state: deliberately simple, but already in the later crate structure.

pub mod state;
pub mod trust;
pub mod container;
pub mod content;
pub mod debounce;
pub mod deploy;
pub mod pkgverify;
pub mod pkgwindow;
pub mod diff;
pub mod event;
pub mod hash;
pub mod policy;
pub mod procinfo;
pub mod proctable;
pub mod processor;
pub mod redact;
pub mod rootfs;
pub mod sink;

pub use event::{Backend, Event, Op, RawEvent};
pub use policy::{ContentMode, Policy};
pub use processor::Processor;

/// Current time in nanoseconds since the epoch.
pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
