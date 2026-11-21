//! Kern des Agents: Ereignismodell, Hashes, Diff/Patch, Snapshot-Cache,
//! Redaction, Policy (inkl. fester lokaler Sperrliste) und Verarbeitung.
//!
//! Spike-Stand: bewusst einfach, aber schon in der späteren Crate-Struktur.

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
pub mod processor;
pub mod redact;
pub mod rootfs;
pub mod sink;

pub use event::{Backend, Event, Op, RawEvent};
pub use policy::{ContentMode, Policy};
pub use processor::Processor;

/// Aktuelle Zeit in Nanosekunden seit Epoch.
pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
