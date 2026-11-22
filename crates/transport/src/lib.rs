//! Transport agent → central server: configuration, enrollment, spool with
//! hash chain, sending (HTTPS + mTLS, protobuf, zstd), heartbeat.
//!
//! Principles (main plan 9, 10):
//! - outgoing only, port 443 (or as configured)
//! - the central server can NOT send commands to the agent; responses contain
//!   only acknowledgements and content requests for paths that are already monitored
//! - on connection loss the spool buffers on disk (bounded)

pub mod client;
pub mod config;
pub mod enroll;
pub mod renew;
pub mod rules;
pub mod sender;
pub mod sink;
pub mod spool;
pub mod update;

pub use config::AgentConfig;
pub use spool::Spool;
