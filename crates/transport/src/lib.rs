//! Transport Agent → Zentrale: Konfiguration, Enrollment, Spool mit
//! Hash-Kette, Versand (HTTPS + mTLS, Protobuf, zstd), Heartbeat.
//!
//! Grundsätze (Hauptplan 9, 10):
//! - nur ausgehend, Port 443 (bzw. konfiguriert)
//! - die Zentrale kann dem Agent KEINE Befehle schicken; Antworten enthalten
//!   nur Bestätigungen und Inhaltsanforderungen für bereits überwachte Pfade
//! - bei Verbindungsverlust puffert der Spool auf der Platte (begrenzt)

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
