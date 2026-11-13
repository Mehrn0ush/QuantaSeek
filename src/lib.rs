//! QuantaSeek: a TLS scanner that reports the key exchange and certificate
//! algorithms an endpoint negotiates, with a focus on post-quantum
//! cryptography.
//!
//! The `quantaseek` binary (`src/main.rs`) is the main consumer of this
//! library. The library API is not stable before 1.0.
//!
//! ## Modules
//!
//! - [`scan`]: target parsing, connection, outcome classification
//! - [`handshake`]: one rustls handshake, recorded as an [`handshake::Observation`]
//! - [`report`]: the output (schema v0) and how each field is derived
//! - [`constants`]: TLS codepoint and X.509 OID registry, with sources
//! - [`cert`]: X.509 algorithm naming
//! - [`http_redirect`]: opt-in redirect following
//!
//! See README.md for what the scanner can and cannot observe.

pub mod cert;
pub mod constants;
pub mod handshake;
pub mod http_redirect;
pub mod report;
pub mod scan;
pub mod types;

pub use handshake::{HandshakeEngine, Observation};
pub use report::ScanReport;
pub use types::{ErrorCategory, ErrorCode, HandshakeConfig, HandshakeProfile, ScanError};
