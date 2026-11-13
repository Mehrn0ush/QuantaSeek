//! QuantaSeek: a TLS scanner that reports negotiated key exchange and
//! certificate algorithms, with a focus on post-quantum cryptography.
//!
//! The `quantaseek` binary (`src/main.rs`) is the main consumer of this
//! library. The library API is not stable before 1.0.
//!
//! ## Modules
//!
//! - [`handshake`]: TLS handshake engine (rustls) and raw record capture
//! - [`tls_parser`]: ServerHello parsing (cipher suite, `key_share` group)
//! - [`detector`]: classification of the negotiated algorithms
//! - [`cert`]: X.509 certificate parsing (x509-parser)
//! - [`constants`]: TLS codepoint and X.509 OID registry, with sources
//! - [`output`]: JSON and text formatting
//!
//! See README.md for what the scanner can and cannot observe.

pub mod cert;
pub mod constants;
pub mod detailed_pqc_analysis;
pub mod detector;
pub mod handshake;
pub mod http_redirect;
pub mod output;
pub mod scan;
pub mod security_scoring;
pub mod signature_detector;
pub mod tls_parser;
pub mod types;

// Re-export main types for easier access
pub use detector::PqcDetector;
pub use handshake::HandshakeEngine;
pub use http_redirect::{detect_http_redirects, detect_http_redirects_with_method, HttpMethod};
pub use output::output_results;
pub use output::OutputFormatter;
pub use security_scoring::SecurityScorer;
pub use signature_detector::SignatureDetector;
pub use types::{
    CertificateInfo, ClientProfile, ErrorCode, ExtensionMap, FallbackInfo, HandshakeProfile,
    HandshakeResult, OutputFormat, PqcAnalysis, PqcExtensions, ScanError, ScanResult,
    SecurityScore, SignatureNegotiationStatus, TlsFeatures,
};
