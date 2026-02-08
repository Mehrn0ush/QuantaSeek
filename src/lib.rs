//! QuantaSeek - PQC-aware TLS Scanner
//!
//! A modular TLS scanner designed to detect and analyze Post-Quantum Cryptography (PQC)
//! implementations in TLS 1.3 handshakes.
//!
//! ## Features
//!
//! - **PQC Detection**: Identifies hybrid key exchange and signature algorithms
//! - **Modular Architecture**: Separate modules for handshake, parsing, detection, and output
//! - **Multiple Profiles**: Support for different handshake profiles (Cloudflare, etc.)
//! - **Comprehensive Analysis**: Detailed security level classification
//! - **JSON Output**: Structured output for automated processing
//!
//! ## Usage
//!
//! ```bash
//! # Scan a server with PQC support
//! RUST_LOG=debug ./target/release/pqcscan pki.goog
//!
//! # Scan with specific profile
//! ./target/release/pqcscan --profile cloudflare pqc-demo.cryptoserver.dev
//! ```
//!
//! ## Architecture
//!
//! - `handshake.rs`: TLS handshake engine and ClientHello construction
//! - `parser.rs`: TLS message parsing and extraction
//! - `detector.rs`: PQC detection and analysis logic
//! - `output.rs`: Output formatting and presentation
//! - `constants.rs`: TLS and PQC constants with IETF references
//! - `cert.rs`: Certificate parsing and analysis

// Pull in pinned deps for security audit (RUSTSEC-2026-0007, RUSTSEC-2026-0009)
#[allow(unused_imports)]
use bytes as _;
#[allow(unused_imports)]
use time as _;

pub mod cert;
pub mod constants;
pub mod detailed_pqc_analysis;
pub mod detector;
pub mod handshake;
pub mod http_redirect;
pub mod output;
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
    CertificateInfo, ClientProfile, ExtensionMap, FallbackInfo, HandshakeProfile, HandshakeResult,
    OutputFormat, PqcAnalysis, PqcExtensions, ScanResult, SecurityScore,
    SignatureNegotiationStatus, TlsFeatures,
};

/// Returns true if verbose/debug output is requested (QUANTASEEK_DEBUG=1 or --verbose).
/// When false, [DEBUG] and progress messages are suppressed for production-friendly output.
pub fn verbose() -> bool {
    std::env::var("QUANTASEEK_DEBUG")
        .map(|v| v != "0")
        .unwrap_or(false)
}
