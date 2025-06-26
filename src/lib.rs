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

pub mod constants;
pub mod detector;
pub mod handshake;
pub mod output;
pub mod types;
pub mod cert;
pub mod signature_detector;
pub mod security_scoring;

// Re-export main types for easier access
pub use types::{
    HandshakeProfile, HandshakeResult, PqcAnalysis, PqcExtensions, 
    TlsFeatures, CertificateInfo, ScanResult, OutputFormat, FallbackInfo, ClientProfile,
    SignatureNegotiationStatus, ExtensionMap, SecurityScore
};
pub use handshake::HandshakeEngine;
pub use output::output_results;
pub use detector::PqcDetector;
pub use output::OutputFormatter;
pub use signature_detector::SignatureDetector;
pub use security_scoring::SecurityScorer; 