use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Handshake configuration for timeout and retry settings
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Trust anchors for chain validation. `None` uses the webpki-roots bundle.
    pub trust_anchors: Option<std::sync::Arc<rustls::RootCertStore>>,
    /// Handshake read/write timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            trust_anchors: None,
            timeout_ms: 5000,
        }
    }
}

/// Client profile: which key-exchange groups the ClientHello offers.
///
/// Each profile is built only from groups the linked rustls (0.23.46) and
/// aws-lc-rs (1.19.0) providers implement; see `rustls::crypto::aws_lc_rs::
/// kx_group` and `ALL_KX_GROUPS` in the rustls source. Groups are offered in
/// the order listed; rustls sends a key share for the first one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum HandshakeProfile {
    /// rustls defaults: X25519MLKEM768, x25519, secp256r1, secp384r1 (TLS 1.3, 1.2)
    Default,
    /// Classical ECDHE only: x25519, secp256r1, secp384r1 (TLS 1.3, 1.2)
    Classical,
    /// Hybrid ML-KEM only: X25519MLKEM768, SecP256r1MLKEM768 (TLS 1.3)
    Hybrid,
    /// Pure ML-KEM only: MLKEM1024, MLKEM768 (TLS 1.3)
    Mlkem,
    /// Every group rustls supports: hybrids, pure ML-KEM, then classical (TLS 1.3, 1.2)
    All,
}

impl HandshakeProfile {
    pub const ALL_PROFILES: [HandshakeProfile; 5] = [
        HandshakeProfile::Default,
        HandshakeProfile::Classical,
        HandshakeProfile::Hybrid,
        HandshakeProfile::Mlkem,
        HandshakeProfile::All,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            HandshakeProfile::Default => "default",
            HandshakeProfile::Classical => "classical",
            HandshakeProfile::Hybrid => "hybrid",
            HandshakeProfile::Mlkem => "mlkem",
            HandshakeProfile::All => "all",
        }
    }

    /// Key-exchange groups offered, in preference order.
    pub fn kx_groups(&self) -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
        use rustls::crypto::aws_lc_rs::kx_group::*;
        match self {
            HandshakeProfile::Default => vec![X25519MLKEM768, X25519, SECP256R1, SECP384R1],
            HandshakeProfile::Classical => vec![X25519, SECP256R1, SECP384R1],
            HandshakeProfile::Hybrid => vec![X25519MLKEM768, SECP256R1MLKEM768],
            HandshakeProfile::Mlkem => vec![MLKEM1024, MLKEM768],
            HandshakeProfile::All => vec![
                X25519MLKEM768,
                SECP256R1MLKEM768,
                MLKEM1024,
                MLKEM768,
                X25519,
                SECP256R1,
                SECP384R1,
            ],
        }
    }

    /// IANA names of the offered groups, in preference order.
    pub fn offered_group_names(&self) -> Vec<String> {
        self.kx_groups()
            .iter()
            .map(|g| crate::constants::get_group_name(u16::from(g.name())))
            .collect()
    }

    /// True if every offered group is post-quantum, so only TLS 1.3 is offered.
    pub fn tls13_only(&self) -> bool {
        self.kx_groups()
            .iter()
            .all(|g| crate::constants::is_pqc_group(u16::from(g.name())))
    }
}

impl std::str::FromStr for HandshakeProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.to_ascii_lowercase();
        if let Some(p) = Self::ALL_PROFILES.iter().find(|p| p.name() == wanted) {
            return Ok(*p);
        }
        let names: Vec<&str> = Self::ALL_PROFILES.iter().map(|p| p.name()).collect();
        Err(format!(
            "unknown profile '{}'. Valid profiles: {}",
            s,
            names.join(", ")
        ))
    }
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// One JSON object per target, one per line (JSON Lines).
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "text")]
    Text,
}

/// Stable, machine-readable error codes for scan failures.
/// Used in the JSON error schema so consumers can rely on fixed codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Connection refused (server not listening or not reachable)
    ConnectionRefused,
    /// Connection timed out
    ConnectionTimeout,
    /// DNS resolution failed
    DnsFailed,
    /// Connection reset by peer
    ConnectionReset,
    /// Permission denied (e.g. binding port)
    PermissionDenied,
    /// Generic connection failure (all ports failed)
    ConnectionFailed,
    /// Handshake failed for a reason not classified below
    HandshakeFailed,
    /// The server answered our ClientHello with a fatal alert
    HandshakeRejected,
    /// The server's certificate chain did not validate
    CertificateRejected,
    /// The server sent a message rustls considers invalid or incompatible
    ProtocolError,
    /// The server accepted TCP but did not complete the handshake in time
    HandshakeTimeout,
    /// The server closed the connection during the handshake
    ConnectionClosed,
    /// Scan failed (generic; used in batch when no specific code applies)
    ScanFailed,
    /// The target string could not be parsed
    InvalidTarget,
    /// Unknown or uncategorized error
    Unknown,
}

impl ErrorCode {
    /// Human-readable default message for this code
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::ConnectionRefused => {
                "Connection refused - server may be offline or not listening on TLS ports"
            }
            ErrorCode::ConnectionTimeout => "Connection timeout - server may be slow or overloaded",
            ErrorCode::DnsFailed => "DNS resolution failed - check hostname spelling",
            ErrorCode::ConnectionReset => {
                "Connection reset - server may not support the requested TLS configuration"
            }
            ErrorCode::PermissionDenied => "Permission denied - may need elevated privileges",
            ErrorCode::ConnectionFailed => "Standard TLS connection failed",
            ErrorCode::HandshakeRejected => "Server rejected the handshake with a fatal alert",
            ErrorCode::CertificateRejected => "Server certificate chain did not validate",
            ErrorCode::ProtocolError => "Server response was invalid or incompatible",
            ErrorCode::HandshakeTimeout => "Server did not complete the handshake in time",
            ErrorCode::ConnectionClosed => "Server closed the connection during the handshake",
            ErrorCode::HandshakeFailed => {
                "Handshake failed - server may not support the requested TLS configuration"
            }
            ErrorCode::ScanFailed => "Scan failed",
            ErrorCode::InvalidTarget => "Target could not be parsed",
            ErrorCode::Unknown => "Unknown connection error",
        }
    }

    /// Whether this outcome describes the network, the server, or the scanner.
    pub fn category(&self) -> ErrorCategory {
        match self {
            ErrorCode::HandshakeRejected
            | ErrorCode::CertificateRejected
            | ErrorCode::ProtocolError
            | ErrorCode::ConnectionClosed => ErrorCategory::ServerResult,
            ErrorCode::ConnectionRefused
            | ErrorCode::ConnectionTimeout
            | ErrorCode::DnsFailed
            | ErrorCode::ConnectionReset
            | ErrorCode::ConnectionFailed
            | ErrorCode::HandshakeTimeout => ErrorCategory::Network,
            ErrorCode::PermissionDenied
            | ErrorCode::HandshakeFailed
            | ErrorCode::ScanFailed
            | ErrorCode::InvalidTarget
            | ErrorCode::Unknown => ErrorCategory::Scanner,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::ConnectionRefused => write!(f, "connection_refused"),
            ErrorCode::ConnectionTimeout => write!(f, "connection_timeout"),
            ErrorCode::DnsFailed => write!(f, "dns_failed"),
            ErrorCode::ConnectionReset => write!(f, "connection_reset"),
            ErrorCode::PermissionDenied => write!(f, "permission_denied"),
            ErrorCode::ConnectionFailed => write!(f, "connection_failed"),
            ErrorCode::HandshakeFailed => write!(f, "handshake_failed"),
            ErrorCode::HandshakeRejected => write!(f, "handshake_rejected"),
            ErrorCode::CertificateRejected => write!(f, "certificate_rejected"),
            ErrorCode::ProtocolError => write!(f, "protocol_error"),
            ErrorCode::HandshakeTimeout => write!(f, "handshake_timeout"),
            ErrorCode::ConnectionClosed => write!(f, "connection_closed"),
            ErrorCode::ScanFailed => write!(f, "scan_failed"),
            ErrorCode::InvalidTarget => write!(f, "invalid_target"),
            ErrorCode::Unknown => write!(f, "unknown"),
        }
    }
}

/// What an unsuccessful outcome tells us about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// The server responded, and the response is itself a scan result
    /// (e.g. it rejected every group the profile offered).
    ServerResult,
    /// No usable response: DNS, TCP, or a timeout.
    Network,
    /// A failure inside the scanner or an unclassified error.
    Scanner,
}

/// A statement the scanner inferred rather than observed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Inference {
    /// Always "inferred".
    pub provenance: String,
    pub statement: String,
}

impl Inference {
    pub fn new(statement: impl Into<String>) -> Self {
        Self {
            provenance: "inferred".to_string(),
            statement: statement.into(),
        }
    }
}

/// Structured error information for a scan (stable JSON schema).
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanError {
    /// Stable, machine-readable error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Context: ports tried, profile, offered groups
    pub details: Option<String>,
    /// Whether the outcome describes the server, the network, or the scanner
    pub category: ErrorCategory,
    /// Fatal TLS alert received from the server, if any (observed)
    pub alert: Option<String>,
    /// Likely cause, when the scanner can only infer it
    pub interpretation: Option<Inference>,
}

impl ScanError {
    /// Build a ScanError from a stable ErrorCode with optional context in details.
    pub fn from_code(code: ErrorCode, details: Option<String>) -> Self {
        Self::from_code_with_message(code, code.default_message().to_string(), details)
    }

    /// Build with a custom message (e.g. from underlying error string) but stable code.
    pub fn from_code_with_message(
        code: ErrorCode,
        message: String,
        details: Option<String>,
    ) -> Self {
        ScanError {
            code: code.to_string(),
            message,
            details,
            category: code.category(),
            alert: None,
            interpretation: None,
        }
    }
}
