use serde::{Serialize, Deserialize};

/// TLS Handshake Profile for different server configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeProfile {
    /// Standard TLS 1.3 with classical algorithms only
    Standard,
    /// Cloudflare PQC-enabled server profile
    CloudflarePqc,
    /// Hybrid PQC with classical fallback
    HybridPqc,
    /// PQC-only configuration (experimental)
    PqcOnly,
}

/// Client Profile for different scanning strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientProfile {
    /// Classic client - only classical algorithms
    Classic,
    /// Hybrid client - PQC + classical fallback
    Hybrid,
    /// Fallback client - starts with PQC, falls back to classical
    Fallback,
    /// Maximum PQC client - PQC-only algorithms
    MaxPqc,
}

impl ClientProfile {
    /// Convert to HandshakeProfile for backward compatibility
    pub fn to_handshake_profile(&self) -> HandshakeProfile {
        match self {
            ClientProfile::Classic => HandshakeProfile::Standard,
            ClientProfile::Hybrid => HandshakeProfile::HybridPqc,
            ClientProfile::Fallback => HandshakeProfile::CloudflarePqc,
            ClientProfile::MaxPqc => HandshakeProfile::PqcOnly,
        }
    }
    
    /// Get display name for the profile
    pub fn display_name(&self) -> &'static str {
        match self {
            ClientProfile::Classic => "Classic",
            ClientProfile::Hybrid => "Hybrid",
            ClientProfile::Fallback => "Fallback",
            ClientProfile::MaxPqc => "MaxPQC",
        }
    }
}

/// Early Data (0-RTT) support status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum EarlyDataStatus {
    #[serde(rename = "not_offered")]
    NotOffered,
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "rejected")]
    Rejected,
}

impl Default for EarlyDataStatus {
    fn default() -> Self {
        Self::NotOffered
    }
}

/// TLS Features detected during handshake
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct TlsFeatures {
    pub alpn: Option<String>,
    pub early_data_status: EarlyDataStatus,
    pub session_ticket: Option<bool>,
    pub ocsp_stapling: bool,
}

/// PQC Extensions detected in handshake
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct PqcExtensions {
    pub kem: bool,
    pub kem_group: bool,
}

/// Certificate information (when visible)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub key_size: Option<u32>,
}

/// Complete handshake analysis result
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResult {
    pub target: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub key_exchange: Vec<String>,
    pub pqc_extensions: PqcExtensions,
    pub certificate_info: Option<CertificateInfo>,
    pub raw_server_hello: Vec<u8>,
    pub raw_certificate: Vec<u8>,
    pub alert_info: Option<String>,
    pub certificate_visible: bool,
    pub handshake_complete: bool,
    pub pqc_signature_algorithms: Vec<String>,
    pub tls_features: TlsFeatures,
    pub handshake_duration_ms: Option<u64>,
    pub client_profile_used: HandshakeProfile,
}

/// PQC Analysis results
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PqcAnalysis {
    pub tls_version: String,
    pub cipher_suite: String,
    pub key_exchange: String,
    pub pqc_detected: bool,
    pub pqc_key_exchange: Vec<String>,
    pub pqc_signature_algorithms: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pqc_signature_status: String,
    pub pqc_public_key_algorithms: Vec<String>,
    pub pqc_extensions: Vec<String>,
    pub security_features: Vec<String>,
    pub security_level: String,
    pub hybrid_detected: bool,
    pub classical_fallback_available: bool,
    pub pqc_signature_used: bool,
    pub pqc_signature_algorithm: Option<String>,
    pub certificate_length_estimate: Option<u32>,
    pub signature_negotiation_status: SignatureNegotiationStatus,
    pub server_endpoint_fingerprint: Option<String>,
}

/// Signature negotiation status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SignatureNegotiationStatus {
    #[serde(rename = "negotiated")]
    Negotiated,
    #[serde(rename = "not_offered")]
    NotOffered,
    #[serde(rename = "rejected")]
    Rejected,
    #[serde(rename = "unknown")]
    Unknown,
}

impl Default for SignatureNegotiationStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Output format options
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Stdout,
}

/// Fallback testing information
#[derive(Debug, Serialize, Deserialize)]
pub struct FallbackInfo {
    pub attempted: bool,
    pub succeeded: bool,
    /// Time penalty for fallback attempts (in milliseconds)
    pub fallback_penalty_ms: Option<u64>,
    /// Number of fallback attempts made
    pub attempts_count: u32,
    /// List of profiles attempted in order
    pub attempted_profiles: Vec<String>,
}

/// Complete scan result with all analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub key_exchange: Vec<String>,
    pub pqc_extensions: PqcExtensions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateInfo>,
    pub tls_features: TlsFeatures,
    pub certificate_visible: bool,
    pub handshake_complete: bool,
    pub pqc_detected: bool,
    pub fallback: FallbackInfo,
    pub analysis: PqcAnalysis,
    pub handshake_duration_ms: Option<u64>,
    pub client_profile_used: String,
    /// Total scan duration including all attempts
    pub total_scan_duration_ms: Option<u64>,
    /// Whether adaptive fingerprinting was used
    pub adaptive_fingerprinting: bool,
    /// Server fingerprint based on response patterns
    pub server_fingerprint: Option<String>,
} 