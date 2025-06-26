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
    /// ALPN protocols negotiated (empty array if none offered)
    pub alpn: Option<Vec<String>>,
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
    pub issuer: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub key_size: Option<u32>,
    pub valid_from: String,
    pub valid_to: String,
    /// Subject Alternative Names (DNS entries)
    pub san: Option<String>,
    /// Estimated certificate length in bytes (DER format)
    pub certificate_length_estimate: Option<u32>,
    /// Whether public key and signature algorithms are consistent
    pub algorithm_consistency: bool,
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
    pub extension_map: ExtensionMap,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "text")]
    Text,
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

/// Warning level for security issues
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum WarningLevel {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warning")]
    Warning,
    #[serde(rename = "critical")]
    Critical,
}

impl std::fmt::Display for WarningLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarningLevel::Info => write!(f, "info"),
            WarningLevel::Warning => write!(f, "warning"),
            WarningLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Security warning or recommendation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityWarning {
    pub level: WarningLevel,
    pub category: String,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Performance warning
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PerformanceWarning {
    pub level: WarningLevel,
    pub category: String,
    pub message: String,
    pub impact: String,
    pub recommendation: Option<String>,
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
    /// Extension negotiation mapping
    pub extension_map: ExtensionMap,
    /// Security scoring assessment
    pub security_score: SecurityScore,
    /// Security warnings and recommendations
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<SecurityWarning>,
    /// Performance warnings and recommendations
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub performance_warnings: Vec<PerformanceWarning>,
}

/// Extension negotiation status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ExtensionStatus {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "not_present")]
    NotPresent,
    #[serde(rename = "encrypted")]
    Encrypted,
    #[serde(rename = "not_offered")]
    NotOffered,
    #[serde(rename = "negotiated")]
    Negotiated(String), // Contains the negotiated value
    #[serde(rename = "not_applicable")]
    NotApplicable, // Extension doesn't exist in this TLS version
}

impl Default for ExtensionStatus {
    fn default() -> Self {
        Self::NotPresent
    }
}

/// Extension negotiation mapping
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct ExtensionMap {
    pub key_share: bool,
    pub supported_versions: bool,
    pub signature_algorithms: bool,
    /// ALPN protocols negotiated (empty array if none)
    pub alpn_protocols: Vec<String>,
    pub ocsp_stapling: bool,
    pub session_ticket: bool,
    pub psk_key_exchange_modes: bool,
    pub early_data: bool,
    pub pre_shared_key: bool,
}

impl ExtensionMap {
    pub fn update_from_client_hello(&mut self, _offered_extensions: &std::collections::HashSet<u16>) {
        // This method is called to track which extensions were offered in ClientHello
        // For now, we don't need to do anything with this information
        // as we're using the real negotiated extensions from the handshake
    }
}

/// Security scoring for quantitative assessment
/// 
/// Scoring Formula:
/// - Overall = TLS(30%) + Certificate(25%) + PQC(45%) for PQC-enabled connections
/// - Overall = TLS(50%) + Certificate(50%) for classical connections
/// 
/// TLS Component = Version(40%) + Cipher(30%) + KeyExchange(30%)
/// Certificate Component = (Validation + KeyStrength) / 2
/// PQC Component = (Algorithm + Implementation + Hybrid) / 3
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityScore {
    /// TLS protocol security score (0-100)
    pub tls: u8,
    /// Certificate security score (0-100)
    pub certificate: u8,
    /// PQC implementation score (0-100)
    pub pqc: u8,
    /// Overall security score (0-100)
    pub overall: u8,
    /// Detailed scoring breakdown
    pub details: SecurityScoreDetails,
    /// Scoring formula explanation
    pub formula: ScoringFormula,
    /// Explicit weights used in calculations
    pub weights: ScoringWeights,
    /// PQC algorithm security levels
    pub pqc_strength: PqcStrengthInfo,
}

/// Explanation of how scores are calculated
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScoringFormula {
    /// Overall score calculation method
    pub overall_method: String,
    /// TLS component calculation
    pub tls_method: String,
    /// Certificate component calculation  
    pub certificate_method: String,
    /// PQC component calculation
    pub pqc_method: String,
    /// Weighting for PQC-enabled connections
    pub pqc_weights: String,
    /// Weighting for classical connections
    pub classical_weights: String,
}

/// Detailed security scoring breakdown
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityScoreDetails {
    /// TLS version score (TLS 1.3 = 100, TLS 1.2 = 60, TLS 1.1 = 20, TLS 1.0 = 0)
    pub tls_version: u8,
    /// Cipher suite strength score
    pub cipher_suite: u8,
    /// Key exchange security score
    pub key_exchange: u8,
    /// Certificate validation score
    pub certificate_validation: u8,
    /// Certificate key strength score
    pub certificate_key_strength: u8,
    /// PQC algorithm security score
    pub pqc_algorithm: u8,
    /// PQC implementation completeness score
    pub pqc_implementation: u8,
    /// Hybrid security score
    pub hybrid_security: u8,
}

/// Explicit weights used in security scoring
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScoringWeights {
    /// Overall score weights for PQC-enabled connections
    pub overall_pqc: OverallWeights,
    /// Overall score weights for classical connections
    pub overall_classical: OverallWeights,
    /// TLS component weights
    pub tls_component: TlsWeights,
    /// Certificate component weights
    pub certificate_component: CertificateWeights,
    /// PQC component weights
    pub pqc_component: PqcWeights,
}

/// Overall scoring weights
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverallWeights {
    pub tls_percentage: u8,
    pub certificate_percentage: u8,
    pub pqc_percentage: u8,
}

/// TLS component weights
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsWeights {
    pub version_percentage: u8,
    pub cipher_percentage: u8,
    pub key_exchange_percentage: u8,
}

/// Certificate component weights
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateWeights {
    pub validation_percentage: u8,
    pub key_strength_percentage: u8,
}

/// PQC component weights
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PqcWeights {
    pub algorithm_percentage: u8,
    pub implementation_percentage: u8,
    pub hybrid_percentage: u8,
}

/// PQC algorithm security strength information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PqcStrengthInfo {
    /// Detected PQC algorithms with their security levels
    pub algorithms: Vec<PqcAlgorithmInfo>,
    /// Overall PQC security level
    pub overall_level: String,
    /// Security bits provided
    pub security_bits: u32,
    /// NIST security level
    pub nist_level: String,
}

/// Individual PQC algorithm information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PqcAlgorithmInfo {
    pub name: String,
    pub security_bits: u32,
    pub nist_level: String,
    pub score: u8,
}

impl Default for SecurityScore {
    fn default() -> Self {
        Self {
            tls: 0,
            certificate: 0,
            pqc: 0,
            overall: 0,
            details: SecurityScoreDetails::default(),
            formula: ScoringFormula::default(),
            weights: ScoringWeights::default(),
            pqc_strength: PqcStrengthInfo::default(),
        }
    }
}

impl Default for SecurityScoreDetails {
    fn default() -> Self {
        Self {
            tls_version: 0,
            cipher_suite: 0,
            key_exchange: 0,
            certificate_validation: 0,
            certificate_key_strength: 0,
            pqc_algorithm: 0,
            pqc_implementation: 0,
            hybrid_security: 0,
        }
    }
}

impl Default for ScoringFormula {
    fn default() -> Self {
        Self {
            overall_method: String::new(),
            tls_method: String::new(),
            certificate_method: String::new(),
            pqc_method: String::new(),
            pqc_weights: String::new(),
            classical_weights: String::new(),
        }
    }
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            overall_pqc: OverallWeights::default(),
            overall_classical: OverallWeights::default(),
            tls_component: TlsWeights::default(),
            certificate_component: CertificateWeights::default(),
            pqc_component: PqcWeights::default(),
        }
    }
}

impl Default for OverallWeights {
    fn default() -> Self {
        Self {
            tls_percentage: 0,
            certificate_percentage: 0,
            pqc_percentage: 0,
        }
    }
}

impl Default for TlsWeights {
    fn default() -> Self {
        Self {
            version_percentage: 0,
            cipher_percentage: 0,
            key_exchange_percentage: 0,
        }
    }
}

impl Default for CertificateWeights {
    fn default() -> Self {
        Self {
            validation_percentage: 0,
            key_strength_percentage: 0,
        }
    }
}

impl Default for PqcWeights {
    fn default() -> Self {
        Self {
            algorithm_percentage: 0,
            implementation_percentage: 0,
            hybrid_percentage: 0,
        }
    }
}

impl Default for PqcStrengthInfo {
    fn default() -> Self {
        Self {
            algorithms: Vec::new(),
            overall_level: String::new(),
            security_bits: 0,
            nist_level: String::new(),
        }
    }
} 