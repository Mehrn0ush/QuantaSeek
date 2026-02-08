use serde::{Deserialize, Serialize};

/// Handshake configuration for timeout and retry settings
#[derive(Debug, Clone, Copy)]
pub struct HandshakeConfig {
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
    /// Number of retry attempts for fallback
    pub retry_attempts: u32,
    /// Retry backoff multiplier (exponential backoff: delay = base_ms * (multiplier ^ attempt))
    pub retry_backoff_multiplier: u32,
    /// Base retry delay in milliseconds
    pub retry_base_delay_ms: u64,
    /// Enable performance optimizations
    pub enable_optimizations: bool,
    /// Enable TLS 1.2 fallback for certificate analysis
    pub tls12_fallback_enabled: bool,
    /// Always attempt TLS 1.2 fallback (not based on hostname)
    pub always_attempt_tls12_fallback: bool,
    /// Always query CT logs (not based on hostname)
    pub always_query_ct_logs: bool,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            retry_attempts: 3,
            retry_backoff_multiplier: 2,
            retry_base_delay_ms: 100,
            enable_optimizations: true,
            tls12_fallback_enabled: false,
            always_attempt_tls12_fallback: false,
            always_query_ct_logs: false,
        }
    }
}

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

impl std::str::FromStr for HandshakeProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "maxpqc" | "max-pqc" | "pqc-only" | "pqconly" | "pqc" => Ok(HandshakeProfile::PqcOnly),
            "hybrid" | "hybridpqc" | "hybrid-pqc" => Ok(HandshakeProfile::HybridPqc),
            "standard" | "classic" => Ok(HandshakeProfile::Standard),
            "cloudflare" | "cloudflarepqc" | "cloudflare-pqc" | "fallback" => {
                Ok(HandshakeProfile::CloudflarePqc)
            }
            other => Err(format!(
                "Unknown profile: {}. Valid values: standard, cloudflare-pqc, hybrid-pqc, pqc-only",
                other
            )),
        }
    }
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

    /// Get CLI argument name for the profile
    pub fn cli_name(&self) -> &'static str {
        match self {
            ClientProfile::Classic => "classic",
            ClientProfile::Hybrid => "hybrid",
            ClientProfile::Fallback => "fallback",
            ClientProfile::MaxPqc => "max-pqc",
        }
    }

    /// Get consistent display name (matches CLI arguments)
    pub fn consistent_display_name(&self) -> &'static str {
        match self {
            ClientProfile::Classic => "Classic",
            ClientProfile::Hybrid => "Hybrid",
            ClientProfile::Fallback => "Fallback",
            ClientProfile::MaxPqc => "MaxPQC",
        }
    }
}

/// Early Data (0-RTT) support status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum EarlyDataStatus {
    #[serde(rename = "not_offered")]
    #[default]
    NotOffered,
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "rejected")]
    Rejected,
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
    /// Public key algorithm of this certificate (e.g., "ECDSA", "RSA")
    pub public_key_algorithm: String,
    /// Signature algorithm used by the ISSUER to sign this certificate (e.g., "RSA-SHA256")
    /// Note: This is the issuer's signature algorithm, not the certificate's own key algorithm.
    /// It is normal for an ECDSA public key to be signed with RSA (or vice versa).
    pub signature_algorithm: String,
    /// OID of the signature algorithm (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256)
    /// This is used for PQC detection via constants::is_pqc_oid()
    /// FIXED: Always serialize OID - remove skip_serializing_if to ensure field is always present in JSON
    pub signature_algorithm_oid: Option<String>,
    pub key_size: Option<u32>,
    pub valid_from: String,
    pub valid_to: String,
    /// Subject Alternative Names (DNS entries)
    pub san: Option<String>,
    /// Estimated certificate length in bytes (DER format)
    pub certificate_length_estimate: Option<u32>,
    /// Whether the certificate's public key algorithm and issuer's signature algorithm
    /// form a valid combination. Returns true for normal combinations (e.g., ECDSA key
    /// with RSA signature is valid and common in practice).
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
    /// PQC signature usage status. None when status is Unknown (TLS 1.3 encrypted), Some(true/false) when known
    pub pqc_signature_used: Option<bool>,
    pub tls_features: TlsFeatures,
    pub handshake_duration_ms: Option<u64>,
    pub client_profile_used: HandshakeProfile,
    pub extension_map: ExtensionMap,
    /// Connection type: "tls" for TCP/TLS, "quic" for QUIC. Enables filtering in reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    /// Reason when cipher_suite is "unknown", e.g. "no_server_hello_available" for QUIC without fallback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite_reason: Option<String>,
}

/// PQC Analysis results
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
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
    /// PQC signature usage status. None when status is Unknown (TLS 1.3 encrypted), Some(true/false) when known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_signature_used: Option<bool>,
    pub pqc_signature_algorithm: Option<String>,
    pub signature_negotiation_status: SignatureNegotiationStatus,
    pub server_endpoint_fingerprint: Option<String>,
    /// Detailed KEM negotiation information
    pub kem_negotiation: Option<KemNegotiation>,
    /// PQC extension usage details
    pub extension_usage: Option<ExtensionUsage>,
    /// Hybrid combination analysis
    pub hybrid_details: Option<HybridDetails>,
}

/// Signature negotiation status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum SignatureNegotiationStatus {
    Negotiated,
    NotOffered,
    Rejected,
    #[default]
    Unknown,
    NotApplicable,
}

/// Output format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "csv")]
    Csv,
}

/// Fallback testing information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FallbackInfo {
    /// Whether profile fallback is enabled (fallback chain is available)
    pub enabled: bool,
    /// Whether profile fallback was actually used (switched to a different profile)
    pub used: bool,
    /// Time penalty for fallback attempts (in milliseconds)
    pub fallback_penalty_ms: Option<u64>,
    /// Number of profile fallback attempts made (excluding the initial attempt)
    /// If 0, no fallback occurred; if > 0, that many fallback attempts were made
    pub attempts_count: u32,
    /// List of profiles attempted in order (only populated if fallback was used)
    pub attempted_profiles: Vec<String>,
    /// TLS 1.2 fallback information (separate from profile fallback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls12_fallback: Option<Tls12FallbackInfo>,
}

/// TLS 1.2 fallback information (separate from profile fallback)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tls12FallbackInfo {
    /// Whether TLS 1.2 fallback is enabled
    pub enabled: bool,
    /// Whether TLS 1.2 was actually used (tls_version == "1.2")
    pub used: bool,
    /// Whether TLS 1.2 fallback was attempted for certificate extraction
    pub attempted_for_certificate: bool,
}

/// HTTP redirect information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpRedirectInfo {
    /// Whether HTTP redirect was detected
    pub detected: bool,
    /// Redirect status code (307, 308, 301, 302, etc.)
    pub status_code: Option<u16>,
    /// Redirect chain (initial URL → final URL)
    pub redirect_chain: Vec<String>,
    /// Final destination URL after all redirects
    pub final_destination: Option<String>,
    /// Certificate from final destination (if different from initial)
    pub final_destination_certificate: Option<CertificateInfo>,
    /// Number of redirects followed
    pub redirect_count: u32,
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
    /// HTTP redirect information (if redirects were detected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_redirect: Option<HttpRedirectInfo>,
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
    /// Raw ServerHello message bytes for PQC detection
    pub raw_server_hello: Vec<u8>,
    /// Connection type: "tls" or "quic". Present when set from handshake for filtering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    /// Reason for cipher_suite "unknown", e.g. "no_server_hello_available".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite_reason: Option<String>,
}

/// Extension negotiation status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum ExtensionStatus {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "not_present")]
    #[default]
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
    pub fn update_from_client_hello(
        &mut self,
        _offered_extensions: &std::collections::HashSet<u16>,
    ) {
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityScore {
    /// TLS protocol security score (0-100)
    pub tls: u8,
    /// Certificate security score (0-100). Treat as "no data" when certificate_visible is false (suggestion 8.3).
    pub certificate: u8,
    /// PQC implementation score (0-100)
    pub pqc: u8,
    /// Overall security score (0-100)
    pub overall: u8,
    /// When certificate_visible is false, overall excluding certificate (TLS + PQC only) for comparable metrics (suggestion 8.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_without_certificate: Option<u8>,
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OverallWeights {
    pub tls_percentage: u8,
    pub certificate_percentage: u8,
    pub pqc_percentage: u8,
}

/// TLS component weights
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TlsWeights {
    pub version_percentage: u8,
    pub cipher_percentage: u8,
    pub key_exchange_percentage: u8,
}

/// Certificate component weights
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CertificateWeights {
    pub validation_percentage: u8,
    pub key_strength_percentage: u8,
}

/// PQC component weights
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PqcWeights {
    pub algorithm_percentage: u8,
    pub implementation_percentage: u8,
    pub hybrid_percentage: u8,
}

/// PQC algorithm security strength information
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

/// Detailed KEM negotiation information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KemNegotiation {
    /// KEMs offered by the client in order of preference
    pub client_offered: Vec<KemCandidate>,
    /// KEM selected by the server
    pub server_selected: Option<KemCandidate>,
    /// Negotiation order and priority
    pub negotiation_order: Vec<String>,
    /// Whether the server's selection matches client's preference
    pub preference_matched: bool,
    /// Number of KEM candidates offered
    pub total_candidates: u32,
}

/// Individual KEM candidate information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KemCandidate {
    pub name: String,
    pub security_bits: u32,
    pub nist_level: String,
    pub priority: u32, // Lower number = higher priority
    pub status: KemStatus,
}

/// KEM negotiation status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum KemStatus {
    #[serde(rename = "offered")]
    Offered,
    #[serde(rename = "selected")]
    Selected,
    #[serde(rename = "rejected")]
    Rejected,
    #[serde(rename = "fallback")]
    Fallback,
}

/// PQC extension usage details
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExtensionUsage {
    /// Extensions offered by the client
    pub client_offered: Vec<ExtensionInfo>,
    /// Extensions actually used in the handshake
    pub server_used: Vec<ExtensionInfo>,
    /// Extensions that were rejected or ignored
    pub rejected: Vec<ExtensionInfo>,
    /// Total number of PQC-related extensions
    pub total_pqc_extensions: u32,
    /// Whether all offered PQC extensions were accepted
    pub full_pqc_support: bool,
}

/// Individual extension information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExtensionInfo {
    pub name: String,
    pub extension_type: u16,
    pub status: ExtensionStatus,
    pub data_length: Option<u32>,
    pub pqc_related: bool,
}

/// Hybrid combination analysis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HybridDetails {
    /// Classical and PQC algorithms in the hybrid
    pub combination: Vec<HybridComponent>,
    /// Combined security strength calculation
    pub combined_security: CombinedSecurity,
    /// Fallback path analysis
    pub fallback_analysis: Option<FallbackAnalysis>,
    /// Hybrid efficiency metrics
    pub efficiency: HybridEfficiency,
}

/// Individual component in hybrid combination
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HybridComponent {
    pub name: String,
    pub algorithm_type: AlgorithmType,
    pub security_bits: u32,
    pub nist_level: String,
    pub weight: f32, // Contribution to overall security
}

/// Algorithm type classification
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AlgorithmType {
    #[serde(rename = "classical")]
    Classical,
    #[serde(rename = "pqc")]
    Pqc,
    #[serde(rename = "hybrid")]
    Hybrid,
}

/// Combined security strength calculation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CombinedSecurity {
    /// Effective security bits of the hybrid combination
    pub effective_bits: u32,
    /// NIST security level of the combination
    pub nist_level: String,
    /// Security score (0-100)
    pub score: u8,
    /// Calculation method used
    pub calculation_method: String,
    /// Whether the combination provides quantum resistance
    pub quantum_resistant: bool,
}

/// Fallback path analysis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FallbackAnalysis {
    /// Classical algorithms used in fallback
    pub classical_algorithms: Vec<String>,
    /// Security strength of fallback path
    pub fallback_security_bits: u32,
    /// Time penalty for fallback (ms)
    pub time_penalty_ms: Option<u64>,
    /// Whether fallback was successful
    pub successful: bool,
    /// Fallback trigger reason
    pub trigger_reason: Option<String>,
}

/// Hybrid efficiency metrics
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HybridEfficiency {
    /// Handshake overhead compared to classical-only
    pub handshake_overhead_ms: Option<i64>,
    /// Bandwidth overhead (bytes)
    pub bandwidth_overhead_bytes: Option<u32>,
    /// CPU usage increase percentage
    pub cpu_overhead_percent: Option<f32>,
    /// Memory usage increase (bytes)
    pub memory_overhead_bytes: Option<u32>,
}
