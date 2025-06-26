use crate::types::{HandshakeResult, PqcAnalysis, SignatureNegotiationStatus};
use crate::signature_detector::SignatureDetector;

pub struct PqcDetector {
    signature_detector: SignatureDetector,
}

impl PqcDetector {
    pub fn new() -> Self {
        Self {
            signature_detector: SignatureDetector::new(),
        }
    }

    /// Determines if PQC is detected based on handshake results
    pub fn detect_pqc(&self, handshake_result: &HandshakeResult) -> bool {
        // If TLS 1.2 is detected, PQC is not possible
        if handshake_result.tls_version == "1.2" {
            return false;
        }
        
        self.detect_pqc_key_exchange(handshake_result) ||
        self.detect_pqc_extensions(handshake_result) ||
        self.detect_pqc_certificate(handshake_result)
    }

    /// Detects PQC algorithms in key exchange
    fn detect_pqc_key_exchange(&self, handshake_result: &HandshakeResult) -> bool {
        handshake_result.key_exchange.iter().any(|kex| {
            self.is_pqc_key_exchange(kex)
        })
    }

    /// Detects PQC-related extensions
    fn detect_pqc_extensions(&self, handshake_result: &HandshakeResult) -> bool {
        handshake_result.pqc_extensions.kem || handshake_result.pqc_extensions.kem_group
    }

    /// Detects PQC algorithms in certificate
    fn detect_pqc_certificate(&self, handshake_result: &HandshakeResult) -> bool {
        if let Some(ref cert_info) = handshake_result.certificate_info {
            self.is_pqc_signature_algorithm(&cert_info.signature_algorithm) ||
            self.is_pqc_public_key_algorithm(&cert_info.public_key_algorithm)
        } else {
            false
        }
    }

    /// Checks if a key exchange algorithm is post-quantum
    fn is_pqc_key_exchange(&self, kex: &str) -> bool {
        matches!(kex.to_lowercase().as_str(),
            "kyber1024" | "kyber768" | "kyber512" |
            "ntru" | "ntru_hps" | "ntru_hrss" |
            "saber" | "lightsaber" | "firesaber" |
            "frodo" | "frodokem" | "frodo640" | "frodo976" |
            "bike" | "hqc" | "mceliece" | "classic_mceliece" |
            "sidh" | "sike" // Note: SIDH/SIKE are broken but included for completeness
        )
    }

    /// Checks if a signature algorithm is post-quantum
    fn is_pqc_signature_algorithm(&self, sig_alg: &str) -> bool {
        let normalized = sig_alg.to_lowercase();
        
        // Dilithium family
        if normalized.contains("dilithium") {
            return true;
        }
        
        // Falcon family
        if normalized.contains("falcon") {
            return true;
        }
        
        // SPHINCS+ family
        if normalized.contains("sphincs") || normalized.contains("sphincsplus") {
            return true;
        }
        
        // Rainbow (broken, but historically relevant)
        if normalized.contains("rainbow") {
            return true;
        }
        
        // PICNIC family
        if normalized.contains("picnic") {
            return true;
        }
        
        // XMSS/LMS hash-based signatures
        if normalized.contains("xmss") || normalized.contains("lms") {
            return true;
        }
        
        false
    }

    /// Checks if a public key algorithm is post-quantum
    fn is_pqc_public_key_algorithm(&self, pub_key_alg: &str) -> bool {
        let normalized = pub_key_alg.to_lowercase();
        
        // Key encapsulation mechanisms
        if normalized.contains("kyber") ||
           normalized.contains("ntru") ||
           normalized.contains("saber") ||
           normalized.contains("frodo") ||
           normalized.contains("bike") ||
           normalized.contains("hqc") ||
           normalized.contains("mceliece") {
            return true;
        }
        
        // Signature algorithms that can also be public key algorithms
        if self.is_pqc_signature_algorithm(pub_key_alg) {
            return true;
        }
        
        false
    }

    /// Provides detailed analysis of PQC support
    pub fn analyze_pqc_support(&self, handshake_result: &HandshakeResult) -> PqcAnalysis {
        let mut analysis = PqcAnalysis {
            tls_version: handshake_result.tls_version.clone(),
            cipher_suite: handshake_result.cipher_suite.clone(),
            key_exchange: handshake_result.key_exchange.join(", "),
            pqc_detected: false,
            pqc_key_exchange: Vec::new(),
            pqc_signature_algorithms: Vec::new(),
            pqc_signature_status: String::new(),
            pqc_public_key_algorithms: Vec::new(),
            pqc_extensions: Vec::new(),
            security_features: Vec::new(),
            security_level: "Unknown".to_string(),
            hybrid_detected: false,
            classical_fallback_available: false,
            pqc_signature_used: false,
            pqc_signature_algorithm: None,
            signature_negotiation_status: SignatureNegotiationStatus::Unknown,
            server_endpoint_fingerprint: None,
        };

        // Analyze key exchange
        for kex in &handshake_result.key_exchange {
            if self.is_pqc_key_exchange(kex) {
                analysis.pqc_key_exchange.push(kex.clone());
                analysis.pqc_detected = true;
            } else if self.is_classical_key_exchange(kex) {
                analysis.classical_fallback_available = true;
            }
        }

        // Analyze PQC signature algorithms from handshake
        for sig_alg in &handshake_result.pqc_signature_algorithms {
            analysis.pqc_signature_algorithms.push(sig_alg.clone());
            analysis.pqc_detected = true;
        }

        // Check for hybrid mode
        if !analysis.pqc_key_exchange.is_empty() && analysis.classical_fallback_available {
            analysis.hybrid_detected = true;
        }

        // Analyze certificate
        if let Some(ref cert_info) = handshake_result.certificate_info {
            if self.is_pqc_signature_algorithm(&cert_info.signature_algorithm) {
                analysis.pqc_signature_algorithms.push(cert_info.signature_algorithm.clone());
                analysis.pqc_detected = true;
                analysis.pqc_signature_algorithm = Some(cert_info.signature_algorithm.clone());
            }

            if self.is_pqc_public_key_algorithm(&cert_info.public_key_algorithm) {
                analysis.pqc_public_key_algorithms.push(cert_info.public_key_algorithm.clone());
                analysis.pqc_detected = true;
            }

            // Validate hostname against certificate
            let hostname_valid = self.validate_hostname(&handshake_result.target, cert_info);
            if !hostname_valid {
                analysis.security_features.push("Hostname Mismatch".to_string());
            }
        }

        // Estimate security level
        analysis.security_level = self.estimate_security_level(&analysis).to_string();

        // Set a clear status for signature algorithms
        if !analysis.pqc_signature_algorithms.is_empty() {
            if handshake_result.tls_version == "1.3" && handshake_result.certificate_visible {
                analysis.pqc_signature_status = "Offered by client".to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            } else if handshake_result.tls_version == "1.3" && !handshake_result.certificate_visible {
                analysis.pqc_signature_status = "Not visible (encrypted in TLS 1.3)".to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::Unknown;
            } else {
                analysis.pqc_signature_status = "Detected".to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::Negotiated;
            }
        } else if !handshake_result.certificate_visible && handshake_result.tls_version == "1.3" {
            analysis.pqc_signature_status = "Not visible (encrypted in TLS 1.3)".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::Unknown;
        } else if handshake_result.certificate_visible {
            analysis.pqc_signature_status = "None found".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
        } else {
            analysis.pqc_signature_status = "Not applicable".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
        }

        analysis
    }

    fn is_classical_key_exchange(&self, kex: &str) -> bool {
        matches!(kex.to_lowercase().as_str(),
            "x25519" | "x448" |
            "secp256r1" | "secp384r1" | "secp521r1" |
            "prime256v1" | "prime384v1" | "prime521v1" |
            "brainpoolp256r1" | "brainpoolp384r1" | "brainpoolp512r1" |
            "ffdhe2048" | "ffdhe3072" | "ffdhe4096" | "ffdhe6144" | "ffdhe8192"
        )
    }

    fn estimate_security_level(&self, analysis: &PqcAnalysis) -> SecurityLevel {
        if !analysis.pqc_detected {
            return SecurityLevel::Classical;
        }

        // Estimate based on known algorithms
        let mut max_level = SecurityLevel::Low;

        for kex in &analysis.pqc_key_exchange {
            let level = match kex.to_lowercase().as_str() {
                "kyber512" => SecurityLevel::Low,
                "kyber768" => SecurityLevel::Medium,
                "kyber1024" => SecurityLevel::High,
                "frodo640" => SecurityLevel::Low,
                "frodo976" => SecurityLevel::Medium,
                _ => SecurityLevel::Medium, // Default for unknown PQC algorithms
            };
            if level as u8 > max_level as u8 {
                max_level = level;
            }
        }

        for sig_alg in &analysis.pqc_signature_algorithms {
            let level = match sig_alg.to_lowercase().as_str() {
                alg if alg.contains("dilithium2") => SecurityLevel::Low,
                alg if alg.contains("dilithium3") => SecurityLevel::Medium,
                alg if alg.contains("dilithium5") => SecurityLevel::High,
                alg if alg.contains("falcon512") => SecurityLevel::Low,
                alg if alg.contains("falcon1024") => SecurityLevel::High,
                _ => SecurityLevel::Medium,
            };
            if level as u8 > max_level as u8 {
                max_level = level;
            }
        }

        max_level
    }

    pub fn analyze_handshake(&self, result: &HandshakeResult) -> PqcAnalysis {
        let mut analysis = PqcAnalysis::default();
        
        // Analyze TLS version
        self.analyze_tls_version(result, &mut analysis);
        
        // If TLS 1.2 is detected, disable PQC detection and enable classical fallback
        if result.tls_version == "1.2" {
            println!("TLS 1.2 detected - disabling PQC detection and enabling classical fallback");
            analysis.pqc_detected = false;
            analysis.hybrid_detected = false;
            analysis.classical_fallback_available = true;
            analysis.security_level = "Classical".to_string();
            analysis.pqc_signature_used = false;
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            analysis.pqc_signature_status = "Not applicable (TLS 1.2)".to_string();
            
            // Still analyze basic TLS information
            self.analyze_cipher_suite(result, &mut analysis);
            self.analyze_key_exchange(result, &mut analysis);
            
            return analysis;
        }
        
        // Analyze cipher suite
        self.analyze_cipher_suite(result, &mut analysis);
        
        // Analyze key exchange
        self.analyze_key_exchange(result, &mut analysis);
        
        // Analyze extensions
        self.analyze_extensions(result, &mut analysis);
        
        // Enhanced PQC signature detection using SignatureDetector
        self.analyze_signatures(result, &mut analysis);
        
        // Analyze certificate information
        if let Some(ref cert_info) = result.certificate_info {
            // Check for PQC public key algorithms
            if self.is_pqc_signature_algorithm(&cert_info.public_key_algorithm) {
                analysis.pqc_public_key_algorithms.push(cert_info.public_key_algorithm.clone());
            }
            
            // Check for PQC signature algorithms
            if self.is_pqc_signature_algorithm(&cert_info.signature_algorithm) {
                analysis.pqc_signature_algorithms.push(cert_info.signature_algorithm.clone());
                // Set the actual PQC signature algorithm used
                analysis.pqc_signature_algorithm = Some(cert_info.signature_algorithm.clone());
            }
            
            // Validate hostname against certificate
            if !self.validate_hostname(&result.target, cert_info) {
                analysis.security_features.push("Hostname Mismatch".to_string());
            }
        }
        
        // Determine overall security level
        self.determine_security_level(&mut analysis);
        
        analysis
    }

    fn analyze_tls_version(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        match result.tls_version.as_str() {
            "1.3" => {
                analysis.tls_version = "TLS 1.3".to_string();
                analysis.security_features.push("TLS 1.3".to_string());
            }
            "1.2" => {
                analysis.tls_version = "TLS 1.2".to_string();
                analysis.security_features.push("TLS 1.2".to_string());
            }
            "1.1" => {
                analysis.tls_version = "TLS 1.1".to_string();
                analysis.security_features.push("TLS 1.1".to_string());
            }
            "1.0" => {
                analysis.tls_version = "TLS 1.0".to_string();
                analysis.security_features.push("TLS 1.0".to_string());
            }
            _ => {
                analysis.tls_version = format!("TLS {}", result.tls_version);
            }
        }
    }

    fn analyze_cipher_suite(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        match result.cipher_suite.as_str() {
            "TLS_AES_128_GCM_SHA256" | "TLS_AES_256_GCM_SHA384" | "TLS_CHACHA20_POLY1305_SHA256" => {
                analysis.cipher_suite = result.cipher_suite.clone();
                analysis.security_features.push("AEAD Cipher".to_string());
                analysis.classical_fallback_available = true;
            }
            "TLS_HYBRID_X25519_MLKEM768_SHA384" | "TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384" => {
                analysis.cipher_suite = result.cipher_suite.clone();
                analysis.security_features.push("PQC Hybrid Cipher".to_string());
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;
                analysis.classical_fallback_available = true;
            }
            "Unknown(0x11ec)" => {
                analysis.cipher_suite = "TLS_HYBRID_X25519_MLKEM768_SHA384".to_string();
                analysis.security_features.push("PQC Hybrid Cipher".to_string());
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;
                analysis.classical_fallback_available = true;
            }
            "Unknown(0x6399)" => {
                analysis.cipher_suite = "TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384".to_string();
                analysis.security_features.push("PQC Hybrid Cipher".to_string());
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;
                analysis.classical_fallback_available = true;
            }
            cipher if cipher.contains("ECDHE") => {
                analysis.cipher_suite = cipher.to_string();
                analysis.security_features.push("ECDHE".to_string());
                analysis.classical_fallback_available = true;
            }
            _ => {
                analysis.cipher_suite = result.cipher_suite.clone();
            }
        }
    }

    fn analyze_key_exchange(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        let mut has_classical = false;
        let mut has_pqc = false;
        
        for key_exchange in &result.key_exchange {
            match key_exchange.as_str() {
                "x25519" | "X25519" => {
                    analysis.key_exchange = "X25519".to_string();
                    analysis.security_features.push("X25519".to_string());
                    analysis.classical_fallback_available = true;
                    has_classical = true;
                }
                "secp256r1" => {
                    analysis.key_exchange = "SECP256R1".to_string();
                    analysis.security_features.push("SECP256R1".to_string());
                    analysis.classical_fallback_available = true;
                    has_classical = true;
                }
                "ML-KEM-768" | "ML-KEM-512" | "ML-KEM-1024" => {
                    analysis.key_exchange = key_exchange.to_string();
                    analysis.pqc_key_exchange.push(key_exchange.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                "Kyber768" | "Kyber512" | "Kyber1024" => {
                    analysis.key_exchange = key_exchange.to_string();
                    analysis.pqc_key_exchange.push(key_exchange.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                key if key.contains("kyber") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                key if key.contains("mlkem") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                key if key.contains("dilithium") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                _ => {
                    analysis.key_exchange = key_exchange.to_string();
                }
            }
        }
        
        // Detect hybrid mode if both classical and PQC algorithms are present
        if has_classical && has_pqc {
            analysis.hybrid_detected = true;
            analysis.classical_fallback_available = true;
        }
        
        // If we detected PQC but TLS version is 1.2, this indicates a fallback scenario
        if analysis.pqc_detected && result.tls_version == "1.2" {
            println!("PQC detected but TLS 1.2 fallback occurred - this indicates server rejected PQC");
            analysis.pqc_detected = false;
            analysis.hybrid_detected = false;
            analysis.classical_fallback_available = true;
        }
    }

    fn analyze_extensions(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        // Analyze PQC extensions from handshake result
        if result.pqc_extensions.kem {
            analysis.pqc_extensions.push("KEM".to_string());
            analysis.pqc_detected = true;
        }
        
        if result.pqc_extensions.kem_group {
            analysis.pqc_extensions.push("KEM_GROUP".to_string());
            analysis.pqc_detected = true;
        }
    }

    fn analyze_signatures(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        // Extract hostname from target (assuming format "hostname:port")
        let hostname = result.target.split(':').next().unwrap_or(&result.target);
        
        // Estimate certificate length from raw certificate data
        let certificate_length = if !result.raw_certificate.is_empty() {
            Some(result.raw_certificate.len() as u32)
        } else {
            None
        };
        
        // Use SignatureDetector to analyze signatures
        self.signature_detector.update_analysis(
            analysis,
            &result.pqc_signature_algorithms,
            certificate_length,
            hostname,
            &result.key_exchange,
            &result.cipher_suite
        );
        
        // Generate endpoint fingerprint with TLS version awareness
        analysis.server_endpoint_fingerprint = self.signature_detector.generate_endpoint_fingerprint_with_version(
            hostname, 
            &result.key_exchange, 
            &result.cipher_suite,
            &result.tls_version
        );
    }

    fn determine_security_level(&self, analysis: &mut PqcAnalysis) {
        if analysis.pqc_detected {
            if analysis.hybrid_detected {
                analysis.security_level = "Hybrid PQC".to_string();
            } else {
                analysis.security_level = "PQC Only".to_string();
            }
        } else if analysis.tls_version == "TLS 1.3" {
            analysis.security_level = "TLS 1.3 Classical".to_string();
        } else {
            analysis.security_level = "Classical".to_string();
        }
    }

    fn estimate_certificate_length(&self, cert_info: &crate::types::CertificateInfo) -> u32 {
        // Estimate certificate length based on key size and algorithm
        let base_length = match cert_info.public_key_algorithm.as_str() {
            "RSA" => {
                // RSA certificates are typically larger due to key size
                cert_info.key_size.unwrap_or(2048) / 8 + 100 // Rough estimate
            },
            "ECDSA" | "ECDSA P-256" => {
                // ECDSA certificates are smaller
                256 / 8 + 50 // Rough estimate
            },
            "Dilithium2" => 1312,
            "Dilithium3" => 1952,
            "Dilithium5" => 2592,
            "Falcon-512" => 896,
            "Falcon-1024" => 1792,
            _ => {
                // Default estimate based on key size
                cert_info.key_size.unwrap_or(256) / 8 + 100
            }
        };
        
        // Add overhead for signature, extensions, etc.
        let total_length = base_length + 200; // Additional overhead
        
        total_length as u32
    }

    fn validate_hostname(&self, target_hostname: &str, cert_info: &crate::types::CertificateInfo) -> bool {
        // Extract hostname from target (remove port if present)
        let hostname = target_hostname.split(':').next().unwrap_or(target_hostname);
        
        // Check if hostname matches the certificate subject
        if self.hostname_matches(hostname, &cert_info.subject) {
            return true;
        }
        
        // Check if hostname matches any SAN entries
        if let Some(ref san) = cert_info.san {
            if self.hostname_matches(hostname, san) {
                return true;
            }
        }
        
        false
    }
    
    fn hostname_matches(&self, hostname: &str, cert_field: &str) -> bool {
        // Handle wildcard matching according to RFC 6125
        if cert_field.starts_with("*.") {
            let domain = &cert_field[2..]; // Remove "*. "
            
            // Wildcard can match the domain itself or one level subdomain
            // *.pki.goog can match pki.goog or foo.pki.goog
            if hostname == domain {
                return true; // Exact domain match
            }
            
            if hostname.ends_with(domain) {
                let prefix = &hostname[..hostname.len() - domain.len()];
                // Check that there's exactly one level (no dots in prefix)
                if !prefix.contains('.') && !prefix.is_empty() {
                    return true;
                }
            }
            return false;
        }
        
        // Exact match
        hostname == cert_field
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityLevel {
    Unknown = 0,
    Low = 1,      // ~128 bits of security
    Medium = 2,   // ~192 bits of security
    High = 3,     // ~256 bits of security
    Classical = 4, // No PQC, classical algorithms only
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Unknown => write!(f, "Unknown"),
            SecurityLevel::Low => write!(f, "Low (~128-bit)"),
            SecurityLevel::Medium => write!(f, "Medium (~192-bit)"),
            SecurityLevel::High => write!(f, "High (~256-bit)"),
            SecurityLevel::Classical => write!(f, "Classical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HandshakeResult, PqcExtensions, HandshakeProfile, TlsFeatures};

    #[test]
    fn test_pqc_key_exchange_detection() {
        let detector = PqcDetector::new();
        
        assert!(detector.is_pqc_key_exchange("kyber1024"));
        assert!(detector.is_pqc_key_exchange("KYBER768"));
        assert!(detector.is_pqc_key_exchange("ntru"));
        assert!(detector.is_pqc_key_exchange("frodo640"));
        
        assert!(!detector.is_pqc_key_exchange("x25519"));
        assert!(!detector.is_pqc_key_exchange("secp256r1"));
    }

    #[test]
    fn test_pqc_signature_detection() {
        let detector = PqcDetector::new();
        
        assert!(detector.is_pqc_signature_algorithm("dilithium3"));
        assert!(detector.is_pqc_signature_algorithm("FALCON512"));
        assert!(detector.is_pqc_signature_algorithm("sphincsplus"));
        
        assert!(!detector.is_pqc_signature_algorithm("sha256WithRSAEncryption"));
        assert!(!detector.is_pqc_signature_algorithm("ecdsa-with-SHA256"));
    }

    #[test]
    fn test_hybrid_detection() {
        let detector = PqcDetector::new();
        
        let handshake_result = HandshakeResult {
            target: "example.com:443".to_string(),
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            key_exchange: vec!["x25519".to_string(), "kyber1024".to_string()],
            pqc_extensions: PqcExtensions::default(),
            certificate_info: None,
            raw_server_hello: Vec::new(),
            raw_certificate: Vec::new(),
            alert_info: None,
            certificate_visible: false,
            handshake_complete: true,
            pqc_signature_algorithms: Vec::new(),
            tls_features: TlsFeatures::default(),
            handshake_duration_ms: None,
            client_profile_used: HandshakeProfile::Standard,
            extension_map: crate::types::ExtensionMap::default(),
        };
        
        let analysis = detector.analyze_pqc_support(&handshake_result);
        assert!(analysis.pqc_detected);
        assert!(analysis.hybrid_detected);
        assert!(analysis.classical_fallback_available);
    }
} 