use crate::types::{HandshakeResult, PqcAnalysis};

pub struct PqcDetector;

impl PqcDetector {
    pub fn new() -> Self {
        Self
    }

    /// Determines if PQC is detected based on handshake results
    pub fn detect_pqc(&self, handshake_result: &HandshakeResult) -> bool {
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
            tls_version: String::new(),
            cipher_suite: String::new(),
            key_exchange: String::new(),
            pqc_detected: false,
            pqc_key_exchange: Vec::new(),
            pqc_signature_algorithms: Vec::new(),
            pqc_signature_status: String::new(),
            pqc_public_key_algorithms: Vec::new(),
            pqc_extensions: Vec::new(),
            security_features: Vec::new(),
            security_level: String::new(),
            hybrid_detected: false,
            classical_fallback_available: false,
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
            }

            if self.is_pqc_public_key_algorithm(&cert_info.public_key_algorithm) {
                analysis.pqc_public_key_algorithms.push(cert_info.public_key_algorithm.clone());
                analysis.pqc_detected = true;
            }
        }

        // Estimate security level
        analysis.security_level = self.estimate_security_level(&analysis).to_string();

        // Set a clear status for signature algorithms
        if !analysis.pqc_signature_algorithms.is_empty() {
            analysis.pqc_signature_status = "Detected".to_string();
        } else if !handshake_result.certificate_visible && handshake_result.tls_version == "1.3" {
            analysis.pqc_signature_status = "Not visible (Encrypted in TLS 1.3)".to_string();
        } else if handshake_result.certificate_visible {
            analysis.pqc_signature_status = "None found".to_string();
        } else {
            analysis.pqc_signature_status = "Not applicable".to_string();
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
        
        // Analyze cipher suite
        self.analyze_cipher_suite(result, &mut analysis);
        
        // Analyze key exchange
        self.analyze_key_exchange(result, &mut analysis);
        
        // Analyze extensions
        self.analyze_extensions(result, &mut analysis);
        
        // Determine overall security level
        self.determine_security_level(&mut analysis);
        
        // Set a clear status for signature algorithms
        if !analysis.pqc_signature_algorithms.is_empty() {
            analysis.pqc_signature_status = "Detected".to_string();
        } else if !result.certificate_visible && result.tls_version == "1.3" {
            analysis.pqc_signature_status = "Not visible (Encrypted in TLS 1.3)".to_string();
        } else if result.certificate_visible {
            analysis.pqc_signature_status = "None found".to_string();
        } else {
            analysis.pqc_signature_status = "Not applicable".to_string();
        }
        
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
        for key_exchange in &result.key_exchange {
            match key_exchange.as_str() {
                "x25519" => {
                    analysis.key_exchange = "X25519".to_string();
                    analysis.security_features.push("X25519".to_string());
                    analysis.classical_fallback_available = true;
                }
                "secp256r1" => {
                    analysis.key_exchange = "SECP256R1".to_string();
                    analysis.security_features.push("SECP256R1".to_string());
                    analysis.classical_fallback_available = true;
                }
                "X25519+ML-KEM768" => {
                    analysis.key_exchange = "X25519+ML-KEM768".to_string();
                    analysis.pqc_key_exchange.push("X25519+ML-KEM768".to_string());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                    analysis.classical_fallback_available = true;
                }
                "X25519+Kyber768Draft00" => {
                    analysis.key_exchange = "X25519+Kyber768Draft00".to_string();
                    analysis.pqc_key_exchange.push("X25519+Kyber768Draft00".to_string());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                    analysis.classical_fallback_available = true;
                }
                "X25519+Kyber512Draft00" => {
                    analysis.key_exchange = "X25519+Kyber512Draft00".to_string();
                    analysis.pqc_key_exchange.push("X25519+Kyber512Draft00".to_string());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                    analysis.classical_fallback_available = true;
                }
                "Kyber768" => {
                    analysis.key_exchange = "Kyber768".to_string();
                    analysis.pqc_key_exchange.push("Kyber768".to_string());
                    analysis.pqc_detected = true;
                }
                "unknown(0x11ec)" => {
                    analysis.key_exchange = "X25519+ML-KEM768".to_string();
                    analysis.pqc_key_exchange.push("X25519+ML-KEM768".to_string());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                    analysis.classical_fallback_available = true;
                }
                "unknown(0xfe30)" => {
                    analysis.key_exchange = "X25519+Kyber768".to_string();
                    analysis.pqc_key_exchange.push("X25519+Kyber768".to_string());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                    analysis.classical_fallback_available = true;
                }
                "unknown(0x001c)" => {
                    analysis.key_exchange = "Kyber768".to_string();
                    analysis.pqc_key_exchange.push("Kyber768".to_string());
                    analysis.pqc_detected = true;
                }
                key if key.contains("kyber") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                }
                key if key.contains("mlkem") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                }
                key if key.contains("dilithium") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    analysis.pqc_detected = true;
                }
                _ => {
                    analysis.key_exchange = key_exchange.to_string();
                }
            }
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

    fn determine_security_level(&self, analysis: &mut PqcAnalysis) {
        if analysis.pqc_detected {
            if analysis.classical_fallback_available {
                analysis.security_level = "Hybrid PQC".to_string();
                analysis.hybrid_detected = true;
            } else {
                analysis.security_level = "PQC Only".to_string();
            }
        } else if analysis.tls_version == "TLS 1.3" {
            analysis.security_level = "TLS 1.3 Classical".to_string();
        } else {
            analysis.security_level = "Classical".to_string();
        }
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
        };
        
        let analysis = detector.analyze_pqc_support(&handshake_result);
        assert!(analysis.pqc_detected);
        assert!(analysis.hybrid_detected);
        assert!(analysis.classical_fallback_available);
    }
} 