use crate::types::{PqcAnalysis, SignatureNegotiationStatus};
use std::collections::HashMap;

/// PQC Signature Detector for TLS 1.3 without decryption
pub struct SignatureDetector {
    /// Mapping of signature algorithm codepoints to names
    signature_codepoints: HashMap<u16, String>,
    /// PQC signature algorithms that are commonly supported
    pqc_signature_algorithms: Vec<String>,
}

impl Default for SignatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            signature_codepoints: HashMap::new(),
            pqc_signature_algorithms: Vec::new(),
        };

        detector.initialize_signature_codepoints();
        detector.initialize_pqc_signatures();

        detector
    }

    /// Initialize standard signature algorithm codepoints
    fn initialize_signature_codepoints(&mut self) {
        // Standard signature algorithms
        self.signature_codepoints
            .insert(0x0401, "RSA_PKCS1_SHA256".to_string());
        self.signature_codepoints
            .insert(0x0403, "ECDSA_SECP256R1_SHA256".to_string());
        self.signature_codepoints
            .insert(0x0807, "ED25519".to_string());
        self.signature_codepoints
            .insert(0x0808, "ED448".to_string());
        self.signature_codepoints
            .insert(0x0809, "RSA_PSS_RSAE_SHA256".to_string());
        self.signature_codepoints
            .insert(0x080a, "RSA_PSS_RSAE_SHA384".to_string());
        self.signature_codepoints
            .insert(0x080b, "RSA_PSS_RSAE_SHA512".to_string());
        self.signature_codepoints
            .insert(0x080c, "ECDSA_SECP384R1_SHA384".to_string());
        self.signature_codepoints
            .insert(0x080d, "ECDSA_SECP521R1_SHA512".to_string());
        self.signature_codepoints
            .insert(0x080e, "RSA_PSS_PSS_SHA256".to_string());
        self.signature_codepoints
            .insert(0x080f, "RSA_PSS_PSS_SHA384".to_string());
        self.signature_codepoints
            .insert(0x0810, "RSA_PSS_PSS_SHA512".to_string());

        // PQC signature algorithms (draft codepoints)
        // Note: These are experimental and may change
        self.signature_codepoints
            .insert(0xfe00, "Dilithium2".to_string());
        self.signature_codepoints
            .insert(0xfe01, "Dilithium3".to_string());
        self.signature_codepoints
            .insert(0xfe02, "Dilithium5".to_string());
        self.signature_codepoints
            .insert(0xfe03, "Falcon512".to_string());
        self.signature_codepoints
            .insert(0xfe04, "Falcon1024".to_string());
        self.signature_codepoints
            .insert(0xfe05, "SPHINCS+-SHA256-128f-simple".to_string());
        self.signature_codepoints
            .insert(0xfe06, "SPHINCS+-SHA256-192f-simple".to_string());
        self.signature_codepoints
            .insert(0xfe07, "SPHINCS+-SHA256-256f-simple".to_string());
    }

    /// Initialize PQC signature algorithms list
    fn initialize_pqc_signatures(&mut self) {
        self.pqc_signature_algorithms = vec![
            "Dilithium2".to_string(),
            "Dilithium3".to_string(),
            "Dilithium5".to_string(),
            "Falcon512".to_string(),
            "Falcon1024".to_string(),
            "SPHINCS+-SHA256-128f-simple".to_string(),
            "SPHINCS+-SHA256-192f-simple".to_string(),
            "SPHINCS+-SHA256-256f-simple".to_string(),
            "Rainbow-III-Classic".to_string(),
            "Rainbow-III-Circumzenithal".to_string(),
            "Rainbow-III-Compressed".to_string(),
            "Picnic3-L1".to_string(),
            "Picnic3-L3".to_string(),
            "Picnic3-L5".to_string(),
        ];
    }

    /// Detect PQC signature algorithms from handshake data
    pub fn detect_pqc_signatures(
        &self,
        raw_server_hello: &[u8],
        raw_certificate: &[u8],
        tls_version: &str,
        certificate_visible: bool,
    ) -> (Vec<String>, SignatureNegotiationStatus, Option<String>) {
        let mut detected_signatures = Vec::new();
        let mut negotiation_status = SignatureNegotiationStatus::Unknown;
        let mut used_signature = None;

        // In TLS 1.3, signature algorithms are negotiated in the signature_algorithms extension
        // but the actual signature used in CertificateVerify is encrypted
        if tls_version == "1.3" {
            // Try to extract signature algorithms from ServerHello
            if let Some(signature_algorithms) =
                self.extract_signature_algorithms_from_server_hello(raw_server_hello)
            {
                for sig_alg in signature_algorithms {
                    if self.is_pqc_signature_algorithm(&sig_alg) {
                        detected_signatures.push(sig_alg.clone());
                    }
                }

                if !detected_signatures.is_empty() {
                    negotiation_status = SignatureNegotiationStatus::Negotiated;

                    // In TLS 1.3, we can't directly see which signature was used in CertificateVerify
                    // but we can infer from the negotiated algorithms
                    if certificate_visible {
                        // If certificate is visible, we can try to infer from certificate signature
                        if let Some(cert_signature) =
                            self.extract_certificate_signature(raw_certificate)
                        {
                            if self.is_pqc_signature_algorithm(&cert_signature) {
                                used_signature = Some(cert_signature);
                            }
                        }
                    }
                } else {
                    // Enhanced detection: try to infer from certificate if available
                    if certificate_visible {
                        if let Some(cert_signature) =
                            self.extract_certificate_signature(raw_certificate)
                        {
                            if self.is_pqc_signature_algorithm(&cert_signature) {
                                detected_signatures.push(cert_signature.clone());
                                used_signature = Some(cert_signature);
                                negotiation_status = SignatureNegotiationStatus::Negotiated;
                            }
                        }
                    }

                    if detected_signatures.is_empty() {
                        negotiation_status = SignatureNegotiationStatus::NotOffered;
                    }
                }
            } else {
                // Enhanced detection: try certificate-based detection even without ServerHello parsing
                if certificate_visible {
                    if let Some(cert_signature) =
                        self.extract_certificate_signature(raw_certificate)
                    {
                        if self.is_pqc_signature_algorithm(&cert_signature) {
                            detected_signatures.push(cert_signature.clone());
                            used_signature = Some(cert_signature);
                            negotiation_status = SignatureNegotiationStatus::Negotiated;
                        }
                    }
                }

                if detected_signatures.is_empty() {
                    negotiation_status = SignatureNegotiationStatus::Unknown;
                }
            }
        } else {
            // TLS 1.2 - signature algorithms are more visible
            negotiation_status = SignatureNegotiationStatus::NotApplicable;
        }

        (detected_signatures, negotiation_status, used_signature)
    }

    /// Extract signature algorithms from ServerHello message
    fn extract_signature_algorithms_from_server_hello(
        &self,
        server_hello: &[u8],
    ) -> Option<Vec<String>> {
        if server_hello.len() < 4 {
            return None;
        }

        // Look for signature_algorithms extension (type 0x000d)
        let mut offset = 0;
        while offset + 4 < server_hello.len() {
            let ext_type = u16::from_be_bytes([server_hello[offset], server_hello[offset + 1]]);
            let ext_len =
                u16::from_be_bytes([server_hello[offset + 2], server_hello[offset + 3]]) as usize;

            if ext_type == 0x000d && offset + 4 + ext_len <= server_hello.len() {
                // Found signature_algorithms extension
                let ext_data = &server_hello[offset + 4..offset + 4 + ext_len];
                return self.parse_signature_algorithms_extension(ext_data);
            }

            offset += 4 + ext_len;
        }

        None
    }

    /// Parse signature algorithms extension data
    fn parse_signature_algorithms_extension(&self, ext_data: &[u8]) -> Option<Vec<String>> {
        if ext_data.len() < 2 {
            return None;
        }

        let total_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        if ext_data.len() < 2 + total_len {
            return None;
        }

        let mut signatures = Vec::new();
        let mut offset = 2;

        while offset + 1 < 2 + total_len {
            let sig_codepoint = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]);

            if let Some(sig_name) = self.signature_codepoints.get(&sig_codepoint) {
                signatures.push(sig_name.clone());
            } else {
                // Unknown codepoint - add as hex
                signatures.push(format!("Unknown(0x{:04x})", sig_codepoint));
            }

            offset += 2;
        }

        Some(signatures)
    }

    /// Extract signature algorithm from certificate
    /// FIXED: Use CertificateParser instead of unreliable UTF-8 string search
    fn extract_certificate_signature(&self, cert_data: &[u8]) -> Option<String> {
        if cert_data.len() < 4 {
            return None;
        }

        // FIXED: Use proper X.509 parser instead of unreliable UTF-8 string search
        // Parse certificate using CertificateParser which extracts OID properly
        let parser = crate::cert::CertificateParser::new();
        if let Ok(cert_info) = parser.parse_certificate(cert_data) {
            // Use OID for PQC detection if available
            if let Some(ref oid) = cert_info.signature_algorithm_oid {
                use crate::constants::is_pqc_oid;
                if is_pqc_oid(oid) {
                    // Return OID-based label for PQC signatures
                    return Some(format!("pqc_sig_oid:{}", oid));
                }
            }
            // Fallback to signature algorithm name if OID is not available or not PQC
            return Some(cert_info.signature_algorithm);
        }

        // If parsing fails, return None (don't use unreliable string search)
        None
    }

    /// Check if a signature algorithm is post-quantum
    fn is_pqc_signature_algorithm(&self, sig_alg: &str) -> bool {
        let normalized = sig_alg.to_lowercase();

        // Check against known PQC signature algorithms
        for pqc_sig in &self.pqc_signature_algorithms {
            if normalized.contains(&pqc_sig.to_lowercase()) {
                return true;
            }
        }

        // Additional PQC signature patterns
        if normalized.contains("dilithium")
            || normalized.contains("falcon")
            || normalized.contains("sphincs")
            || normalized.contains("rainbow")
            || normalized.contains("picnic")
            || normalized.contains("xmss")
            || normalized.contains("lms")
        {
            return true;
        }

        false
    }

    /// Get all known PQC signature algorithms
    pub fn get_pqc_signature_algorithms(&self) -> Vec<String> {
        self.pqc_signature_algorithms.clone()
    }

    /// Estimate signature algorithm from certificate length
    pub fn estimate_from_certificate_length(&self, cert_length: u32) -> Option<String> {
        match cert_length {
            0..=100 => Some("ECDSA secp256r1".to_string()),
            101..=300 => Some("RSA 2048".to_string()),
            301..=1000 => Some("RSA 4096".to_string()),
            1001..=2000 => Some("Dilithium2".to_string()),
            2001..=3000 => Some("Dilithium3".to_string()),
            3001..=5000 => Some("Dilithium5".to_string()),
            5001..=10000 => Some("Falcon1024".to_string()),
            _ => Some("SPHINCS+".to_string()),
        }
    }

    /// Generate endpoint fingerprint based on hostname and algorithms
    pub fn generate_endpoint_fingerprint(
        &self,
        hostname: &str,
        key_exchange: &[String],
        cipher_suite: &str,
    ) -> Option<String> {
        let mut fingerprint_parts = Vec::new();

        // Extract domain info
        let hostname_lower = hostname.to_lowercase();
        if hostname_lower.contains("cloudflare") {
            fingerprint_parts.push("cloudflare");
        }
        if hostname_lower.contains("pq") || hostname_lower.contains("quantum") {
            fingerprint_parts.push("pqc");
        }

        // Add key exchange info
        for kex in key_exchange {
            if kex.contains("ML-KEM") {
                fingerprint_parts.push("mlkem768");
            } else if kex.contains("Kyber") {
                fingerprint_parts.push("kyber768");
            }
        }

        // Add cipher suite info
        if cipher_suite.contains("AES_128_GCM") {
            fingerprint_parts.push("aes128gcm");
        }

        if fingerprint_parts.is_empty() {
            None
        } else {
            Some(fingerprint_parts.join("-"))
        }
    }

    /// Update PQC analysis with signature detection results
    pub fn update_analysis(
        &self,
        analysis: &mut PqcAnalysis,
        detected_signatures: &[String],
        negotiation_status: SignatureNegotiationStatus,
        used_signature: Option<String>,
    ) {
        // Update signature algorithms list
        analysis.pqc_signature_algorithms = detected_signatures.to_vec();

        // Update signature negotiation status
        analysis.signature_negotiation_status = negotiation_status.clone();

        // Update used signature algorithm
        analysis.pqc_signature_algorithm = used_signature.clone();

        // Update signature usage status based on negotiation status
        // FIXED: Set pqc_signature_used to None when status is Unknown
        match negotiation_status {
            SignatureNegotiationStatus::Negotiated => {
                analysis.pqc_signature_used = Some(true);
                if !detected_signatures.is_empty() {
                    analysis.pqc_signature_status = format!(
                        "Negotiated: {} algorithms detected",
                        detected_signatures.len()
                    );
                } else {
                    analysis.pqc_signature_status =
                        "Negotiated via certificate signature".to_string();
                }
            }
            SignatureNegotiationStatus::NotOffered => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Not offered by client or server".to_string();
            }
            SignatureNegotiationStatus::Rejected => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Rejected by server during negotiation".to_string();
            }
            SignatureNegotiationStatus::NotApplicable => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Not applicable (TLS 1.2 or earlier)".to_string();
            }
            SignatureNegotiationStatus::Unknown => {
                // FIXED: Set to None when Unknown (TLS 1.3 encrypted)
                analysis.pqc_signature_used = None;
                if used_signature.is_some() {
                    analysis.pqc_signature_status =
                        "Detected via certificate analysis (TLS 1.3 encrypted)".to_string();
                } else if !detected_signatures.is_empty() {
                    analysis.pqc_signature_status = format!(
                        "{} algorithms detected but usage unclear (TLS 1.3 encrypted)",
                        detected_signatures.len()
                    );
                } else {
                    analysis.pqc_signature_status =
                        "Not Implemented for TLS 1.3 (requires deeper handshake parsing)"
                            .to_string();
                }
            }
        }

        // Add detailed information about detected algorithms
        if !detected_signatures.is_empty() {
            let algorithm_details = detected_signatures.join(", ");
            if !analysis
                .pqc_signature_status
                .contains("algorithms detected")
            {
                analysis
                    .pqc_signature_status
                    .push_str(&format!(" - Detected: {}", algorithm_details));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm_mapping() {
        let detector = SignatureDetector::new();

        assert_eq!(
            detector.signature_codepoints.get(&0xfe00),
            Some(&"Dilithium2".to_string())
        );
        assert_eq!(
            detector.signature_codepoints.get(&0x080b),
            Some(&"RSA_PSS_RSAE_SHA512".to_string())
        );
        assert_eq!(
            detector.signature_codepoints.get(&0x0401),
            Some(&"RSA_PKCS1_SHA256".to_string())
        );
        assert_eq!(detector.signature_codepoints.get(&0x9999), None);
    }

    #[test]
    fn test_pqc_signature_detection() {
        let detector = SignatureDetector::new();

        assert!(detector.is_pqc_signature_algorithm("Dilithium2"));
        assert!(detector.is_pqc_signature_algorithm("Falcon512"));
        assert!(detector.is_pqc_signature_algorithm("SPHINCS+-SHA256-128f-simple"));

        assert!(!detector.is_pqc_signature_algorithm("RSA-SHA256"));
        assert!(!detector.is_pqc_signature_algorithm("ECDSA-SHA256"));
    }

    #[test]
    fn test_signature_codepoint_mapping() {
        let detector = SignatureDetector::new();

        assert!(detector.signature_codepoints.contains_key(&0xfe00));
        assert!(detector.signature_codepoints.contains_key(&0xfe03));
    }

    #[test]
    fn test_certificate_length_estimation() {
        let detector = SignatureDetector::new();

        assert_eq!(
            detector.estimate_from_certificate_length(2500),
            Some("Dilithium3".to_string())
        );
        assert_eq!(
            detector.estimate_from_certificate_length(70),
            Some("ECDSA secp256r1".to_string())
        );
        assert_eq!(
            detector.estimate_from_certificate_length(200),
            Some("RSA 2048".to_string())
        );
        assert_eq!(
            detector.estimate_from_certificate_length(10000),
            Some("Falcon1024".to_string())
        );
    }

    #[test]
    fn test_endpoint_fingerprint() {
        let detector = SignatureDetector::new();

        let fingerprint = detector.generate_endpoint_fingerprint(
            "pq.cloudflareresearch.com",
            &["X25519+ML-KEM768".to_string()],
            "TLS_AES_128_GCM_SHA256",
        );

        assert_eq!(
            fingerprint,
            Some("cloudflare-pqc-mlkem768-aes128gcm".to_string())
        );
    }
}
