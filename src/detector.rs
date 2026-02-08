use crate::detailed_pqc_analysis::DetailedPqcAnalyzer;
use crate::signature_detector::SignatureDetector;
use crate::tls_parser::TlsMessageParser;
use crate::types::{HandshakeResult, PqcAnalysis, SignatureNegotiationStatus};

pub struct PqcDetector {
    signature_detector: SignatureDetector,
    detailed_analyzer: DetailedPqcAnalyzer,
}

impl Default for PqcDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PqcDetector {
    pub fn new() -> Self {
        Self {
            signature_detector: SignatureDetector::new(),
            detailed_analyzer: DetailedPqcAnalyzer::new(),
        }
    }

    /// Determines if PQC is detected based on handshake results
    pub fn detect_pqc(&self, handshake_result: &HandshakeResult) -> bool {
        // If TLS 1.2 is detected, PQC is not possible
        if handshake_result.tls_version == "1.2" {
            return false;
        }

        // Use proper TLS message parsing for PQC detection
        self.detect_pqc_via_tls_parsing(handshake_result)
            || self.detect_pqc_key_exchange(handshake_result)
            || self.detect_pqc_extensions(handshake_result)
            || self.detect_pqc_certificate(handshake_result)
    }

    /// Detects PQC algorithms in key exchange
    fn detect_pqc_key_exchange(&self, handshake_result: &HandshakeResult) -> bool {
        handshake_result
            .key_exchange
            .iter()
            .any(|kex| self.is_pqc_key_exchange(kex))
    }

    /// Detects PQC-related extensions
    fn detect_pqc_extensions(&self, handshake_result: &HandshakeResult) -> bool {
        handshake_result.pqc_extensions.kem || handshake_result.pqc_extensions.kem_group
    }

    /// Detects PQC via proper TLS message parsing
    fn detect_pqc_via_tls_parsing(&self, handshake_result: &HandshakeResult) -> bool {
        let tls_parser = TlsMessageParser::new();

        // Parse ServerHello to check for PQC group selection
        if let Ok(Some(server_group)) =
            tls_parser.parse_server_hello_group(&handshake_result.raw_server_hello)
        {
            if tls_parser.is_pqc_group(server_group) {
                return true;
            }
        }

        // NOTE: EncryptedExtensions is a separate message from ServerHello and is encrypted in TLS 1.3
        // We cannot parse it from raw_server_hello. This path is disabled until we capture raw_encrypted_extensions
        // For now, PQC detection relies on ServerHello.key_share extension which is unencrypted
        // if let Ok(Some(kem_id)) = tls_parser.parse_encrypted_extensions_kem(&handshake_result.raw_encrypted_extensions) {
        //     if tls_parser.is_pqc_group(kem_id) {
        //         return true;
        //     }
        // }

        false
    }

    /// Detects PQC algorithms in certificate
    fn detect_pqc_certificate(&self, handshake_result: &HandshakeResult) -> bool {
        if let Some(ref cert_info) = handshake_result.certificate_info {
            self.is_pqc_signature_algorithm(&cert_info.signature_algorithm)
                || self.is_pqc_public_key_algorithm(&cert_info.public_key_algorithm)
        } else {
            false
        }
    }

    /// Checks if a key exchange algorithm is post-quantum
    fn is_pqc_key_exchange(&self, algorithm: &str) -> bool {
        let pqc_algorithms = [
            // ML-KEM family (NIST PQC winners)
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            // Hybrid groups (X25519 + ML-KEM, P256 + ML-KEM)
            "X25519ML-KEM-512",
            "X25519ML-KEM-768",
            "X25519ML-KEM-1024",
            "X25519+ML-KEM-512",
            "X25519+ML-KEM-768",
            "X25519+ML-KEM-1024",
            "P256ML-KEM-512",
            "P256ML-KEM-768",
            "P256ML-KEM-1024",
            "P256+ML-KEM-512",
            "P256+ML-KEM-768",
            "P256+ML-KEM-1024",
            // Kyber family (original names, still in use)
            "Kyber512",
            "Kyber768",
            "Kyber1024",
            "X25519Kyber768",
            "X25519Kyber512",
            // Alternative spellings
            "MLKEM512",
            "MLKEM768",
            "MLKEM1024",
            "KYBER512",
            "KYBER768",
            "KYBER1024",
            // Experimental/alternative KEMs
            "HQC",
            "Classic-McEliece",
            "BIKE",
            "SIKE",
            "NTRU",
            "FRODO",
            // Generic PQC indicators
            "PQC",
            "Post-Quantum",
            "Quantum-Resistant",
        ];

        let algorithm_upper = algorithm.to_uppercase();
        pqc_algorithms
            .iter()
            .any(|&pqc| algorithm_upper.contains(&pqc.to_uppercase()))
    }

    /// Checks if a signature algorithm is post-quantum
    fn is_pqc_signature_algorithm(&self, algorithm: &str) -> bool {
        let pqc_signatures = [
            // Dilithium family (NIST PQC winners)
            "Dilithium2",
            "Dilithium3",
            "Dilithium5",
            "DILITHIUM2",
            "DILITHIUM3",
            "DILITHIUM5",
            // Falcon family
            "Falcon512",
            "Falcon1024",
            "FALCON512",
            "FALCON1024",
            // SPHINCS+ family
            "SPHINCS+",
            "SPHINCS",
            "SphincsPlus",
            "Sphincs",
            // Alternative spellings
            "DILITHIUM-2",
            "DILITHIUM-3",
            "DILITHIUM-5",
            "FALCON-512",
            "FALCON-1024",
            // Generic PQC signature indicators
            "PQC-Signature",
            "Quantum-Signature",
            "Post-Quantum-Signature",
        ];

        let algorithm_upper = algorithm.to_uppercase();
        pqc_signatures
            .iter()
            .any(|&pqc| algorithm_upper.contains(pqc))
    }

    /// Checks if a public key algorithm is post-quantum
    fn is_pqc_public_key_algorithm(&self, pub_key_alg: &str) -> bool {
        let normalized = pub_key_alg.to_lowercase();

        // Key encapsulation mechanisms
        if normalized.contains("kyber")
            || normalized.contains("ntru")
            || normalized.contains("saber")
            || normalized.contains("frodo")
            || normalized.contains("bike")
            || normalized.contains("hqc")
            || normalized.contains("mceliece")
        {
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
            pqc_signature_used: None,
            pqc_signature_algorithm: None,
            signature_negotiation_status: SignatureNegotiationStatus::Unknown,
            server_endpoint_fingerprint: None,
            kem_negotiation: None,
            extension_usage: None,
            hybrid_details: None,
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
                analysis
                    .pqc_signature_algorithms
                    .push(cert_info.signature_algorithm.clone());
                analysis.pqc_detected = true;
                analysis.pqc_signature_algorithm = Some(cert_info.signature_algorithm.clone());
            }

            if self.is_pqc_public_key_algorithm(&cert_info.public_key_algorithm) {
                analysis
                    .pqc_public_key_algorithms
                    .push(cert_info.public_key_algorithm.clone());
                analysis.pqc_detected = true;
            }

            // Validate hostname against certificate
            let hostname_valid = self.validate_hostname(&handshake_result.target, cert_info);
            if !hostname_valid {
                analysis
                    .security_features
                    .push("Hostname Mismatch".to_string());
            }
        }

        // Estimate security level
        analysis.security_level = self.estimate_security_level(&analysis).to_string();

        // Set a clear status for signature algorithms
        // FIXED: Set pqc_signature_used to None when status is Unknown (TLS 1.3 encrypted)
        if !analysis.pqc_signature_algorithms.is_empty() {
            if handshake_result.tls_version == "1.3" && handshake_result.certificate_visible {
                analysis.pqc_signature_status = "Offered by client".to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
                analysis.pqc_signature_used = Some(false);
            } else if handshake_result.tls_version == "1.3" && !handshake_result.certificate_visible
            {
                // FIXED: Updated message - extraction function is implemented but requires raw TLS data
                analysis.pqc_signature_status =
                    "Unknown (CertificateVerify extraction requires raw TLS message capture)"
                        .to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::Unknown;
                analysis.pqc_signature_used = None; // Unknown - cannot determine
            } else {
                analysis.pqc_signature_status = "Detected".to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::Negotiated;
                analysis.pqc_signature_used = Some(true);
            }
        } else if !handshake_result.certificate_visible && handshake_result.tls_version == "1.3" {
            analysis.pqc_signature_status =
                "Unknown (TLS 1.3 encryption prevents direct observation)".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::Unknown;
            analysis.pqc_signature_used = None; // Unknown - cannot determine
        } else if handshake_result.certificate_visible {
            analysis.pqc_signature_status = "None found".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            analysis.pqc_signature_used = Some(false);
        } else {
            analysis.pqc_signature_status = "Not applicable".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            analysis.pqc_signature_used = Some(false);
        }

        // Apply detailed PQC analysis
        self.apply_detailed_pqc_analysis(&mut analysis, handshake_result);

        analysis
    }

    /// Apply detailed PQC analysis using the DetailedPqcAnalyzer
    fn apply_detailed_pqc_analysis(
        &self,
        analysis: &mut PqcAnalysis,
        handshake_result: &HandshakeResult,
    ) {
        // Extract client-offered KEMs from the handshake profile
        let client_offered_kems = self.extract_client_offered_kems(handshake_result);

        // Determine server-selected KEM
        let server_selected_kem = analysis.pqc_key_exchange.first().map(|s| s.as_str());

        // Analyze KEM negotiation
        analysis.kem_negotiation = Some(self.detailed_analyzer.analyze_kem_negotiation(
            &client_offered_kems,
            server_selected_kem,
            &handshake_result.key_exchange,
        ));

        // Analyze extension usage
        let client_extensions = self.extract_client_extensions(handshake_result);
        let server_extensions = self.extract_server_extensions(handshake_result);
        analysis.extension_usage = Some(self.detailed_analyzer.analyze_extension_usage(
            &client_extensions,
            &server_extensions,
            &analysis.pqc_extensions,
        ));

        // Analyze hybrid details
        analysis.hybrid_details = Some(self.detailed_analyzer.analyze_hybrid_details(
            &handshake_result.key_exchange,
            handshake_result.handshake_duration_ms,
            analysis.classical_fallback_available,
        ));
    }

    /// Extract client-offered KEMs based on the handshake profile
    fn extract_client_offered_kems(&self, handshake_result: &HandshakeResult) -> Vec<String> {
        match handshake_result.client_profile_used {
            crate::types::HandshakeProfile::CloudflarePqc => {
                vec![
                    "ML-KEM-768".to_string(),
                    "ML-KEM-512".to_string(),
                    "X25519".to_string(),
                ]
            }
            crate::types::HandshakeProfile::HybridPqc => {
                vec![
                    "ML-KEM-768".to_string(),
                    "Kyber768".to_string(),
                    "X25519".to_string(),
                    "P-256".to_string(),
                ]
            }
            crate::types::HandshakeProfile::PqcOnly => {
                vec![
                    "ML-KEM-768".to_string(),
                    "ML-KEM-1024".to_string(),
                    "Kyber768".to_string(),
                    "Kyber1024".to_string(),
                ]
            }
            crate::types::HandshakeProfile::Standard => {
                vec!["X25519".to_string(), "P-256".to_string()]
            }
        }
    }

    /// Extract client extensions from handshake result
    fn extract_client_extensions(
        &self,
        handshake_result: &HandshakeResult,
    ) -> Vec<(u16, Option<u32>)> {
        let mut extensions = Vec::new();

        // Check if classical key exchange is used (X25519, P-256, etc.)
        let has_classical_kex = handshake_result
            .key_exchange
            .iter()
            .any(|kex| self.is_classical_key_exchange(kex));

        // Add supported_groups only if classical key exchange is used
        if has_classical_kex {
            extensions.push((0x000a, Some(16))); // supported_groups - typically 16 bytes
        }

        // Add key_share (always present in TLS 1.3)
        extensions.push((0x001c, Some(32))); // key_share - typically 32 bytes

        // Add signature_algorithms (always present in TLS 1.3)
        extensions.push((0x000d, Some(8))); // signature_algorithms - typically 8 bytes

        // Add PQC extensions if detected
        if handshake_result.pqc_extensions.kem {
            extensions.push((0xfe00, Some(8))); // kem - typically 8 bytes
        }
        if handshake_result.pqc_extensions.kem_group {
            extensions.push((0xfe01, Some(8))); // kem_group - typically 8 bytes
        }

        extensions
    }

    /// Extract server extensions from handshake result
    fn extract_server_extensions(
        &self,
        handshake_result: &HandshakeResult,
    ) -> Vec<(u16, Option<u32>)> {
        let mut extensions = Vec::new();

        // Check if classical key exchange is used
        let has_classical_kex = handshake_result
            .key_exchange
            .iter()
            .any(|kex| self.is_classical_key_exchange(kex));

        // Add extensions that were actually used with estimated data lengths
        if handshake_result.extension_map.key_share {
            extensions.push((0x001c, Some(32))); // key_share - typically 32 bytes
        }
        if handshake_result.extension_map.signature_algorithms {
            extensions.push((0x000d, Some(8))); // signature_algorithms - typically 8 bytes
        }
        if has_classical_kex && handshake_result.extension_map.supported_versions {
            extensions.push((0x000a, Some(16))); // supported_groups - typically 16 bytes
        }
        if handshake_result.pqc_extensions.kem {
            extensions.push((0xfe00, Some(8))); // kem - typically 8 bytes
        }
        if handshake_result.pqc_extensions.kem_group {
            extensions.push((0xfe01, Some(8))); // kem_group - typically 8 bytes
        }

        extensions
    }

    fn is_classical_key_exchange(&self, kex: &str) -> bool {
        matches!(
            kex.to_lowercase().as_str(),
            "x25519"
                | "x448"
                | "secp256r1"
                | "secp384r1"
                | "secp521r1"
                | "prime256v1"
                | "prime384v1"
                | "prime521v1"
                | "brainpoolp256r1"
                | "brainpoolp384r1"
                | "brainpoolp512r1"
                | "ffdhe2048"
                | "ffdhe3072"
                | "ffdhe4096"
                | "ffdhe6144"
                | "ffdhe8192"
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
            if crate::verbose() {
                println!(
                    "TLS 1.2 detected - disabling PQC detection and enabling classical fallback"
                );
            }
            analysis.pqc_detected = false;
            analysis.hybrid_detected = false;
            analysis.classical_fallback_available = true;
            analysis.security_level = "Classical".to_string();
            analysis.pqc_signature_used = Some(false);
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotApplicable;
            analysis.pqc_signature_status = "Not applicable (TLS 1.2)".to_string();

            // Still analyze basic TLS information
            self.analyze_cipher_suite(result, &mut analysis);
            self.analyze_key_exchange(result, &mut analysis);

            return analysis;
        }

        // Use TLS parser for proper PQC detection
        let tls_parser = TlsMessageParser::new();
        let mut server_group = None;
        let mut kem_id = None;

        // Parse ServerHello for PQC group selection
        if let Ok(group) = tls_parser.parse_server_hello_group(&result.raw_server_hello) {
            server_group = group;
        }

        // Parse EncryptedExtensions for KEM extension
        if let Ok(kem) = tls_parser.parse_encrypted_extensions_kem(&result.raw_server_hello) {
            kem_id = kem;
        }

        // Validate PQC detection: ServerHello group must be in PQC range AND KEM extension must match
        if let (Some(server_group_id), Some(kem_extension_id)) = (server_group, kem_id) {
            if tls_parser.is_pqc_group(server_group_id)
                && tls_parser.is_pqc_group(kem_extension_id)
                && server_group_id == kem_extension_id
            {
                // Valid PQC detection - set hybrid_detected = true
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;

                // Map group ID to algorithm name
                if let Some(alg_name) = tls_parser.group_id_to_algorithm(server_group_id) {
                    analysis.pqc_key_exchange.push(alg_name.clone());
                    // For hybrid, show both classical and PQC components
                    if analysis.classical_fallback_available {
                        analysis.key_exchange = format!("Hybrid ({} + classical)", alg_name);
                    } else {
                        analysis.key_exchange = alg_name;
                    }
                }

                if crate::verbose() {
                    println!("PQC detected via TLS parsing: ServerHello group 0x{:04X} matches KEM extension 0x{:04X}", 
                             server_group_id, kem_extension_id);
                }
            }
        }

        // Enhanced hybrid detection: Check if multiple PQC algorithms are present
        if analysis.pqc_key_exchange.len() > 1 {
            analysis.hybrid_detected = true;
            analysis.key_exchange = format!("Hybrid ({})", analysis.pqc_key_exchange.join(", "));
        }

        // Analyze cipher suite
        self.analyze_cipher_suite(result, &mut analysis);

        // Analyze key exchange (fallback to string-based detection if TLS parsing didn't work)
        if !analysis.pqc_detected {
            self.analyze_key_exchange(result, &mut analysis);
        }

        // Analyze extensions
        self.analyze_extensions(result, &mut analysis);

        // Enhanced PQC signature detection using SignatureDetector
        self.analyze_signatures(result, &mut analysis);

        // Analyze certificate information
        if let Some(ref cert_info) = result.certificate_info {
            // Check for PQC public key algorithms
            if self.is_pqc_signature_algorithm(&cert_info.public_key_algorithm) {
                analysis
                    .pqc_public_key_algorithms
                    .push(cert_info.public_key_algorithm.clone());
            }

            // Check for PQC signature algorithms
            if self.is_pqc_signature_algorithm(&cert_info.signature_algorithm) {
                analysis
                    .pqc_signature_algorithms
                    .push(cert_info.signature_algorithm.clone());
                // Set the actual PQC signature algorithm used
                analysis.pqc_signature_algorithm = Some(cert_info.signature_algorithm.clone());
            }

            // Validate hostname against certificate
            if !self.validate_hostname(&result.target, cert_info) {
                analysis
                    .security_features
                    .push("Hostname Mismatch".to_string());
            }
        }

        // Determine overall security level
        self.determine_security_level(&mut analysis);

        // Apply detailed PQC analysis
        self.apply_detailed_pqc_analysis(&mut analysis, result);

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
                // FIXED: Don't add "TLS" prefix if it's already present
                if result.tls_version.starts_with("TLS ") {
                    analysis.tls_version = result.tls_version.clone();
                } else {
                    analysis.tls_version = format!("TLS {}", result.tls_version);
                }
            }
        }
    }

    fn analyze_cipher_suite(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        match result.cipher_suite.as_str() {
            "TLS_AES_128_GCM_SHA256"
            | "TLS_AES_256_GCM_SHA384"
            | "TLS_CHACHA20_POLY1305_SHA256" => {
                analysis.cipher_suite = result.cipher_suite.clone();
                analysis.security_features.push("AEAD Cipher".to_string());
                analysis.classical_fallback_available = true;
            }
            "TLS_HYBRID_X25519_MLKEM768_SHA384" | "TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384" => {
                analysis.cipher_suite = result.cipher_suite.clone();
                analysis
                    .security_features
                    .push("PQC Hybrid Cipher".to_string());
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;
                analysis.classical_fallback_available = true;
            }
            "Unknown(0x11ec)" => {
                analysis.cipher_suite = "TLS_HYBRID_X25519_MLKEM768_SHA384".to_string();
                analysis
                    .security_features
                    .push("PQC Hybrid Cipher".to_string());
                analysis.pqc_detected = true;
                analysis.hybrid_detected = true;
                analysis.classical_fallback_available = true;
            }
            "Unknown(0x6399)" => {
                analysis.cipher_suite = "TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384".to_string();
                analysis
                    .security_features
                    .push("PQC Hybrid Cipher".to_string());
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
                    // FIXED: Add PQC algorithms to security_features
                    analysis.security_features.push(key_exchange.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                "Kyber768" | "Kyber512" | "Kyber1024" => {
                    analysis.key_exchange = key_exchange.to_string();
                    analysis.pqc_key_exchange.push(key_exchange.to_string());
                    // FIXED: Add PQC algorithms to security_features
                    analysis.security_features.push(key_exchange.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                key if key.contains("kyber") || key.contains("Kyber") => {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    // FIXED: Add PQC algorithms to security_features
                    analysis.security_features.push(key.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                }
                key if key.to_uppercase().contains("ML-KEM")
                    || key.to_uppercase().contains("MLKEM")
                    || key.to_uppercase().contains("X25519ML")
                    || key.to_uppercase().contains("P256ML") =>
                {
                    analysis.key_exchange = key.to_string();
                    analysis.pqc_key_exchange.push(key.to_string());
                    // FIXED: Add PQC algorithms to security_features
                    analysis.security_features.push(key.to_string());
                    analysis.pqc_detected = true;
                    has_pqc = true;
                    // Hybrid groups contain both classical and PQC components
                    if key.to_uppercase().contains("X25519ML")
                        || key.to_uppercase().contains("P256ML")
                    {
                        analysis.hybrid_detected = true;
                        analysis.classical_fallback_available = true;
                    }
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
            if crate::verbose() {
                println!("PQC detected but TLS 1.2 fallback occurred - this indicates server rejected PQC");
            }
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
        // FIXED: Priority order for PQC signature detection:
        // 1. Captured TLS 1.3 CertificateVerify SignatureScheme (from CapturingVerifier) - most authoritative
        // 2. TLS 1.2 CertificateVerify parsed from raw handshake records
        // 3. Certificate chain OIDs (SPKI + cert signatureAlgorithm)

        // If we have pqc_signature_used from CapturingVerifier (TLS 1.3), use it as authoritative
        if let Some(pqc_used) = result.pqc_signature_used {
            // We have definitive answer from CapturingVerifier
            analysis.pqc_signature_used = Some(pqc_used);
            if pqc_used {
                analysis.pqc_signature_status =
                    "Detected via TLS 1.3 CertificateVerify (captured from verifier callback)"
                        .to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::Negotiated;
            } else {
                analysis.pqc_signature_status =
                    "Not used (TLS 1.3 CertificateVerify captured from verifier callback)"
                        .to_string();
                analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            }
            // Still detect algorithms from other sources for completeness
            let (detected_signatures, _, _) = self.signature_detector.detect_pqc_signatures(
                &result.raw_server_hello,
                &result.raw_certificate,
                &result.tls_version,
                result.certificate_visible,
            );
            if !detected_signatures.is_empty() {
                analysis.pqc_signature_algorithms = detected_signatures;
            }
        } else {
            // Fallback: Use enhanced signature detection (TLS 1.2 or when CapturingVerifier didn't capture)
            let (detected_signatures, negotiation_status, used_signature) =
                self.signature_detector.detect_pqc_signatures(
                    &result.raw_server_hello,
                    &result.raw_certificate,
                    &result.tls_version,
                    result.certificate_visible,
                );

            // Update analysis with signature detection results
            self.signature_detector.update_analysis(
                analysis,
                &detected_signatures,
                negotiation_status,
                used_signature,
            );
        }

        // Generate endpoint fingerprint with TLS version awareness
        let hostname = result.target.split(':').next().unwrap_or(&result.target);
        analysis.server_endpoint_fingerprint = self.generate_endpoint_fingerprint(
            hostname,
            &result.key_exchange,
            &result.cipher_suite,
            &result.tls_version,
        );
    }

    /// Generate server endpoint fingerprint with TLS version awareness
    /// Fixed: Correctly handles ML-KEM-1024, ML-KEM-768, Kyber variants, and standardizes format
    fn generate_endpoint_fingerprint(
        &self,
        hostname: &str,
        key_exchange: &[String],
        cipher_suite: &str,
        tls_version: &str,
    ) -> Option<String> {
        // For TLS 1.2, don't generate PQC-related fingerprints
        if tls_version == "1.2" {
            return None;
        }

        let mut fingerprint_parts = Vec::new();

        // Check for known PQC endpoints
        let hostname_lower = hostname.to_lowercase();

        if hostname_lower.contains("cloudflare") && hostname_lower.contains("pq") {
            fingerprint_parts.push("cloudflare-pqc".to_string());
        }

        // Add key exchange info (deduplicated) - FIXED: Correctly identify ML-KEM variants
        let mut seen_algorithms = std::collections::HashSet::new();

        for kex in key_exchange {
            let kex_lower = kex.to_lowercase();
            let alg_name = if kex_lower.contains("ml-kem-1024") || kex.contains("ML-KEM-1024") {
                "mlkem1024"
            } else if kex_lower.contains("ml-kem-768") || kex.contains("ML-KEM-768") {
                "mlkem768"
            } else if kex_lower.contains("ml-kem-512") || kex.contains("ML-KEM-512") {
                "mlkem512"
            } else if kex_lower.contains("kyber1024") || kex.contains("Kyber1024") {
                "kyber1024"
            } else if kex_lower.contains("kyber768") || kex.contains("Kyber768") {
                "kyber768"
            } else if kex_lower.contains("kyber512") || kex.contains("Kyber512") {
                "kyber512"
            } else if kex_lower.contains("x25519") || kex.contains("X25519") {
                "x25519"
            } else {
                continue;
            };

            if !seen_algorithms.contains(alg_name) {
                fingerprint_parts.push(alg_name.to_string());
                seen_algorithms.insert(alg_name);
            }
        }

        // Standardized format: [cloudflare-pqc-]classical-pqc-cipher
        // If only classical: classical-cipher
        // If only PQC: pqc-cipher
        // If hybrid: classical-pqc-cipher

        // Reorder to ensure consistent format: classical first (if present), then PQC, then cipher
        let mut ordered_parts = Vec::new();
        let mut pqc_parts = Vec::new();
        let mut classical_parts = Vec::new();

        for part in &fingerprint_parts {
            if part == "x25519" {
                classical_parts.push(part.clone());
            } else if part.starts_with("mlkem") || part.starts_with("kyber") {
                pqc_parts.push(part.clone());
            } else if part == "cloudflare-pqc" {
                ordered_parts.push(part.clone());
            }
        }

        // Build final fingerprint in consistent order
        ordered_parts.extend(classical_parts);
        ordered_parts.extend(pqc_parts);

        // Add cipher suite info (standardized)
        if cipher_suite.contains("AES_128_GCM") {
            ordered_parts.push("aes128gcm".to_string());
        } else if cipher_suite.contains("AES_256_GCM") {
            ordered_parts.push("aes256gcm".to_string());
        } else if cipher_suite.contains("CHACHA20") {
            ordered_parts.push("chacha20poly1305".to_string());
        }

        if ordered_parts.is_empty() {
            None
        } else {
            Some(ordered_parts.join("-"))
        }
    }

    fn determine_security_level(&self, analysis: &mut PqcAnalysis) {
        if analysis.pqc_detected {
            if analysis.hybrid_detected {
                analysis.security_level = "Hybrid PQC".to_string();
            } else {
                analysis.security_level = "PQC Only".to_string();
            }
        } else {
            analysis.security_level = "Classical Only".to_string();
        }
    }

    // Note: estimate_certificate_length method is not used in the current implementation

    fn validate_hostname(
        &self,
        target_hostname: &str,
        cert_info: &crate::types::CertificateInfo,
    ) -> bool {
        // Extract hostname from target (remove port if present)
        let hostname = target_hostname.split(':').next().unwrap_or(target_hostname);

        // FIXED: Use CertificateParser::validate_hostname_match which properly handles
        // SAN splitting and wildcard matching according to RFC 6125
        crate::cert::CertificateParser::validate_hostname_match(
            hostname,
            &cert_info.san,
            &cert_info.subject,
        )
    }

    fn hostname_matches(&self, hostname: &str, cert_field: &str) -> bool {
        // Handle wildcard matching according to RFC 6125
        if let Some(domain) = cert_field.strip_prefix("*.") {
            // Remove "*. "

            // Wildcard can match the domain itself or one level subdomain
            // *.pki.goog can match pki.goog or foo.pki.goog
            if hostname == domain {
                return true; // Exact domain match
            }

            if let Some(prefix) = hostname.strip_suffix(domain) {
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
    Low = 1,       // ~128 bits of security
    Medium = 2,    // ~192 bits of security
    High = 3,      // ~256 bits of security
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
    use crate::types::{HandshakeProfile, HandshakeResult, PqcExtensions, TlsFeatures};

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
            pqc_signature_used: None, // Unknown - no certificate or CertificateVerify available
            tls_features: TlsFeatures::default(),
            handshake_duration_ms: None,
            client_profile_used: HandshakeProfile::Standard,
            extension_map: crate::types::ExtensionMap::default(),
            connection_type: None,
            cipher_suite_reason: None,
        };

        let analysis = detector.analyze_pqc_support(&handshake_result);
        assert!(analysis.pqc_detected);
        assert!(analysis.hybrid_detected);
        assert!(analysis.classical_fallback_available);
    }
}
