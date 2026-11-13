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

    /// Checks if a key exchange group name is post-quantum (hybrid or pure),
    /// using the IANA registry in [`crate::constants`].
    fn is_pqc_key_exchange(&self, algorithm: &str) -> bool {
        crate::constants::named_group_by_name(algorithm)
            .is_some_and(|g| g.kind != crate::constants::GroupKind::Classical)
    }

    /// Checks if a signature algorithm name is post-quantum: a PQC TLS
    /// SignatureScheme name or a PQC X.509 OID name from [`crate::constants`].
    fn is_pqc_signature_algorithm(&self, algorithm: &str) -> bool {
        crate::constants::is_pqc_signature_scheme_name(algorithm)
            || crate::constants::PQC_OIDS.iter().any(|o| {
                o.kind != crate::constants::OidKind::MlKem && o.name.eq_ignore_ascii_case(algorithm)
            })
    }

    /// Checks if a certificate public key algorithm name is post-quantum.
    fn is_pqc_public_key_algorithm(&self, pub_key_alg: &str) -> bool {
        crate::constants::PQC_OIDS
            .iter()
            .any(|o| o.name.eq_ignore_ascii_case(pub_key_alg))
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
            pqc_signature_observation: String::new(),
            pqc_key_exchange_observed: false,
            pqc_signature_observed: false,
            pqc_signature_inferred_from_cert: false,
        };

        // Analyze key exchange
        for kex in &handshake_result.key_exchange {
            if self.is_pqc_key_exchange(kex) {
                analysis.pqc_key_exchange.push(kex.clone());
                analysis.pqc_detected = true;
                if crate::constants::named_group_by_name(kex)
                    .is_some_and(|g| g.kind == crate::constants::GroupKind::Hybrid)
                {
                    analysis.hybrid_detected = true;
                }
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

        // Set a clear status for signature algorithms and machine-readable observation flag
        // FIXED: Set pqc_signature_used to None when status is Unknown (TLS 1.3 encrypted)
        if !analysis.pqc_signature_algorithms.is_empty() {
            analysis.pqc_signature_observed = true;
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
            analysis.pqc_signature_observation = "unknown".to_string();
        } else if handshake_result.certificate_visible {
            analysis.pqc_signature_status = "None found".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            analysis.pqc_signature_used = Some(false);
            analysis.pqc_signature_observation = "not_applicable".to_string();
        } else {
            analysis.pqc_signature_status = "Not applicable".to_string();
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotOffered;
            analysis.pqc_signature_used = Some(false);
            analysis.pqc_signature_observation = "not_applicable".to_string();
        }

        // Apply detailed PQC analysis
        self.apply_detailed_pqc_analysis(&mut analysis, handshake_result);

        // Finalize key/signature observation flags
        if !analysis.pqc_key_exchange.is_empty() {
            analysis.pqc_key_exchange_observed = true;
        }
        if analysis
            .pqc_signature_algorithms
            .iter()
            .any(|s| s.starts_with("pqc_sig_oid:"))
        {
            analysis.pqc_signature_inferred_from_cert = true;
        }

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

    /// Groups offered in our ClientHello, in preference order (from the profile).
    fn extract_client_offered_kems(&self, handshake_result: &HandshakeResult) -> Vec<String> {
        handshake_result.client_profile_used.offered_group_names()
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
        extensions.push((crate::constants::EXT_KEY_SHARE, Some(32))); // key_share - estimated length, not measured

        // Add signature_algorithms (always present in TLS 1.3)
        extensions.push((0x000d, Some(8))); // signature_algorithms - typically 8 bytes

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
            extensions.push((crate::constants::EXT_KEY_SHARE, Some(32))); // key_share - estimated length, not measured
        }
        if handshake_result.extension_map.signature_algorithms {
            extensions.push((0x000d, Some(8))); // signature_algorithms - typically 8 bytes
        }
        if has_classical_kex && handshake_result.extension_map.supported_versions {
            extensions.push((0x000a, Some(16))); // supported_groups - typically 16 bytes
        }

        extensions
    }

    fn is_classical_key_exchange(&self, kex: &str) -> bool {
        crate::constants::named_group_by_name(kex)
            .is_some_and(|g| g.kind == crate::constants::GroupKind::Classical)
    }

    fn estimate_security_level(&self, analysis: &PqcAnalysis) -> SecurityLevel {
        if !analysis.pqc_detected {
            return SecurityLevel::Classical;
        }

        // Estimate based on known algorithms
        let mut max_level = SecurityLevel::Low;

        for kex in &analysis.pqc_key_exchange {
            let pq_kem = crate::constants::named_group_by_name(kex).and_then(|g| g.pq_kem);
            let level = match pq_kem {
                Some(k) if k.contains("512") => SecurityLevel::Low,
                Some(k) if k.contains("1024") => SecurityLevel::High,
                _ => SecurityLevel::Medium,
            };
            if level as u8 > max_level as u8 {
                max_level = level;
            }
        }

        for sig_alg in &analysis.pqc_signature_algorithms {
            let alg = sig_alg.to_lowercase();
            let level = if alg.contains("mldsa44") || alg.contains("ml-dsa-44") {
                SecurityLevel::Low
            } else if alg.contains("mldsa87") || alg.contains("ml-dsa-87") {
                SecurityLevel::High
            } else {
                SecurityLevel::Medium
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
            tracing::debug!(
                "TLS 1.2 detected - disabling PQC detection and enabling classical fallback"
            );

            analysis.pqc_detected = false;
            analysis.hybrid_detected = false;
            analysis.classical_fallback_available = true;
            analysis.security_level = "Classical".to_string();
            analysis.pqc_signature_used = Some(false);
            analysis.signature_negotiation_status = SignatureNegotiationStatus::NotApplicable;
            analysis.pqc_signature_status = "Not applicable (TLS 1.2)".to_string();
            analysis.pqc_signature_observation = "not_applicable".to_string();

            // Still analyze basic TLS information
            self.analyze_cipher_suite(result, &mut analysis);
            self.analyze_key_exchange(result, &mut analysis);

            return analysis;
        }

        // The negotiated group is already in result.key_exchange: the handshake
        // engine reads it from ServerHello.key_share (or from rustls).
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

        // Finalize key/signature observation flags and status classification
        if !analysis.pqc_key_exchange.is_empty() {
            analysis.pqc_key_exchange_observed = true;
        }
        if !analysis.pqc_signature_algorithms.is_empty() {
            analysis.pqc_signature_observed = true;
        }
        if analysis
            .pqc_signature_algorithms
            .iter()
            .any(|s| s.starts_with("pqc_sig_oid:"))
        {
            analysis.pqc_signature_inferred_from_cert = true;
        }

        // Derive a compact, machine-readable observation status for PQC signatures.
        //
        // - "observed": at least one PQC signature algorithm was observed or inferred
        // - "not_applicable":
        //     * TLS 1.2 or earlier (no PQC signatures in protocol)
        //     * TLS 1.3+ where certificate is visible but only classical signatures are present
        // - "not_implemented": QUIC handshakes where PQC signature visibility is not yet supported
        // - "unknown": TLS 1.3+ where handshake encryption prevents us from deciding and we have
        //              no positive evidence of PQC signatures
        analysis.pqc_signature_observation = if matches!(
            analysis.signature_negotiation_status,
            SignatureNegotiationStatus::NotApplicable
        ) || result.tls_version == "1.2"
        {
            "not_applicable".to_string()
        } else if analysis.pqc_signature_observed {
            "observed".to_string()
        } else if result.connection_type.as_deref() == Some("quic")
            && matches!(
                analysis.signature_negotiation_status,
                SignatureNegotiationStatus::Unknown
            )
        {
            // QUIC path: we don't yet expose handshake signatures, so this is a scanner
            // limitation rather than a property of the endpoint.
            "not_implemented".to_string()
        } else if result.certificate_visible && analysis.pqc_signature_algorithms.is_empty() {
            // TLS 1.3+ with a visible (classical-only) certificate and no PQC signature
            // algorithms detected: PQC signatures are simply not in use here.
            "not_applicable".to_string()
        } else {
            "unknown".to_string()
        };

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
        // TLS 1.3 cipher suites carry no key-exchange information; PQC is
        // negotiated through supported_groups/key_share, never the suite.
        analysis.cipher_suite = result.cipher_suite.clone();
        match result.cipher_suite.as_str() {
            "TLS13_AES_128_GCM_SHA256"
            | "TLS13_AES_256_GCM_SHA384"
            | "TLS13_CHACHA20_POLY1305_SHA256"
            | "TLS_AES_128_GCM_SHA256"
            | "TLS_AES_256_GCM_SHA384"
            | "TLS_CHACHA20_POLY1305_SHA256" => {
                analysis.security_features.push("AEAD Cipher".to_string());
            }
            cipher if cipher.contains("ECDHE") => {
                analysis.security_features.push("ECDHE".to_string());
                analysis.classical_fallback_available = true;
            }
            _ => {}
        }
    }

    fn analyze_key_exchange(&self, result: &HandshakeResult, analysis: &mut PqcAnalysis) {
        use crate::constants::{named_group_by_name, GroupKind};

        for key_exchange in &result.key_exchange {
            analysis.key_exchange = key_exchange.clone();
            match named_group_by_name(key_exchange).map(|g| g.kind) {
                Some(GroupKind::Classical) => {
                    analysis.security_features.push(key_exchange.clone());
                    analysis.classical_fallback_available = true;
                }
                Some(GroupKind::Hybrid) => {
                    // A hybrid group combines ECDHE with a PQ KEM in one key share.
                    analysis.pqc_key_exchange.push(key_exchange.clone());
                    analysis.security_features.push(key_exchange.clone());
                    analysis.pqc_detected = true;
                    analysis.hybrid_detected = true;
                }
                Some(GroupKind::PurePq) => {
                    analysis.pqc_key_exchange.push(key_exchange.clone());
                    analysis.security_features.push(key_exchange.clone());
                    analysis.pqc_detected = true;
                }
                None => {}
            }
        }

        // PQC groups cannot be negotiated in TLS 1.2.
        if analysis.pqc_detected && result.tls_version == "1.2" {
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
        _hostname: &str,
        key_exchange: &[String],
        cipher_suite: &str,
        tls_version: &str,
    ) -> Option<String> {
        // For TLS 1.2, don't generate PQC-related fingerprints
        if tls_version == "1.2" {
            return None;
        }

        let mut fingerprint_parts = Vec::new();

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

        // Standardized format: classical-pqc-cipher
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

        assert!(detector.is_pqc_key_exchange("X25519MLKEM768"));
        assert!(detector.is_pqc_key_exchange("SecP256r1MLKEM768"));
        assert!(detector.is_pqc_key_exchange("MLKEM1024"));
        assert!(detector.is_pqc_key_exchange("X25519Kyber768Draft00"));
        // Names outside the IANA registry are not guessed at.
        assert!(!detector.is_pqc_key_exchange("ntru"));

        assert!(!detector.is_pqc_key_exchange("x25519"));
        assert!(!detector.is_pqc_key_exchange("secp256r1"));
    }

    #[test]
    fn test_pqc_signature_detection() {
        let detector = PqcDetector::new();

        assert!(detector.is_pqc_signature_algorithm("id-ml-dsa-65"));
        assert!(detector.is_pqc_signature_algorithm("mldsa87"));
        assert!(detector.is_pqc_signature_algorithm("id-MLDSA65-ECDSA-P256-SHA512"));
        // ML-KEM identifies a KEM key, never a signature.
        assert!(!detector.is_pqc_signature_algorithm("id-alg-ml-kem-768"));

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
            key_exchange: vec!["X25519MLKEM768".to_string()],
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
            client_profile_used: HandshakeProfile::Default,
            extension_map: crate::types::ExtensionMap::default(),
            connection_type: None,
            cipher_suite_reason: None,
        };

        let analysis = detector.analyze_pqc_support(&handshake_result);
        assert!(analysis.pqc_detected);
        assert!(analysis.hybrid_detected);
        assert_eq!(
            analysis.pqc_key_exchange,
            vec!["X25519MLKEM768".to_string()]
        );
    }
}
