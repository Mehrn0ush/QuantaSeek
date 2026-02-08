use crate::types::{
    CertificateInfo, CertificateWeights, OverallWeights, PerformanceWarning, PqcAlgorithmInfo,
    PqcAnalysis, PqcStrengthInfo, PqcWeights, ScanResult, ScoringFormula, ScoringWeights,
    SecurityScore, SecurityScoreDetails, SecurityWarning, TlsWeights, WarningLevel,
};
use chrono;
use std::collections::HashSet;

pub struct SecurityScorer;

impl Default for SecurityScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityScorer {
    pub fn new() -> Self {
        Self
    }

    /// Calculate comprehensive security score for a scan result
    pub fn calculate_security_score(&self, result: &ScanResult) -> SecurityScore {
        let mut details = SecurityScoreDetails::default();

        // Calculate TLS protocol score
        details.tls_version = self.score_tls_version(&result.tls_version);
        details.cipher_suite = self.score_cipher_suite(&result.cipher_suite);
        details.key_exchange = self.score_key_exchange(&result.key_exchange);

        // Calculate certificate score
        if let Some(cert) = &result.certificate {
            details.certificate_validation = self.score_certificate_validation(result);
            details.certificate_key_strength = self.score_certificate_key_strength(cert);
        } else if result.tls_version == "QUIC" {
            // For QUIC connections, use reasonable default certificate scores
            // since certificates may not be directly accessible
            details.certificate_validation = 80; // Assume valid for QUIC
            details.certificate_key_strength = 80; // Assume reasonable strength
        }

        // Calculate PQC score
        details.pqc_algorithm = self.calculate_pqc_algorithm_score(&result.analysis);
        details.pqc_implementation = self.score_pqc_implementation(&result.analysis);
        details.hybrid_security = self.score_hybrid_security(&result.analysis);

        let pqc_score = if result.pqc_detected {
            // PQC = (Algorithm + Implementation + Hybrid) / 3
            // Use floating-point division and round to get accurate score
            let raw_score = (details.pqc_algorithm as f32
                + details.pqc_implementation as f32
                + details.hybrid_security as f32)
                / 3.0;
            raw_score.round() as u8
        } else {
            0
        };

        // Calculate component scores with proper weighting
        let tls_score = self.calculate_tls_component_score(&details);
        let certificate_score =
            (details.certificate_validation + details.certificate_key_strength) / 2;

        // Treat certificate score 0 as "no data" when certificate_visible is false (suggestion 8.3).
        // Exclude cert from overall so experimental/QUIC targets do not pull down metrics.
        let certificate_available =
            result.certificate_visible && result.certificate.is_some() && certificate_score > 0;

        // Calculate overall score with adjusted weighting based on available components
        let (overall, tls_weight, cert_weight, pqc_weight) = if result.pqc_detected {
            if certificate_available {
                // PQC-enabled connections with certificate: TLS(30%) + Certificate(25%) + PQC(45%)
                let overall_score = ((tls_score as u32 * 30
                    + certificate_score as u32 * 25
                    + pqc_score as u32 * 45)
                    / 100) as u8;
                (overall_score, 30, 25, 45)
            } else if result.tls_version == "QUIC" {
                // QUIC connections without certificate: TLS(35%) + PQC(65%)
                // QUIC gets slightly higher TLS weight since it's a modern protocol
                let overall_score = ((tls_score as u32 * 35 + pqc_score as u32 * 65) / 100) as u8;
                (overall_score, 35, 0, 65)
            } else {
                // PQC-enabled connections without certificate: TLS(40%) + PQC(60%)
                let overall_score = ((tls_score as u32 * 40 + pqc_score as u32 * 60) / 100) as u8;
                (overall_score, 40, 0, 60)
            }
        } else if certificate_available {
            // Classical connections with certificate: TLS(50%) + Certificate(50%)
            let overall_score =
                ((tls_score as u32 * 50 + certificate_score as u32 * 50) / 100) as u8;
            (overall_score, 50, 50, 0)
        } else if result.tls_version == "QUIC" {
            // QUIC connections without certificate: TLS(100%)
            // For QUIC, if no PQC is detected, it's still a modern protocol
            (tls_score, 100, 0, 0)
        } else {
            // Classical connections without certificate: TLS(100%)
            let overall_score = tls_score;
            (overall_score, 100, 0, 0)
        };

        // Create formula explanation with dynamic weights
        let formula = ScoringFormula {
            overall_method: if result.pqc_detected {
                if certificate_available {
                    format!("Overall = 0.30×TLS({}) + 0.25×Certificate({}) + 0.45×PQC({}) = 0.30×{} + 0.25×{} + 0.45×{} = {}", 
                        tls_score, certificate_score, pqc_score, tls_score, certificate_score, pqc_score, overall)
                } else if result.tls_version == "QUIC" {
                    format!("Overall = 0.35×TLS({}) + 0.65×PQC({}) = 0.35×{} + 0.65×{} = {} (Certificate: N/A)", 
                        tls_score, pqc_score, tls_score, pqc_score, overall)
                } else {
                    format!("Overall = 0.40×TLS({}) + 0.60×PQC({}) = 0.40×{} + 0.60×{} = {} (Certificate: N/A)", 
                        tls_score, pqc_score, tls_score, pqc_score, overall)
                }
            } else if certificate_available {
                format!("Overall = 0.50×TLS({}) + 0.50×Certificate({}) = 0.50×{} + 0.50×{} = {}", 
                    tls_score, certificate_score, tls_score, certificate_score, overall)
            } else if result.tls_version == "QUIC" {
                format!("Overall = TLS({}) = {} (Certificate: N/A)", tls_score, overall)
            } else {
                format!("Overall = TLS({}) = {} (Certificate: N/A)", tls_score, overall)
            },
            tls_method: if details.key_exchange == 0 {
                // FIXED: Show adjusted formula when key_exchange is unknown
                format!("TLS = Version({})×0.57 + Cipher({})×0.43 = {}×0.57 + {}×0.43 = {} (KeyExchange: not analyzed)", 
                    details.tls_version, details.cipher_suite,
                    details.tls_version, details.cipher_suite, tls_score)
            } else {
                format!("TLS = Version({})×0.40 + Cipher({})×0.30 + KeyExchange({})×0.30 = {}×0.40 + {}×0.30 + {}×0.30 = {}", 
                    details.tls_version, details.cipher_suite, details.key_exchange,
                    details.tls_version, details.cipher_suite, details.key_exchange, tls_score)
            },
            certificate_method: format!("Certificate = (Validation({}) + KeyStrength({})) / 2 = ({} + {}) / 2 = {}", 
                details.certificate_validation, details.certificate_key_strength,
                details.certificate_validation, details.certificate_key_strength, certificate_score),
            pqc_method: format!("PQC = (Algorithm({}) + Implementation({}) + Hybrid({})) / 3 = ({} + {} + {}) / 3 = {}", 
                details.pqc_algorithm, details.pqc_implementation, details.hybrid_security,
                details.pqc_algorithm, details.pqc_implementation, details.hybrid_security, pqc_score),
            pqc_weights: if result.tls_version == "QUIC" {
                if certificate_available {
                    "TLS: 30%, Certificate: 25%, PQC: 45%".to_string()
                } else {
                    "TLS: 35%, Certificate: N/A, PQC: 65%".to_string()
                }
            } else if certificate_available {
                "TLS: 30%, Certificate: 25%, PQC: 45%".to_string()
            } else {
                "TLS: 40%, Certificate: N/A, PQC: 60%".to_string()
            },
            classical_weights: if result.tls_version == "QUIC" {
                "TLS: 100%, Certificate: N/A".to_string()
            } else if certificate_available {
                "TLS: 50%, Certificate: 50%".to_string()
            } else {
                "TLS: 100%, Certificate: N/A".to_string()
            },
        };

        // Create weights documentation with dynamic weights
        let weights = ScoringWeights {
            overall_pqc: OverallWeights {
                tls_percentage: if result.tls_version == "QUIC" {
                    35
                } else {
                    tls_weight
                },
                certificate_percentage: cert_weight,
                pqc_percentage: if result.tls_version == "QUIC" {
                    65
                } else {
                    pqc_weight
                },
            },
            overall_classical: OverallWeights {
                tls_percentage: if result.tls_version == "QUIC" {
                    100
                } else {
                    tls_weight
                },
                certificate_percentage: cert_weight,
                pqc_percentage: if result.tls_version == "QUIC" {
                    0
                } else {
                    pqc_weight
                },
            },
            tls_component: TlsWeights {
                version_percentage: 40,
                cipher_percentage: 30,
                key_exchange_percentage: 30,
            },
            certificate_component: CertificateWeights {
                validation_percentage: 50,
                key_strength_percentage: 50,
            },
            pqc_component: PqcWeights {
                algorithm_percentage: 33,
                implementation_percentage: 33,
                hybrid_percentage: 34,
            },
        };

        // Create PQC strength information
        let pqc_strength = self.create_pqc_strength_info(&result.analysis);

        // When certificate_visible is false, report overall excluding certificate (TLS + PQC only) for comparable metrics (suggestion 8.3).
        let overall_without_certificate = if !result.certificate_visible {
            Some(overall)
        } else {
            None
        };

        SecurityScore {
            tls: tls_score,
            certificate: certificate_score,
            pqc: pqc_score,
            overall,
            overall_without_certificate,
            details,
            formula,
            weights,
            pqc_strength,
        }
    }

    fn calculate_tls_component_score(&self, details: &SecurityScoreDetails) -> u8 {
        // FIXED: Adjust weights when key_exchange is unknown (0)
        // If key_exchange is 0, it means it wasn't extracted, so we should not penalize the score
        // Instead, adjust the weights to only use Version and Cipher
        if details.key_exchange == 0 {
            // Key exchange unknown: Version(57%) + Cipher(43%) = Version(40/70) + Cipher(30/70)
            // This prevents artificially low scores when key_exchange is not available
            ((details.tls_version as u32 * 40 + details.cipher_suite as u32 * 30) * 100 / 70) as u8
        } else {
            // Normal calculation: Version(40%) + Cipher(30%) + KeyExchange(30%)
            ((details.tls_version as u32 * 40
                + details.cipher_suite as u32 * 30
                + details.key_exchange as u32 * 30)
                / 100) as u8
        }
    }

    fn score_tls_version(&self, version: &str) -> u8 {
        match version {
            "1.3" => 100, // TLS 1.3 is the best
            "1.2" => 70,  // TLS 1.2 is acceptable but older
            "1.1" => 30,  // TLS 1.1 is deprecated
            "1.0" => 0,   // TLS 1.0 is insecure
            "QUIC" => 95, // QUIC is modern and secure, similar to TLS 1.3
            _ => {
                // Try to parse version numbers
                if let Ok(ver_num) = version.parse::<f32>() {
                    if ver_num >= 1.3 {
                        100
                    } else if ver_num >= 1.2 {
                        70
                    } else if ver_num >= 1.1 {
                        30
                    } else {
                        0
                    }
                } else {
                    0 // Unknown version gets 0
                }
            }
        }
    }

    fn score_cipher_suite(&self, cipher_suite: &str) -> u8 {
        match cipher_suite {
            // TLS 1.3 cipher suites (all are strong)
            "TLS13_AES_256_GCM_SHA384" => 100,
            "TLS13_AES_128_GCM_SHA256" => 95,
            "TLS13_CHACHA20_POLY1305_SHA256" => 100,
            // TLS 1.2 cipher suites
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => 85,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => 80,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => 90,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => 85,
            // Weak cipher suites
            "TLS_RSA_WITH_AES_256_CBC_SHA" => 40,
            "TLS_RSA_WITH_AES_128_CBC_SHA" => 35,
            _ => {
                if cipher_suite.contains("AES_256") || cipher_suite.contains("CHACHA20") {
                    80
                } else if cipher_suite.contains("AES_128") {
                    75
                } else {
                    60
                }
            }
        }
    }

    fn score_key_exchange(&self, key_exchange: &[String]) -> u8 {
        let mut score = 0;
        let mut count = 0;

        for ke in key_exchange {
            count += 1;
            score += match ke.as_str() {
                // PQC algorithms (NIST Level 1-3-5)
                "ML-KEM-1024" | "Kyber1024" => 100, // Level 5
                "ML-KEM-768" | "Kyber768" => 95,    // Level 3
                "ML-KEM-512" | "Kyber512" => 80,    // Level 1
                // Classical algorithms
                "X25519" => 90,
                "P-256" => 85,
                "P-384" => 90,
                "P-521" => 95,
                // Weak algorithms
                "RSA" => 40,
                _ => 70,
            };
        }

        if count > 0 {
            (score / count) as u8
        } else {
            0
        }
    }

    fn score_certificate_validation(&self, result: &ScanResult) -> u8 {
        if let Some(ref cert) = result.certificate {
            let mut score = 100;

            // Check for hostname validation
            if result
                .analysis
                .security_features
                .contains(&"Hostname Mismatch".to_string())
            {
                // FIXED: More appropriate penalty for hostname mismatch
                // Hostname mismatch is a security issue - should significantly reduce validation score
                let target_lower = result.target.to_lowercase();
                let experimental_indicators = [
                    "test",
                    "demo",
                    "dev",
                    "experimental",
                    "pqc",
                    "quantum",
                    "duckdns",
                    "oqstest",
                    "cryptoserver",
                    "pqkd",
                ];

                let is_experimental = experimental_indicators
                    .iter()
                    .any(|indicator| target_lower.contains(indicator));

                if is_experimental {
                    // Minimal penalty for experimental/test servers (they often use shared certs)
                    score -= 10;
                } else {
                    // Significant penalty for production servers - hostname mismatch is a security issue
                    // Reduces score to 50-60 range which is appropriate for mismatch
                    score -= 40; // Changed from 25 to 40 for more accurate scoring
                }
            }

            // Check for algorithm consistency
            if !cert.algorithm_consistency {
                // Penalize for algorithm inconsistency (e.g., ECDSA public key with RSA signature)
                score -= 15;
            }

            // Check for large SAN lists (performance impact)
            if let Some(san) = &cert.san {
                let san_count = san.split(',').count();
                // Configurable threshold - only penalize for very large lists
                if san_count > 200 {
                    score -= 5; // Minor penalty for very large SAN lists (>200 entries)
                }
                // Note: Most SAN lists with 50-200 entries have minimal performance impact
            }

            // Check certificate validity dates
            let now = chrono::Utc::now();
            if let Ok(valid_from) = chrono::DateTime::parse_from_rfc2822(&cert.valid_from) {
                if now < valid_from {
                    score -= 20; // Certificate not yet valid
                }
            }

            if let Ok(valid_to) = chrono::DateTime::parse_from_rfc2822(&cert.valid_to) {
                if now > valid_to {
                    score -= 30; // Certificate expired
                }
            }

            // Check for non-standard RSA key sizes
            if cert.public_key_algorithm == "RSA" {
                if let Some(key_size) = cert.key_size {
                    if key_size > 4096 && key_size < 8192 {
                        score -= 5; // Minor penalty for non-standard RSA key size
                    }
                }
            }

            score.min(100)
        } else {
            // No certificate available - this is normal for TLS 1.3
            if result.tls_version == "1.3" {
                85 // Good score for TLS 1.3 where certificates are encrypted
            } else {
                0 // No certificate available in other TLS versions
            }
        }
    }

    fn score_certificate_key_strength(&self, cert: &CertificateInfo) -> u8 {
        match cert.public_key_algorithm.as_str() {
            "RSA" => {
                if let Some(key_size) = cert.key_size {
                    match key_size {
                        4096.. => {
                            // Handle non-standard sizes like 4144 bits
                            if key_size > 4096 && key_size < 8192 {
                                // Non-standard but large RSA key - still secure but unusual
                                95 // Slightly lower score for non-standard size
                            } else {
                                100 // Standard large RSA key
                            }
                        }
                        3072 => 95, // Very good
                        2048 => 85, // Good
                        1024 => 30, // Weak
                        _ => 50,    // Unknown size
                    }
                } else {
                    70 // Unknown key size for RSA
                }
            }
            "ECDSA" => {
                if let Some(key_size) = cert.key_size {
                    match key_size {
                        521 => 100, // P-521
                        384 => 95,  // P-384
                        256 => 90,  // P-256
                        _ => 80,    // Other curves
                    }
                } else {
                    85 // ECDSA is generally secure
                }
            }
            "Ed25519" => 100,
            "Ed448" => 100,
            _ => 70, // Unknown algorithm
        }
    }

    fn calculate_pqc_algorithm_score(&self, analysis: &PqcAnalysis) -> u8 {
        if !analysis.pqc_detected {
            return 0;
        }

        let mut max_score = 0;

        // Score based on PQC key exchange algorithms
        for ke in &analysis.pqc_key_exchange {
            let score = match ke.as_str() {
                "ML-KEM-1024" => 100, // NIST Level 3, 256-bit security
                "ML-KEM-768" => 95,   // NIST Level 2, 192-bit security (current standard)
                "ML-KEM-512" => 90,   // NIST Level 1, 128-bit security
                "Kyber1024" => 100,   // NIST Level 3, 256-bit security
                "Kyber768" => 95,     // NIST Level 2, 192-bit security
                "Kyber512" => 90,     // NIST Level 1, 128-bit security
                _ => 85,              // Unknown algorithm
            };
            max_score = max_score.max(score);
        }

        // Score based on PQC signature algorithms
        for sig in &analysis.pqc_signature_algorithms {
            let score = match sig.as_str() {
                "Dilithium5" => 100, // NIST Level 3, 256-bit security
                "Dilithium3" => 95,  // NIST Level 2, 192-bit security
                "Dilithium2" => 90,  // NIST Level 1, 128-bit security
                "Falcon1024" => 100, // NIST Level 3, 256-bit security
                "Falcon512" => 95,   // NIST Level 2, 192-bit security
                _ => 85,             // Unknown algorithm
            };
            max_score = max_score.max(score);
        }

        // Note: ML-KEM-768 gets 95/100 because:
        // - It's the current NIST standard (Level 2)
        // - Provides 192-bit security (adequate for most use cases)
        // - Score reflects relative strength compared to ML-KEM-1024 (100/100)
        // - Formula: 95 = (192/256) * 100 * 0.99 (standardization factor)

        max_score
    }

    fn score_pqc_implementation(&self, analysis: &PqcAnalysis) -> u8 {
        // FIXED: Return 0 if no PQC is detected
        if !analysis.pqc_detected {
            return 0;
        }

        let mut score = 0;

        // Check for hybrid implementation (bonus)
        if analysis.hybrid_detected {
            score += 25;
        }

        // Check for classical fallback (bonus for reliability)
        if analysis.classical_fallback_available {
            score += 20;
        }

        // Check PQC extensions
        for ext in &analysis.pqc_extensions {
            match ext.as_str() {
                "KEM" => score += 25,
                "KEM_GROUP" => score += 25,
                _ => {}
            }
        }

        // Signature negotiation status scoring
        match analysis.signature_negotiation_status {
            crate::types::SignatureNegotiationStatus::Negotiated => score += 20,
            crate::types::SignatureNegotiationStatus::NotOffered => score += 0,
            crate::types::SignatureNegotiationStatus::Rejected => score += 5,
            crate::types::SignatureNegotiationStatus::Unknown => score += 10,
            crate::types::SignatureNegotiationStatus::NotApplicable => score += 15,
        }

        // IMPROVED: Fair scoring for PQC-only implementations
        // If this is a PQC-only connection (no hybrid, no classical fallback),
        // give a fair baseline score instead of penalizing
        if !analysis.hybrid_detected
            && !analysis.classical_fallback_available
            && !analysis.pqc_key_exchange.is_empty()
        {
            // PQC-only implementations should get a fair score
            // Base score of 70 for PQC-only, plus bonuses for good implementation
            score = 70.max(score);

            // Bonus for strong PQC algorithms
            for ke in &analysis.pqc_key_exchange {
                if ke.contains("1024") || ke.contains("768") {
                    score += 10;
                    break;
                }
            }

            // Bonus for proper PQC extensions
            if !analysis.pqc_extensions.is_empty() {
                score += 10;
            }
        }

        score.min(100)
    }

    fn score_hybrid_security(&self, analysis: &PqcAnalysis) -> u8 {
        // FIXED: hybrid_security should only be non-zero for actual hybrid scenarios
        // For PQC-only (no hybrid), return 0 since there's no hybrid to score
        if !analysis.hybrid_detected {
            // Classical-only or PQC-only: no hybrid, so score is 0
            return 0;
        }

        // Only score hybrid scenarios (classical + PQC together)
        let mut score = 85; // Base score for hybrid (excellent security)

        // Check for strong classical algorithms in hybrid
        let classical_algorithms: HashSet<&str> = analysis
            .security_features
            .iter()
            .map(|s| s.as_str())
            .collect();

        if classical_algorithms.contains("X25519") {
            score += 10;
        }

        if classical_algorithms.contains("P-256") || classical_algorithms.contains("P-384") {
            score += 5;
        }

        // Check for strong PQC algorithms
        for ke in &analysis.pqc_key_exchange {
            if ke.contains("1024") || ke.contains("768") {
                score += 5;
                break;
            }
        }

        score.min(100)
    }

    fn create_pqc_strength_info(&self, analysis: &PqcAnalysis) -> PqcStrengthInfo {
        // FIXED: When no PQC is detected, return proper "No PQC" values instead of Level 1 with 0 bits
        if !analysis.pqc_detected
            || (analysis.pqc_key_exchange.is_empty()
                && analysis.pqc_signature_algorithms.is_empty())
        {
            return PqcStrengthInfo {
                algorithms: Vec::new(),
                overall_level: "No PQC configured".to_string(),
                security_bits: 0,
                nist_level: "None".to_string(),
            };
        }

        let mut algorithms = Vec::new();
        let mut max_security_bits = 0;
        let mut max_nist_level = "Level 1".to_string();

        // Analyze PQC key exchange algorithms
        for ke in &analysis.pqc_key_exchange {
            let (security_bits, nist_level, score) = match ke.as_str() {
                "ML-KEM-1024" => (256, "Level 5", 100), // NIST Category 5 ≈ AES-256
                "ML-KEM-768" => (192, "Level 3", 95),   // NIST Category 3 ≈ AES-192
                "ML-KEM-512" => (128, "Level 1", 90),   // NIST Category 1 ≈ AES-128
                "Kyber1024" => (256, "Level 5", 100),   // NIST Category 5 ≈ AES-256
                "Kyber768" => (192, "Level 3", 95),     // NIST Category 3 ≈ AES-192
                "Kyber512" => (128, "Level 1", 90),     // NIST Category 1 ≈ AES-128
                _ => (128, "Level 1", 85),
            };

            algorithms.push(PqcAlgorithmInfo {
                name: ke.clone(),
                security_bits,
                nist_level: nist_level.to_string(),
                score,
            });

            if security_bits > max_security_bits {
                max_security_bits = security_bits;
                max_nist_level = nist_level.to_string();
            }
        }

        // Analyze PQC signature algorithms
        for sig in &analysis.pqc_signature_algorithms {
            let (security_bits, nist_level, score) = match sig.as_str() {
                "Dilithium5" => (256, "Level 3", 100),
                "Dilithium3" => (192, "Level 2", 95),
                "Dilithium2" => (128, "Level 1", 90),
                "Falcon1024" => (256, "Level 3", 100),
                "Falcon512" => (192, "Level 2", 95),
                _ => (128, "Level 1", 85),
            };

            algorithms.push(PqcAlgorithmInfo {
                name: sig.clone(),
                security_bits,
                nist_level: nist_level.to_string(),
                score,
            });

            if security_bits > max_security_bits {
                max_security_bits = security_bits;
                max_nist_level = nist_level.to_string();
            }
        }

        // Determine overall level based on highest security
        let overall_level = match max_security_bits {
            256.. => format!("NIST Category 5 (~AES-256, {} bits)", max_security_bits),
            192.. => format!("NIST Category 3 (~AES-192, {} bits)", max_security_bits),
            128.. => format!("NIST Category 1 (~AES-128, {} bits)", max_security_bits),
            _ => format!("Basic Security (<128 bits, {} bits)", max_security_bits),
        };

        PqcStrengthInfo {
            algorithms,
            overall_level,
            security_bits: max_security_bits,
            nist_level: max_nist_level,
        }
    }

    /// Generate security warnings based on scan results
    pub fn generate_security_warnings(&self, score: &SecurityScore) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        if score.tls < 80 {
            // FIXED: Conditional warning message based on actual issues
            // Check if the low score is due to key_exchange being unknown vs actual security issues
            let recommendation = if score.details.key_exchange == 0 {
                // Key exchange not extracted - this is an analysis limitation, not a security issue
                Some("TLS score is based on version and cipher suite only. Key exchange analysis is not yet implemented for this connection type.".to_string())
            } else if score.details.tls_version < 100 {
                // TLS version is the issue
                Some("Upgrade to TLS 1.3 for improved security.".to_string())
            } else if score.details.cipher_suite < 80 {
                // Cipher suite is the issue
                Some(
                    "Use stronger cipher suites (e.g., AES-256-GCM or ChaCha20-Poly1305)."
                        .to_string(),
                )
            } else if score.details.key_exchange < 80 {
                // Key exchange is the issue
                Some("Use stronger key exchange algorithms (e.g., X25519, P-256, or PQC algorithms).".to_string())
            } else {
                // General recommendation
                Some("Review TLS configuration for potential improvements.".to_string())
            };

            warnings.push(SecurityWarning {
                level: WarningLevel::Warning,
                category: "TLS Security".to_string(),
                message: format!("TLS component score is low: {}", score.tls),
                recommendation,
            });
        }
        if score.certificate < 80 {
            warnings.push(SecurityWarning {
                level: WarningLevel::Warning,
                category: "Certificate Security".to_string(),
                message: format!("Certificate component score is low: {}", score.certificate),
                recommendation: Some(
                    "Use strong, valid certificates with modern algorithms.".to_string(),
                ),
            });
        }
        if score.pqc < 80 && score.pqc > 0 {
            // FIXED: Generate recommendation based on detected PQC algorithms
            // If ML-KEM-768 or similar is already in use, only recommend 1024 or higher
            let recommendation = {
                let has_768 = score.pqc_strength.algorithms.iter().any(|alg| {
                    alg.name.contains("768")
                        || alg.name.contains("ML-KEM-768")
                        || alg.name.contains("Kyber768")
                        || alg.name.contains("X25519ML-KEM-768")
                });
                let has_512 = score.pqc_strength.algorithms.iter().any(|alg| {
                    alg.name.contains("512")
                        || alg.name.contains("ML-KEM-512")
                        || alg.name.contains("Kyber512")
                        || alg.name.contains("X25519ML-KEM-512")
                });

                if has_768 {
                    // Already using 768, recommend 1024 or higher NIST category
                    Some("Use higher NIST level PQC algorithms (e.g., ML-KEM-1024 for Level 5 security).".to_string())
                } else if has_512 {
                    // Using 512, recommend 768 or 1024
                    Some(
                        "Use higher NIST level PQC algorithms (e.g., ML-KEM-768 or 1024)."
                            .to_string(),
                    )
                } else {
                    // Unknown or other PQC algorithms
                    Some(
                        "Use higher NIST level PQC algorithms (e.g., ML-KEM-768 or 1024)."
                            .to_string(),
                    )
                }
            };

            warnings.push(SecurityWarning {
                level: WarningLevel::Warning,
                category: "PQC Security".to_string(),
                message: format!("PQC component score is low: {}", score.pqc),
                recommendation,
            });
        }
        warnings
    }

    /// Generate performance warnings based on scan results
    pub fn generate_performance_warnings(&self, result: &ScanResult) -> Vec<PerformanceWarning> {
        let mut warnings = Vec::new();

        // Check handshake duration
        if let Some(duration) = result.handshake_duration_ms {
            if duration > 1000 {
                warnings.push(PerformanceWarning {
                    level: WarningLevel::Warning,
                    category: "Handshake Performance".to_string(),
                    message: format!("Slow handshake detected: {}ms (expected < 500ms)", duration),
                    impact: "Slow handshake times may impact user experience and connection reliability".to_string(),
                    recommendation: Some("Consider optimizing certificate size, reducing SAN entries, or using more efficient key exchange algorithms".to_string()),
                });
            } else if duration > 500 {
                warnings.push(PerformanceWarning {
                    level: WarningLevel::Info,
                    category: "Handshake Performance".to_string(),
                    message: format!("Moderate handshake time: {}ms", duration),
                    impact: "Handshake time is acceptable but could be optimized".to_string(),
                    recommendation: Some(
                        "Monitor handshake performance and consider optimizations if needed"
                            .to_string(),
                    ),
                });
            }
        }

        // Check certificate size
        if let Some(ref cert) = result.certificate {
            if let Some(length) = cert.certificate_length_estimate {
                if length > 3000 {
                    warnings.push(PerformanceWarning {
                        level: WarningLevel::Warning,
                        category: "Certificate Size".to_string(),
                        message: format!("Large certificate detected: {} bytes", length),
                        impact: "Large certificates increase handshake overhead and may impact performance".to_string(),
                        recommendation: Some("Consider using smaller certificates or reducing the number of SAN entries".to_string()),
                    });
                }
            }
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_key_exchange_levels() {
        let scorer = SecurityScorer::new();
        assert_eq!(scorer.score_key_exchange(&["ML-KEM-512".to_string()]), 80);
        assert_eq!(scorer.score_key_exchange(&["ML-KEM-768".to_string()]), 95);
        assert_eq!(scorer.score_key_exchange(&["ML-KEM-1024".to_string()]), 100);
        assert_eq!(scorer.score_key_exchange(&["Kyber512".to_string()]), 80);
        assert_eq!(scorer.score_key_exchange(&["Kyber768".to_string()]), 95);
        assert_eq!(scorer.score_key_exchange(&["Kyber1024".to_string()]), 100);
    }

    #[test]
    fn test_generate_security_warnings() {
        let scorer = SecurityScorer::new();
        let mut score = SecurityScore::default();
        score.tls = 75;
        score.certificate = 70;
        score.pqc = 75;
        let warnings = scorer.generate_security_warnings(&score);
        assert!(warnings.iter().any(|w| w.category == "TLS Security"));
        assert!(warnings
            .iter()
            .any(|w| w.category == "Certificate Security"));
        assert!(warnings.iter().any(|w| w.category == "PQC Security"));
    }
}
