use crate::types::{
    SecurityScore, SecurityScoreDetails, ScanResult, PqcAnalysis, CertificateInfo, 
    ScoringFormula, ScoringWeights, OverallWeights, TlsWeights, CertificateWeights, 
    PqcWeights, PqcStrengthInfo, PqcAlgorithmInfo, SecurityWarning, PerformanceWarning, WarningLevel
};
use std::collections::HashSet;
use chrono;

pub struct SecurityScorer;

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
        }
        
        // Calculate PQC score
        details.pqc_algorithm = self.calculate_pqc_algorithm_score(&result.analysis);
        details.pqc_implementation = self.score_pqc_implementation(&result.analysis);
        details.hybrid_security = self.score_hybrid_security(&result.analysis);
        
        let pqc_score = if result.pqc_detected {
            // PQC = (Algorithm + Implementation + Hybrid) / 3
            // Use floating-point division and round to get accurate score
            let raw_score = (details.pqc_algorithm as f32 + details.pqc_implementation as f32 + details.hybrid_security as f32) / 3.0;
            raw_score.round() as u8
        } else {
            0
        };
        
        // Calculate component scores with proper weighting
        let tls_score = self.calculate_tls_component_score(&details);
        let certificate_score = (details.certificate_validation + details.certificate_key_strength) / 2;
        
        // Calculate overall score with proper weighting
        let overall = if result.pqc_detected {
            // PQC-enabled connections: TLS(30%) + Certificate(25%) + PQC(45%)
            ((tls_score as u32 * 30 + certificate_score as u32 * 25 + pqc_score as u32 * 45) / 100) as u8
        } else {
            // Classical connections: TLS(50%) + Certificate(50%)
            ((tls_score as u32 * 50 + certificate_score as u32 * 50) / 100) as u8
        };
        
        // Create formula explanation
        let formula = ScoringFormula {
            overall_method: if result.pqc_detected {
                format!("Overall = TLS({}) + Certificate({}) + PQC({}) = {}×0.30 + {}×0.25 + {}×0.45 = {}", 
                    tls_score, certificate_score, pqc_score, tls_score, certificate_score, pqc_score, overall)
            } else {
                format!("Overall = TLS({}) + Certificate({}) = {}×0.50 + {}×0.50 = {}", 
                    tls_score, certificate_score, tls_score, certificate_score, overall)
            },
            tls_method: format!("TLS = Version({})×0.40 + Cipher({})×0.30 + KeyExchange({})×0.30 = {}×0.40 + {}×0.30 + {}×0.30 = {}", 
                details.tls_version, details.cipher_suite, details.key_exchange,
                details.tls_version, details.cipher_suite, details.key_exchange, tls_score),
            certificate_method: format!("Certificate = (Validation({}) + KeyStrength({})) / 2 = ({} + {}) / 2 = {}", 
                details.certificate_validation, details.certificate_key_strength,
                details.certificate_validation, details.certificate_key_strength, certificate_score),
            pqc_method: format!("PQC = (Algorithm({}) + Implementation({}) + Hybrid({})) / 3 = ({} + {} + {}) / 3 = {}", 
                details.pqc_algorithm, details.pqc_implementation, details.hybrid_security,
                details.pqc_algorithm, details.pqc_implementation, details.hybrid_security, pqc_score),
            pqc_weights: "TLS: 30%, Certificate: 25%, PQC: 45%".to_string(),
            classical_weights: "TLS: 50%, Certificate: 50%".to_string(),
        };
        
        // Create weights documentation
        let weights = ScoringWeights {
            overall_pqc: OverallWeights {
                tls_percentage: 30,
                certificate_percentage: 25,
                pqc_percentage: 45,
            },
            overall_classical: OverallWeights {
                tls_percentage: 50,
                certificate_percentage: 50,
                pqc_percentage: 0,
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
        
        SecurityScore {
            tls: tls_score,
            certificate: certificate_score,
            pqc: pqc_score,
            overall,
            details,
            formula,
            weights,
            pqc_strength,
        }
    }

    fn calculate_tls_component_score(&self, details: &SecurityScoreDetails) -> u8 {
        // TLS component: Version(40%) + Cipher(30%) + KeyExchange(30%)
        ((details.tls_version as u32 * 40 + details.cipher_suite as u32 * 30 + details.key_exchange as u32 * 30) / 100) as u8
    }

    fn score_tls_version(&self, version: &str) -> u8 {
        match version {
            "1.3" => 100,  // TLS 1.3 is the gold standard
            "1.2" => 70,   // TLS 1.2 is acceptable but not optimal
            "1.1" => 30,   // TLS 1.1 is deprecated
            "1.0" => 0,    // TLS 1.0 is insecure
            _ => 0,
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
                // PQC algorithms (NIST Level 1-3)
                "ML-KEM-1024" => 100,  // NIST Level 3
                "ML-KEM-768" => 95,    // NIST Level 2
                "ML-KEM-512" => 90,    // NIST Level 1
                "Kyber1024" => 100,    // NIST Level 3
                "Kyber768" => 95,      // NIST Level 2
                "Kyber512" => 90,      // NIST Level 1
                // Classical algorithms
                "X25519" => 90,        // Strong classical
                "P-256" => 85,         // Strong classical
                "P-384" => 90,         // Strong classical
                "P-521" => 95,         // Very strong classical
                // Weak algorithms
                "RSA" => 40,           // No forward secrecy
                _ => 70,               // Default for unknown
            };
        }
        
        if count > 0 {
            score / count
        } else {
            0
        }
    }

    fn score_certificate_validation(&self, result: &ScanResult) -> u8 {
        if let Some(ref cert) = result.certificate {
            let mut score = 100;
            
            // Check for hostname validation
            if result.analysis.security_features.contains(&"Hostname Mismatch".to_string()) {
                score -= 25; // Significant penalty for hostname mismatch
            }
            
            // Check for algorithm consistency
            if !cert.algorithm_consistency {
                // Penalize for algorithm inconsistency (e.g., ECDSA public key with RSA signature)
                score -= 15;
            }
            
            // Check for large SAN lists (performance impact)
            if let Some(san) = &cert.san {
                let san_count = san.split(',').count();
                if san_count > 100 {
                    score -= 10; // Penalty for very large SAN lists
                } else if san_count > 50 {
                    score -= 5;  // Minor penalty for large SAN lists
                }
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
            
            score.max(0).min(100)
        } else {
            0 // No certificate available
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
                        },
                        3072 => 95,     // Very good
                        2048 => 85,     // Good
                        1024 => 30,     // Weak
                        _ => 50,        // Unknown size
                    }
                } else {
                    70 // Unknown key size for RSA
                }
            },
            "ECDSA" => {
                if let Some(key_size) = cert.key_size {
                    match key_size {
                        521 => 100,     // P-521
                        384 => 95,      // P-384
                        256 => 90,      // P-256
                        _ => 80,        // Other curves
                    }
                } else {
                    85 // ECDSA is generally secure
                }
            },
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
                "Dilithium5" => 100,  // NIST Level 3, 256-bit security
                "Dilithium3" => 95,   // NIST Level 2, 192-bit security
                "Dilithium2" => 90,   // NIST Level 1, 128-bit security
                "Falcon1024" => 100,  // NIST Level 3, 256-bit security
                "Falcon512" => 95,    // NIST Level 2, 192-bit security
                _ => 85,              // Unknown algorithm
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
        
        // Check signature negotiation
        match analysis.signature_negotiation_status {
            crate::types::SignatureNegotiationStatus::Negotiated => score += 20,
            crate::types::SignatureNegotiationStatus::NotOffered => score += 10,
            crate::types::SignatureNegotiationStatus::Rejected => score += 5,
            crate::types::SignatureNegotiationStatus::Unknown => score += 10,
        }
        
        score.min(100)
    }

    fn score_hybrid_security(&self, analysis: &PqcAnalysis) -> u8 {
        if !analysis.hybrid_detected {
            return 0;
        }
        
        let mut score = 85; // Base score for hybrid (excellent security)
        
        // Check for strong classical algorithms in hybrid
        let classical_algorithms: HashSet<&str> = analysis.security_features
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
        let mut algorithms = Vec::new();
        let mut max_security_bits = 0;
        let mut max_nist_level = "Level 1".to_string();
        
        // Analyze PQC key exchange algorithms
        for ke in &analysis.pqc_key_exchange {
            let (security_bits, nist_level, score) = match ke.as_str() {
                "ML-KEM-1024" => (256, "Level 3", 100),
                "ML-KEM-768" => (192, "Level 2", 95),
                "ML-KEM-512" => (128, "Level 1", 90),
                "Kyber1024" => (256, "Level 3", 100),
                "Kyber768" => (192, "Level 2", 95),
                "Kyber512" => (128, "Level 1", 90),
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
            256.. => "Maximum Security (256+ bits)".to_string(),
            192.. => "High Security (192 bits)".to_string(),
            128.. => "Standard Security (128 bits)".to_string(),
            _ => "Basic Security (<128 bits)".to_string(),
        };
        
        PqcStrengthInfo {
            algorithms,
            overall_level,
            security_bits: max_security_bits,
            nist_level: max_nist_level,
        }
    }

    /// Generate security warnings based on scan results
    pub fn generate_security_warnings(&self, result: &ScanResult) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        
        if let Some(ref cert) = result.certificate {
            // Check for hostname mismatch
            if result.analysis.security_features.contains(&"Hostname Mismatch".to_string()) {
                warnings.push(SecurityWarning {
                    level: WarningLevel::Critical,
                    category: "Certificate Validation".to_string(),
                    message: "Hostname mismatch detected - certificate subject does not match the target hostname".to_string(),
                    recommendation: Some("Ensure the certificate's Subject Alternative Names (SAN) includes the correct hostname".to_string()),
                });
            }
            
            // Check for non-standard RSA key sizes
            if cert.public_key_algorithm == "RSA" {
                if let Some(key_size) = cert.key_size {
                    if key_size > 4096 && key_size < 8192 {
                        warnings.push(SecurityWarning {
                            level: WarningLevel::Warning,
                            category: "Certificate Key Size".to_string(),
                            message: format!("Non-standard RSA key size detected: {} bits (expected 2048, 3072, or 4096)", key_size),
                            recommendation: Some("Consider using standard RSA key sizes (2048, 3072, or 4096 bits) for better compatibility".to_string()),
                        });
                    }
                }
            }
            
            // Check for algorithm inconsistency
            if !cert.algorithm_consistency {
                warnings.push(SecurityWarning {
                    level: WarningLevel::Warning,
                    category: "Certificate Algorithms".to_string(),
                    message: "Certificate public key and signature algorithms are inconsistent".to_string(),
                    recommendation: Some("Ensure the certificate uses consistent algorithms for both public key and signature".to_string()),
                });
            }
            
            // Check for large SAN lists
            if let Some(san) = &cert.san {
                let san_count = san.split(',').count();
                if san_count > 100 {
                    warnings.push(SecurityWarning {
                        level: WarningLevel::Warning,
                        category: "Certificate SAN".to_string(),
                        message: format!("Certificate contains {} SAN entries, which may impact performance", san_count),
                        recommendation: Some("Consider reducing the number of SAN entries to improve handshake performance".to_string()),
                    });
                }
            }
        }
        
        // Check for PQC signature status confusion
        if result.analysis.pqc_signature_used && result.analysis.pqc_signature_algorithm.is_none() {
            warnings.push(SecurityWarning {
                level: WarningLevel::Info,
                category: "PQC Signatures".to_string(),
                message: "PQC signature algorithms are offered but actual usage cannot be confirmed in TLS 1.3".to_string(),
                recommendation: Some("PQC signatures are negotiated but encrypted in TLS 1.3. This is normal behavior.".to_string()),
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
                    recommendation: Some("Monitor handshake performance and consider optimizations if needed".to_string()),
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