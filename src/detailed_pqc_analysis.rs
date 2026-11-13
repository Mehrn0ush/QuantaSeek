use crate::types::{
    AlgorithmType, CombinedSecurity, ExtensionInfo, ExtensionStatus, ExtensionUsage,
    FallbackAnalysis, HybridComponent, HybridDetails, HybridEfficiency, KemCandidate,
    KemNegotiation, KemStatus, PqcAnalysis,
};
use std::collections::HashMap;

/// Detailed PQC Analysis Engine
pub struct DetailedPqcAnalyzer {
    /// Mapping of KEM names to their security properties
    kem_properties: HashMap<String, KemProperties>,
    /// Mapping of extension types to their names
    extension_names: HashMap<u16, String>,
}

/// Security properties of KEM algorithms
#[derive(Debug, Clone)]
struct KemProperties {
    security_bits: u32,
    nist_level: String,
    priority: u32,
}

impl Default for DetailedPqcAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DetailedPqcAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            kem_properties: HashMap::new(),
            extension_names: HashMap::new(),
        };

        // Initialize KEM properties
        analyzer.initialize_kem_properties();
        analyzer.initialize_extension_names();

        analyzer
    }

    /// Initialize KEM security properties.
    ///
    /// NIST security categories are from FIPS 203 §8 (ML-KEM-512: 1,
    /// ML-KEM-768: 3, ML-KEM-1024: 5). A hybrid group is rated by its PQ
    /// component. Classical groups are labelled "Classical" (no PQ category).
    fn initialize_kem_properties(&mut self) {
        let entries: &[(&str, u32, &str, u32)] = &[
            ("MLKEM1024", 256, "Category 5", 1),
            ("SecP384r1MLKEM1024", 256, "Category 5", 2),
            ("MLKEM1024X448", 256, "Category 5", 3),
            ("X25519MLKEM768", 192, "Category 3", 4),
            ("SecP256r1MLKEM768", 192, "Category 3", 5),
            ("MLKEM768", 192, "Category 3", 6),
            ("MLKEM512", 128, "Category 1", 7),
            (
                "X25519Kyber768Draft00",
                192,
                "Category 3 (pre-standard Kyber)",
                8,
            ),
            (
                "SecP256r1Kyber768Draft00",
                192,
                "Category 3 (pre-standard Kyber)",
                9,
            ),
            ("x25519", 128, "Classical", 10),
            ("secp256r1", 128, "Classical", 11),
            ("secp384r1", 192, "Classical", 12),
            ("secp521r1", 256, "Classical", 13),
            ("X25519", 128, "Classical", 10),
            ("P-256", 128, "Classical", 11),
            ("P-384", 192, "Classical", 12),
            // Bare KEM names used by callers and tests
            ("ML-KEM-1024", 256, "Category 5", 1),
            ("ML-KEM-768", 192, "Category 3", 6),
            ("ML-KEM-512", 128, "Category 1", 7),
        ];
        for &(name, security_bits, nist_level, priority) in entries {
            self.kem_properties.insert(
                name.to_string(),
                KemProperties {
                    security_bits,
                    nist_level: nist_level.to_string(),
                    priority,
                },
            );
        }
    }

    /// Extension names come from the IANA registry in [`crate::constants`].
    fn initialize_extension_names(&mut self) {
        for ext in 0u16..=57 {
            if let Some(name) = crate::constants::extension_name(ext) {
                self.extension_names.insert(ext, name.to_string());
            }
        }
        for ext in [65037u16, 65281] {
            if let Some(name) = crate::constants::extension_name(ext) {
                self.extension_names.insert(ext, name.to_string());
            }
        }
    }

    /// Analyze KEM negotiation from handshake data
    pub fn analyze_kem_negotiation(
        &self,
        client_offered_kems: &[String],
        server_selected_kem: Option<&str>,
        _key_exchange_result: &[String],
    ) -> KemNegotiation {
        let mut client_candidates = Vec::new();
        let mut negotiation_order = Vec::new();

        // Process client-offered KEMs
        for (index, kem_name) in client_offered_kems.iter().enumerate() {
            let default_properties = KemProperties {
                security_bits: 128,
                nist_level: "Unknown".to_string(),
                priority: 100 + index as u32,
            };

            let properties = self
                .kem_properties
                .get(kem_name)
                .unwrap_or(&default_properties);

            let status = if let Some(selected) = server_selected_kem {
                if selected == kem_name {
                    KemStatus::Selected
                } else {
                    KemStatus::Offered
                }
            } else {
                KemStatus::Offered
            };

            client_candidates.push(KemCandidate {
                name: kem_name.clone(),
                security_bits: properties.security_bits,
                nist_level: properties.nist_level.clone(),
                priority: properties.priority,
                status,
            });

            negotiation_order.push(kem_name.clone());
        }

        // Determine server selection
        let server_selected = if let Some(selected_kem) = server_selected_kem {
            let default_properties = KemProperties {
                security_bits: 128,
                nist_level: "Unknown".to_string(),
                priority: 0,
            };

            let properties = self
                .kem_properties
                .get(selected_kem)
                .unwrap_or(&default_properties);

            Some(KemCandidate {
                name: selected_kem.to_string(),
                security_bits: properties.security_bits,
                nist_level: properties.nist_level.clone(),
                priority: properties.priority,
                status: KemStatus::Selected,
            })
        } else {
            None
        };

        // Check if server selection matches client preference
        let preference_matched = if let (Some(selected), Some(first_offered)) =
            (server_selected_kem, client_offered_kems.first())
        {
            selected == first_offered
        } else {
            false
        };

        KemNegotiation {
            client_offered: client_candidates,
            server_selected,
            negotiation_order,
            preference_matched,
            total_candidates: client_offered_kems.len() as u32,
        }
    }

    /// Analyze extension usage from handshake data
    pub fn analyze_extension_usage(
        &self,
        client_extensions: &[(u16, Option<u32>)],
        server_extensions: &[(u16, Option<u32>)],
        _pqc_extensions: &[String],
    ) -> ExtensionUsage {
        let mut client_offered = Vec::new();
        let mut server_used = Vec::new();
        let mut rejected = Vec::new();

        // Process client extensions
        for (ext_type, data_length) in client_extensions {
            let ext_name = self
                .extension_names
                .get(ext_type)
                .unwrap_or(&format!("Unknown(0x{:04x})", ext_type))
                .clone();

            // TLS 1.3 has no PQC-specific extensions; PQC uses supported_groups/key_share.
            let pqc_related = false;

            // Estimate data length if not provided
            let estimated_length = data_length.unwrap_or_else(|| {
                match ext_type {
                    0x000a => 16, // supported_groups: typically 16 bytes
                    0x0033 => 32, // key_share: estimated
                    0x000d => 8,  // signature_algorithms: typically 8 bytes
                    _ => 0,
                }
            });

            // If extension is in client list, it was offered
            let status = ExtensionStatus::Present;

            client_offered.push(ExtensionInfo {
                name: ext_name.clone(),
                extension_type: *ext_type,
                status,
                data_length: Some(estimated_length),
                pqc_related,
            });
        }

        // Process server extensions
        for (ext_type, data_length) in server_extensions {
            let ext_name = self
                .extension_names
                .get(ext_type)
                .unwrap_or(&format!("Unknown(0x{:04x})", ext_type))
                .clone();

            // TLS 1.3 has no PQC-specific extensions; PQC uses supported_groups/key_share.
            let pqc_related = false;

            // Estimate data length if not provided
            let estimated_length = data_length.unwrap_or_else(|| {
                match ext_type {
                    0x000a => 16, // supported_groups: typically 16 bytes
                    0x0033 => 32, // key_share: estimated
                    0x000d => 8,  // signature_algorithms: typically 8 bytes
                    _ => 0,
                }
            });

            server_used.push(ExtensionInfo {
                name: ext_name,
                extension_type: *ext_type,
                status: ExtensionStatus::Present,
                data_length: Some(estimated_length),
                pqc_related,
            });
        }

        // Find rejected extensions (offered by client but not used by server)
        for client_ext in &client_offered {
            let was_used = server_extensions
                .iter()
                .any(|(ext_type, _)| *ext_type == client_ext.extension_type);

            if !was_used {
                rejected.push(client_ext.clone());
            }
        }

        // Count PQC extensions
        let total_pqc_extensions =
            client_offered.iter().filter(|ext| ext.pqc_related).count() as u32;

        // Check if full PQC support is present
        let full_pqc_support = total_pqc_extensions >= 2; // At least KEM and KEM_GROUP

        ExtensionUsage {
            client_offered,
            server_used,
            rejected,
            total_pqc_extensions,
            full_pqc_support,
        }
    }

    /// Analyze hybrid combination details
    pub fn analyze_hybrid_details(
        &self,
        key_exchange: &[String],
        handshake_duration_ms: Option<u64>,
        classical_fallback_available: bool,
    ) -> HybridDetails {
        let mut combination = Vec::new();
        let mut classical_algorithms = Vec::new();
        let mut pqc_algorithms = Vec::new();

        // Separate classical and PQC algorithms
        for kem_name in key_exchange {
            let default_properties = KemProperties {
                security_bits: 128,
                nist_level: "Unknown".to_string(),
                priority: 100,
            };

            let properties = self
                .kem_properties
                .get(kem_name)
                .unwrap_or(&default_properties);

            let algorithm_type = if properties.nist_level == "Classical" {
                classical_algorithms.push(kem_name.clone());
                AlgorithmType::Classical
            } else {
                pqc_algorithms.push(kem_name.clone());
                AlgorithmType::Pqc
            };

            let weight = if algorithm_type == AlgorithmType::Pqc {
                0.7
            } else {
                0.3
            };

            combination.push(HybridComponent {
                name: kem_name.clone(),
                algorithm_type,
                security_bits: properties.security_bits,
                nist_level: properties.nist_level.clone(),
                weight,
            });
        }

        // Calculate combined security
        let combined_security = self.calculate_combined_security(&combination);

        // Analyze fallback path
        let fallback_analysis = if classical_fallback_available && !classical_algorithms.is_empty()
        {
            Some(self.analyze_fallback_path(&classical_algorithms))
        } else {
            None
        };

        // Calculate efficiency metrics
        let efficiency = self.calculate_hybrid_efficiency(handshake_duration_ms, &combination);

        HybridDetails {
            combination,
            combined_security,
            fallback_analysis,
            efficiency,
        }
    }

    /// Calculate combined security strength of hybrid combination
    fn calculate_combined_security(&self, combination: &[HybridComponent]) -> CombinedSecurity {
        let mut min_security_bits = u32::MAX;
        let mut max_security_bits = 0;
        let mut has_pqc = false;
        let mut has_classical = false;
        let mut classical_bits = 0;
        let mut pqc_bits = 0;

        for component in combination {
            min_security_bits = min_security_bits.min(component.security_bits);
            max_security_bits = max_security_bits.max(component.security_bits);

            match component.algorithm_type {
                AlgorithmType::Pqc => {
                    has_pqc = true;
                    pqc_bits = component.security_bits;
                }
                AlgorithmType::Classical => {
                    has_classical = true;
                    classical_bits = component.security_bits;
                }
                AlgorithmType::Hybrid => {
                    has_pqc = true;
                    has_classical = true;
                    pqc_bits = component.security_bits;
                    classical_bits = component.security_bits;
                }
            }
        }

        // Calculate weighted hybrid security score
        let effective_bits = if has_pqc && has_classical {
            // Hybrid: effective security is the minimum (weakest link)
            min_security_bits
        } else if has_pqc {
            // PQC-only: use PQC bits
            pqc_bits
        } else {
            // Classical-only: use classical bits
            classical_bits
        };

        // Determine NIST level based on effective bits
        let nist_level = match effective_bits {
            // Bits-to-category mapping per NIST PQC security categories
            // (1 ~ AES-128, 3 ~ AES-192, 5 ~ AES-256).
            0..128 => "Below Category 1".to_string(),
            128..192 => "Category 1".to_string(),
            192..256 => "Category 3".to_string(),
            _ => "Category 5".to_string(),
        };

        // Calculate score on 100-point scale using weighted formula
        let score = if has_pqc && has_classical {
            // Hybrid scoring: (classical_bits * 0.4 + pqc_bits * 0.6) / 2

            ((classical_bits as f64 * 0.4 + pqc_bits as f64 * 0.6) / 2.0) as u8
        } else if has_pqc {
            // PQC-only: standard scoring
            (effective_bits as f64 / 256.0 * 100.0) as u8
        } else {
            // Classical-only: reduced score
            (effective_bits as f64 / 256.0 * 80.0) as u8
        };

        // Create calculation method description
        let calculation_method = if has_pqc && has_classical {
            format!(
                "Weighted hybrid security (40% classical({} bits), 60% PQC({} bits)) / 2",
                classical_bits, pqc_bits
            )
        } else if has_pqc {
            format!("PQC-only security ({} bits)", pqc_bits)
        } else {
            format!("Classical-only security ({} bits)", classical_bits)
        };

        CombinedSecurity {
            effective_bits,
            nist_level,
            score,
            calculation_method,
            quantum_resistant: has_pqc,
        }
    }

    /// Analyze fallback path to classical algorithms
    fn analyze_fallback_path(&self, classical_algorithms: &[String]) -> FallbackAnalysis {
        let mut max_security_bits = 0;

        for alg in classical_algorithms {
            if let Some(properties) = self.kem_properties.get(alg) {
                max_security_bits = max_security_bits.max(properties.security_bits);
            }
        }

        FallbackAnalysis {
            classical_algorithms: classical_algorithms.to_vec(),
            fallback_security_bits: max_security_bits,
            time_penalty_ms: Some(200), // Estimated fallback penalty
            successful: true,
            trigger_reason: Some("PQC handshake failed, falling back to classical".to_string()),
        }
    }

    /// Calculate hybrid efficiency metrics
    fn calculate_hybrid_efficiency(
        &self,
        _handshake_duration_ms: Option<u64>,
        combination: &[HybridComponent],
    ) -> HybridEfficiency {
        let has_pqc = combination
            .iter()
            .any(|c| c.algorithm_type == AlgorithmType::Pqc);
        let has_classical = combination
            .iter()
            .any(|c| c.algorithm_type == AlgorithmType::Classical);

        let handshake_overhead_ms = if has_pqc && has_classical {
            // Estimate overhead for hybrid vs classical-only
            Some(150) // Typical overhead for hybrid handshake
        } else {
            None
        };

        let bandwidth_overhead_bytes = if has_pqc {
            // PQC algorithms typically have larger key sizes
            Some(1024) // Estimated overhead
        } else {
            None
        };

        let cpu_overhead_percent = if has_pqc {
            Some(25.0) // Estimated CPU overhead for PQC operations
        } else {
            None
        };

        let memory_overhead_bytes = if has_pqc {
            Some(2048) // Estimated memory overhead
        } else {
            None
        };

        HybridEfficiency {
            handshake_overhead_ms,
            bandwidth_overhead_bytes,
            cpu_overhead_percent,
            memory_overhead_bytes,
        }
    }

    /// Update PQC analysis with detailed information
    pub fn update_pqc_analysis(
        &self,
        analysis: &mut PqcAnalysis,
        client_offered_kems: &[String],
        server_selected_kem: Option<&str>,
        key_exchange: &[String],
        client_extensions: &[(u16, Option<u32>)],
        server_extensions: &[(u16, Option<u32>)],
        handshake_duration_ms: Option<u64>,
    ) {
        // Analyze KEM negotiation
        analysis.kem_negotiation = Some(self.analyze_kem_negotiation(
            client_offered_kems,
            server_selected_kem,
            key_exchange,
        ));

        // Analyze extension usage
        analysis.extension_usage = Some(self.analyze_extension_usage(
            client_extensions,
            server_extensions,
            &analysis.pqc_extensions,
        ));

        // Analyze hybrid details
        analysis.hybrid_details = Some(self.analyze_hybrid_details(
            key_exchange,
            handshake_duration_ms,
            analysis.classical_fallback_available,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_negotiation_analysis() {
        let analyzer = DetailedPqcAnalyzer::new();
        let client_offered = vec!["ML-KEM-768".to_string(), "ML-KEM-512".to_string()];
        let server_selected = Some("ML-KEM-768");
        let key_exchange = vec!["X25519".to_string(), "ML-KEM-768".to_string()];

        let negotiation =
            analyzer.analyze_kem_negotiation(&client_offered, server_selected, &key_exchange);

        assert_eq!(negotiation.client_offered.len(), 2);
        // Ensure server_selected is present and has the expected name without panicking
        assert!(negotiation.server_selected.is_some());
        assert_eq!(negotiation.server_selected.unwrap().name, "ML-KEM-768");
        assert!(negotiation.preference_matched);
        assert_eq!(negotiation.total_candidates, 2);
    }

    #[test]
    fn test_extension_usage_analysis() {
        let analyzer = DetailedPqcAnalyzer::new();
        let client_extensions = vec![(0x0033, Some(100)), (0x000d, Some(50))]; // key_share, signature_algorithms
        let server_extensions = vec![(0x0033, Some(100))]; // key_share only
        let pqc_extensions = vec!["kem".to_string(), "kem_group".to_string()];

        let usage = analyzer.analyze_extension_usage(
            &client_extensions,
            &server_extensions,
            &pqc_extensions,
        );

        assert_eq!(usage.client_offered.len(), 2);
        assert_eq!(usage.server_used.len(), 1);
        assert_eq!(usage.rejected.len(), 1);
    }

    #[test]
    fn test_hybrid_analysis() {
        let analyzer = DetailedPqcAnalyzer::new();
        let key_exchange = vec!["X25519".to_string(), "ML-KEM-768".to_string()];
        let handshake_duration = Some(400);

        let hybrid = analyzer.analyze_hybrid_details(&key_exchange, handshake_duration, true);

        assert_eq!(hybrid.combination.len(), 2);
        assert!(hybrid.combined_security.quantum_resistant);
        assert!(hybrid.fallback_analysis.is_some());
        assert!(hybrid.efficiency.handshake_overhead_ms.is_some());
    }
}
