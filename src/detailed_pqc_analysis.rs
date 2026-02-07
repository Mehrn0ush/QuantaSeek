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

    /// Initialize KEM security properties
    fn initialize_kem_properties(&mut self) {
        // ML-KEM family
        self.kem_properties.insert(
            "ML-KEM-1024".to_string(),
            KemProperties {
                security_bits: 256,
                nist_level: "Level 3".to_string(),
                priority: 1,
            },
        );
        self.kem_properties.insert(
            "ML-KEM-768".to_string(),
            KemProperties {
                security_bits: 192,
                nist_level: "Level 2".to_string(),
                priority: 2,
            },
        );
        self.kem_properties.insert(
            "ML-KEM-512".to_string(),
            KemProperties {
                security_bits: 128,
                nist_level: "Level 1".to_string(),
                priority: 3,
            },
        );

        // Kyber family
        self.kem_properties.insert(
            "Kyber1024".to_string(),
            KemProperties {
                security_bits: 256,
                nist_level: "Level 3".to_string(),
                priority: 4,
            },
        );
        self.kem_properties.insert(
            "Kyber768".to_string(),
            KemProperties {
                security_bits: 192,
                nist_level: "Level 2".to_string(),
                priority: 5,
            },
        );
        self.kem_properties.insert(
            "Kyber512".to_string(),
            KemProperties {
                security_bits: 128,
                nist_level: "Level 1".to_string(),
                priority: 6,
            },
        );

        // Classical algorithms
        self.kem_properties.insert(
            "X25519".to_string(),
            KemProperties {
                security_bits: 128,
                nist_level: "Classical".to_string(),
                priority: 7,
            },
        );
        self.kem_properties.insert(
            "P-256".to_string(),
            KemProperties {
                security_bits: 128,
                nist_level: "Classical".to_string(),
                priority: 8,
            },
        );
        self.kem_properties.insert(
            "P-384".to_string(),
            KemProperties {
                security_bits: 192,
                nist_level: "Classical".to_string(),
                priority: 9,
            },
        );
    }

    /// Initialize extension type names
    fn initialize_extension_names(&mut self) {
        // TLS 1.3 extensions
        self.extension_names
            .insert(0x0000, "server_name".to_string());
        self.extension_names
            .insert(0x0001, "max_fragment_length".to_string());
        self.extension_names
            .insert(0x0002, "client_certificate_url".to_string());
        self.extension_names
            .insert(0x0003, "trusted_ca_keys".to_string());
        self.extension_names
            .insert(0x0004, "truncated_hmac".to_string());
        self.extension_names
            .insert(0x0005, "status_request".to_string());
        self.extension_names
            .insert(0x0006, "user_mapping".to_string());
        self.extension_names
            .insert(0x0007, "client_authz".to_string());
        self.extension_names
            .insert(0x0008, "server_authz".to_string());
        self.extension_names.insert(0x0009, "cert_type".to_string());
        self.extension_names
            .insert(0x000a, "supported_groups".to_string());
        self.extension_names
            .insert(0x000b, "ec_point_formats".to_string());
        self.extension_names.insert(0x000c, "srp".to_string());
        self.extension_names
            .insert(0x000d, "signature_algorithms".to_string());
        self.extension_names.insert(0x000e, "use_srtp".to_string());
        self.extension_names.insert(0x000f, "heartbeat".to_string());
        self.extension_names
            .insert(0x0010, "application_layer_protocol_negotiation".to_string());
        self.extension_names
            .insert(0x0011, "status_request_v2".to_string());
        self.extension_names
            .insert(0x0012, "signed_certificate_timestamp".to_string());
        self.extension_names
            .insert(0x0013, "client_certificate_type".to_string());
        self.extension_names
            .insert(0x0014, "server_certificate_type".to_string());
        self.extension_names.insert(0x0015, "padding".to_string());
        self.extension_names
            .insert(0x0016, "encrypt_then_mac".to_string());
        self.extension_names
            .insert(0x0017, "extended_master_secret".to_string());
        self.extension_names
            .insert(0x0018, "session_ticket".to_string());
        self.extension_names
            .insert(0x0019, "renegotiation_info".to_string());
        self.extension_names
            .insert(0x001a, "post_handshake_auth".to_string());
        self.extension_names
            .insert(0x001b, "signature_algorithms_cert".to_string());
        self.extension_names.insert(0x001c, "key_share".to_string());
        self.extension_names
            .insert(0x001d, "transparency_info".to_string());
        self.extension_names
            .insert(0x001e, "connection_id".to_string());
        self.extension_names
            .insert(0x001f, "connection_id_deprecated".to_string());
        self.extension_names
            .insert(0x0020, "external_id_hash".to_string());
        self.extension_names
            .insert(0x0021, "external_session_id".to_string());
        self.extension_names
            .insert(0x0022, "quic_transport_parameters".to_string());
        self.extension_names
            .insert(0x0023, "ticket_early_data_info".to_string());
        self.extension_names.insert(0x0024, "cookie".to_string());
        self.extension_names
            .insert(0x0025, "psk_key_exchange_modes".to_string());
        self.extension_names
            .insert(0x0026, "early_data".to_string());
        self.extension_names
            .insert(0x0027, "certificate_authorities".to_string());
        self.extension_names
            .insert(0x0028, "oid_filters".to_string());
        self.extension_names
            .insert(0x0029, "post_handshake_auth".to_string());
        self.extension_names
            .insert(0x002a, "signature_algorithms_cert".to_string());
        self.extension_names.insert(0x002b, "key_share".to_string());

        // PQC-specific extensions (draft numbers)
        self.extension_names.insert(0xfe00, "kem".to_string());
        self.extension_names.insert(0xfe01, "kem_group".to_string());
        self.extension_names
            .insert(0xfe02, "pqc_signature_algorithms".to_string());
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

            let pqc_related = matches!(
                ext_type,
                0xfe00..=0xfe02 // PQC-specific extensions
            );

            // Estimate data length if not provided
            let estimated_length = data_length.unwrap_or_else(|| {
                match ext_type {
                    0x000a => 16, // supported_groups: typically 16 bytes
                    0x001c => 32, // key_share: typically 32 bytes
                    0x000d => 8,  // signature_algorithms: typically 8 bytes
                    0xfe00 => 8,  // kem: typically 8 bytes
                    0xfe01 => 8,  // kem_group: typically 8 bytes
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

            let pqc_related = matches!(
                ext_type,
                0xfe00..=0xfe02 // PQC-specific extensions
            );

            // Estimate data length if not provided
            let estimated_length = data_length.unwrap_or_else(|| {
                match ext_type {
                    0x000a => 16, // supported_groups: typically 16 bytes
                    0x001c => 32, // key_share: typically 32 bytes
                    0x000d => 8,  // signature_algorithms: typically 8 bytes
                    0xfe00 => 8,  // kem: typically 8 bytes
                    0xfe01 => 8,  // kem_group: typically 8 bytes
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
            0..128 => "Level 0".to_string(),
            128..192 => "Level 1".to_string(),
            192..256 => "Level 2".to_string(),
            _ => "Level 3".to_string(),
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
        assert_eq!(
            negotiation.server_selected.as_ref().unwrap().name,
            "ML-KEM-768"
        );
        assert!(negotiation.preference_matched);
        assert_eq!(negotiation.total_candidates, 2);
    }

    #[test]
    fn test_extension_usage_analysis() {
        let analyzer = DetailedPqcAnalyzer::new();
        let client_extensions = vec![(0x001c, Some(100)), (0x000d, Some(50))]; // key_share, signature_algorithms
        let server_extensions = vec![(0x001c, Some(100))]; // key_share only
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
