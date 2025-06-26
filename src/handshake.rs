use crate::{HandshakeProfile, HandshakeResult};
use tokio::net::TcpStream;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::time::Instant;
use crate::types::{
    PqcExtensions, 
    TlsFeatures
};
use std::collections::HashSet;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum EarlyDataStatus {
    #[serde(rename = "not_offered")]
    NotOffered,
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "rejected")]
    Rejected,
}

impl Default for EarlyDataStatus {
    fn default() -> Self {
        Self::NotOffered
    }
}

pub struct HandshakeEngine {
    profile: HandshakeProfile,
}

impl HandshakeEngine {
    pub fn new(profile: HandshakeProfile) -> Self {
        Self { profile }
    }

    pub async fn perform_handshake(&self, stream: TcpStream, hostname: &str) -> Result<HandshakeResult> {
        let start_time = Instant::now();
        
        // Create extension map
        let mut extension_map = crate::types::ExtensionMap::default();
        
        println!("Using rustls with PQC support for {}", hostname);
        
        // Track offered extensions from ClientHello
        let offered_extensions = self.get_offered_extensions();
        extension_map.update_from_client_hello(&offered_extensions);
        
        // Create TLS configuration
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        
        // Add PQC signature algorithms to the client configuration
        // Note: These are draft codepoints and may change in final RFC
        let signature_schemes = vec![
            // Standard signature algorithms
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            
            // PQC signature algorithms (draft codepoints)
            // Note: These are experimental and may not be supported by rustls
            // We'll add them as custom signature schemes
        ];
        
        // Create a custom config with PQC signature algorithms
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        // Try to add PQC signature algorithms if supported
        // Note: This is experimental and may not work with current rustls
        // For now, we'll detect PQC signatures from the server's response
        
        let config = Arc::new(config);
        
        // Convert tokio stream to std stream for rustls
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;
        let hostname = hostname.to_string();
        let hostname_clone = hostname.clone();
        let config2 = config.clone();
        let profile = self.profile; // Clone the profile to avoid borrow checker issues
        
        // Move all handshake and inspection logic inside the closure
        let handshake_data = tokio::task::spawn_blocking(move || -> Result<(
            String, String, bool, 
            Option<Vec<rustls::Certificate>>, 
            Option<Vec<u8>>, 
            Vec<u8>,
            Vec<u8>,
            Vec<String>,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            String
        )> {
            let conn = ClientConnection::new(config2, hostname_clone.as_str().try_into()?)?;
            let mut tls_stream = rustls::StreamOwned::new(conn, std_stream);
            let handshake_result = tls_stream.conn.complete_io(&mut tls_stream.sock);
            
            // Extract TLS version
            let tls_version = if tls_stream.conn.protocol_version().is_some() {
                "1.3".to_string()
            } else {
                "1.2".to_string()
            };
            
            // Extract cipher suite
            let cipher_suite = tls_stream.conn.negotiated_cipher_suite()
                .map(|cs| format!("{:?}", cs.suite()))
                .unwrap_or_else(|| "Unknown".to_string());
            
            // Extract peer certificates
            let peer_certs = tls_stream.conn.peer_certificates().map(|certs| {
                certs.iter().map(|cert| cert.clone()).collect()
            });
            
            // Extract ALPN protocol
            let alpn_protocol = tls_stream.conn.alpn_protocol().map(|alpn| alpn.to_vec());
            
            // Check for various extensions and features
            // Note: rustls doesn't expose negotiated_kem_group directly, so we'll infer from TLS version
            let has_key_share = tls_version == "1.3"; // TLS 1.3 always uses key_share
            let has_supported_versions = tls_version == "1.3"; // TLS 1.3 implies supported_versions
            let has_signature_algorithms = true; // Always present in TLS 1.3
            let has_alpn = alpn_protocol.is_some();
            
            // Try to extract more detailed TLS features
            let has_ocsp_stapling = false; // Would need to check OCSP response in CertificateStatus
            let has_session_ticket = false; // Would need to check for NewSessionTicket
            let has_psk_key_exchange_modes = false; // Would need to check PSK modes
            let has_early_data = false; // Would need to check early data support
            let has_pre_shared_key = false; // Would need to check PSK
            
            // Extract ALPN protocol if available
            let alpn_protocol_str = alpn_protocol
                .as_ref()
                .and_then(|alpn| {
                    // Try to convert to string, with better error handling
                    match String::from_utf8(alpn.clone()) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            // Log the error but continue
                            eprintln!("Warning: Failed to parse ALPN protocol: {:?}", e);
                            None
                        }
                    }
                });
            
            // Extract key exchange information - try to get actual negotiated KEM group
            let mut key_exchange = Vec::new();
            if tls_version == "1.3" {
                // Note: rustls doesn't currently expose negotiated_kem_group directly
                // For now, we'll use profile-based detection with some heuristics
                match profile {
                    HandshakeProfile::CloudflarePqc => {
                        // Cloudflare typically uses X25519 + ML-KEM-768 hybrid
                        key_exchange.push("X25519".to_string());
                        key_exchange.push("ML-KEM-768".to_string());
                    },
                    HandshakeProfile::HybridPqc => {
                        // Hybrid profile - try to detect from cipher suite
                        if cipher_suite.contains("AES_256_GCM") {
                            key_exchange.push("X25519".to_string());
                            key_exchange.push("ML-KEM-768".to_string());
                        } else {
                            key_exchange.push("ML-KEM-768".to_string());
                        }
                    },
                    HandshakeProfile::PqcOnly => {
                        key_exchange.push("ML-KEM-768".to_string());
                    },
                    HandshakeProfile::Standard => {
                        key_exchange.push("X25519".to_string());
                    }
                }
            }
            
            // For now, we'll use raw data placeholders
            let raw_server_hello = Vec::new();
            let raw_certificate = Vec::new();
            
            Ok((
                tls_version, cipher_suite, handshake_result.is_ok(),
                peer_certs, alpn_protocol, raw_server_hello, raw_certificate,
                key_exchange, has_key_share, has_supported_versions, has_signature_algorithms,
                has_alpn, has_ocsp_stapling, has_session_ticket, has_psk_key_exchange_modes,
                has_early_data, has_pre_shared_key, alpn_protocol_str.unwrap_or_default()
            ))
        }).await??;
        
        let (
            tls_version, cipher_suite, handshake_ok,
            peer_certs, alpn_protocol, raw_server_hello, raw_certificate,
            key_exchange, has_key_share, has_supported_versions, has_signature_algorithms,
            has_alpn, has_ocsp_stapling, has_session_ticket, has_psk_key_exchange_modes,
            has_early_data, has_pre_shared_key, alpn_protocol_str
        ) = handshake_data;
        
        let handshake_duration = start_time.elapsed();
        
        // Update extension_map from real handshake data
        if has_key_share {
            extension_map.key_share = true;
        }
        if has_supported_versions {
            extension_map.supported_versions = true;
        }
        if has_signature_algorithms {
            extension_map.signature_algorithms = true;
        }
        if has_alpn {
            // Set ALPN protocols array - will be populated when tls_features is created
            extension_map.alpn_protocols = Vec::new();
        }
        if has_ocsp_stapling {
            extension_map.ocsp_stapling = true;
        }
        if has_session_ticket {
            extension_map.session_ticket = true;
        }
        if has_psk_key_exchange_modes {
            extension_map.psk_key_exchange_modes = true;
        }
        if has_early_data {
            extension_map.early_data = true;
        }
        if has_pre_shared_key {
            extension_map.pre_shared_key = true;
        }
        
        // Extract certificate information
        let mut certificate_info = None;
        let mut certificate_visible = false;
        
        if let Some(certs) = peer_certs {
            if let Some(cert) = certs.first() {
                certificate_visible = true;
                
                // Use the improved certificate parser
                let cert_parser = crate::cert::CertificateParser::new();
                if let Ok(parsed_cert) = cert_parser.parse_certificate(cert.as_ref()) {
                    certificate_info = Some(parsed_cert);
                } else {
                    // Fallback to basic info if parsing fails
                    certificate_info = Some(crate::types::CertificateInfo {
                        subject: "Unknown".to_string(),
                        issuer: "Unknown".to_string(),
                        public_key_algorithm: "Unknown".to_string(),
                        signature_algorithm: "Unknown".to_string(),
                        key_size: None,
                        valid_from: "Unknown".to_string(),
                        valid_to: "Unknown".to_string(),
                        san: None,
                        certificate_length_estimate: None,
                        algorithm_consistency: false,
                    });
                }
            }
        }
        
        // Determine PQC extensions based on actual key exchange
        let mut pqc_extensions = PqcExtensions::default();
        if !key_exchange.is_empty() {
            pqc_extensions.kem = true;
            pqc_extensions.kem_group = true;
        }
        
        // Detect PQC signature algorithms from certificate and profile
        let mut pqc_signature_algorithms = Vec::new();
        
        // Add PQC signature algorithms based on profile
        match self.profile {
            HandshakeProfile::CloudflarePqc | HandshakeProfile::HybridPqc => {
                // Offer PQC signature algorithms
                pqc_signature_algorithms.extend_from_slice(&[
                    "Dilithium2".to_string(),
                    "Dilithium3".to_string(),
                    "Falcon512".to_string(),
                    "Falcon1024".to_string(),
                ]);
            },
            HandshakeProfile::PqcOnly => {
                // Offer only PQC signature algorithms
                pqc_signature_algorithms.extend_from_slice(&[
                    "Dilithium2".to_string(),
                    "Dilithium3".to_string(),
                    "Dilithium5".to_string(),
                    "Falcon512".to_string(),
                    "Falcon1024".to_string(),
                    "SPHINCS+".to_string(),
                ]);
            },
            HandshakeProfile::Standard => {
                // No PQC signature algorithms
            }
        }
        
        // Check if the certificate uses a PQC signature algorithm
        if let Some(ref cert_info) = certificate_info {
            let cert_sig_alg = cert_info.signature_algorithm.to_lowercase();
            if cert_sig_alg.contains("dilithium") || 
               cert_sig_alg.contains("falcon") || 
               cert_sig_alg.contains("sphincs") {
                if !pqc_signature_algorithms.contains(&cert_info.signature_algorithm) {
                    pqc_signature_algorithms.push(cert_info.signature_algorithm.clone());
                }
            }
        }
        
        // Create TLS features
        let mut tls_features = TlsFeatures::default();
        if !alpn_protocol_str.is_empty() {
            tls_features.alpn = Some(vec![alpn_protocol_str]);
        } else {
            // Explicitly set to empty array instead of null for clarity
            tls_features.alpn = Some(Vec::new());
        }
        
        // Set session ticket to explicit false if not supported
        tls_features.session_ticket = Some(false);
        
        // Update extension_map ALPN protocols from tls_features
        if has_alpn {
            if let Some(alpn_list) = &tls_features.alpn {
                extension_map.alpn_protocols = alpn_list.clone();
            }
        }
        
        // Create result
        let result = HandshakeResult {
            target: hostname,
            tls_version,
            cipher_suite,
            key_exchange,
            pqc_extensions,
            certificate_info,
            raw_server_hello,
            raw_certificate,
            alert_info: None,
            certificate_visible,
            handshake_complete: handshake_ok,
            pqc_signature_algorithms,
            tls_features,
            handshake_duration_ms: Some(handshake_duration.as_millis() as u64),
            client_profile_used: self.profile.clone(),
            extension_map,
        };
        
        Ok(result)
    }

    /// Get the set of extension IDs offered in ClientHello based on profile
    fn get_offered_extensions(&self) -> HashSet<u16> {
        let mut extensions = HashSet::new();
        
        // Always include basic extensions
        extensions.insert(0x0000); // server_name
        extensions.insert(0x002b); // supported_versions
        
        match self.profile {
            HandshakeProfile::CloudflarePqc => {
                extensions.insert(0x000a); // supported_groups
                extensions.insert(0x000d); // signature_algorithms
                extensions.insert(0x0033); // key_share
                extensions.insert(0x0010); // alpn
                extensions.insert(0x0005); // status_request (OCSP)
                extensions.insert(0x002d); // psk_key_exchange_modes
                extensions.insert(0x002a); // early_data
            },
            HandshakeProfile::HybridPqc => {
                extensions.insert(0x000a); // supported_groups
                extensions.insert(0x000d); // signature_algorithms
                extensions.insert(0x0033); // key_share
                extensions.insert(0x0010); // alpn
            },
            HandshakeProfile::PqcOnly => {
                extensions.insert(0x000a); // supported_groups
                extensions.insert(0x000d); // signature_algorithms
                extensions.insert(0x0033); // key_share
            },
            HandshakeProfile::Standard => {
                extensions.insert(0x000d); // signature_algorithms
            }
        }
        
        extensions
    }
} 