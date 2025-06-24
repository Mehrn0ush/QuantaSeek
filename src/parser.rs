use crate::types::{HandshakeResult, PqcExtensions, CertificateInfo, TlsFeatures, EarlyDataStatus, HandshakeProfile};
use crate::constants;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use x509_parser::prelude::*;

// TLS Constants
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_TYPE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;

// Extension IDs (from handshake.rs)
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PQC_KEM: u16 = 0xfe33;
const EXT_PQC_KEM_GROUP: u16 = 0xfe34;

// TLS Feature Extensions
const EXT_ALPN: u16 = 0x0010;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_STATUS_REQUEST_V2: u16 = 0x0025;
const EXT_EARLY_DATA: u16 = 0x002a;
const EXT_PRE_SHARED_KEY: u16 = 0x0041;
const EXT_SESSION_TICKET: u16 = 0x0023;

// Named Groups
const NAMED_GROUP_X25519: u16 = 0x001d;
const NAMED_GROUP_SECP256R1: u16 = 0x0017;
const NAMED_GROUP_KYBER1024: u16 = 0xfe31;
const NAMED_GROUP_KYBER768: u16 = 0xfe30;

// Cipher Suites
const CIPHER_SUITES: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x11ec, "TLS_HYBRID_X25519_MLKEM768_SHA384"),
    (0x6399, "TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384"),
    (0xfe00, "TLS_PQC_HYBRID"),
];

// Signature Algorithms
const SIG_DILITHIUM3: u16 = 0xfe60;
const SIG_DILITHIUM5: u16 = 0xfe61;

pub struct TlsParser {
    cipher_suite_map: HashMap<u16, String>,
}

impl TlsParser {
    pub fn new() -> Self {
        let mut cipher_suite_map = HashMap::new();
        for (id, name) in CIPHER_SUITES {
            cipher_suite_map.insert(*id, name.to_string());
        }
        
        Self { cipher_suite_map }
    }

    pub async fn parse_handshake_response(&self, data: &[u8]) -> Result<HandshakeResult> {
        println!("Parsing TLS response of {} bytes", data.len());
        
        let mut result = HandshakeResult {
            target: "Unknown".to_string(),
            tls_version: "Unknown".to_string(),
            cipher_suite: "Unknown".to_string(),
            key_exchange: Vec::new(),
            pqc_extensions: PqcExtensions::default(),
            certificate_info: None,
            raw_server_hello: Vec::new(),
            raw_certificate: Vec::new(),
            alert_info: None,
            certificate_visible: false,
            handshake_complete: false,
            pqc_signature_algorithms: Vec::new(),
            tls_features: TlsFeatures::default(),
            handshake_duration_ms: None,
            client_profile_used: HandshakeProfile::Standard, // Default value
        };

        let mut offset = 0;
        let mut handshake_complete = false;
        let mut certificate_visible = false;
        
        // Parse multiple TLS records in the response
        while offset < data.len() {
            if offset + 5 > data.len() {
                println!("Not enough data for TLS record header at offset {}", offset);
                break;
            }
            
            let content_type = data[offset];
            let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
            let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            
            println!("TLS Record: type=0x{:02x}, version=0x{:04x}, length={}", 
                     content_type, version, length);
            
            // Check if we have enough data for the complete record
            if offset + 5 + length > data.len() {
                println!("Incomplete TLS record. Need {} bytes, have {} bytes.", 
                         offset + 5 + length, data.len());
                break;
            }
            
            let record_data = &data[offset + 5..offset + 5 + length];
            
            match content_type {
                TLS_CONTENT_TYPE_HANDSHAKE => {
                    println!("Processing handshake record");
                    if let Err(e) = self.parse_handshake_record(record_data, &mut result) {
                        println!("Error parsing handshake record: {}", e);
                    }
                }
                0x15 => {
                    println!("Received TLS Alert");
                    if record_data.len() >= 2 {
                        let alert_level = record_data[0];
                        let alert_description = record_data[1];
                        println!("Alert level: {}, description: {}", alert_level, alert_description);
                        
                        // Add alert information to result for analysis
                        let alert_info = match alert_description {
                            40 => "handshake_failure - Server rejected the handshake parameters",
                            50 => "decode_error - Malformed ClientHello or unsupported extensions",
                            70 => "protocol_version - Server doesn't support the TLS version",
                            86 => "insufficient_security - Security level too low",
                            90 => "internal_error - Server internal error",
                            _ => &format!("unknown_alert({})", alert_description),
                        };
                        println!("Alert analysis: {}", alert_info);
                        result.alert_info = Some(alert_info.to_string());
                    }
                }
                0x17 => {
                    println!("Received Application Data (encrypted, stopping)");
                    handshake_complete = true;
                    // This is encrypted data, we can't parse it without the session keys
                    break;
                }
                0x14 => {
                    println!("Received Change Cipher Spec");
                    // This is just a protocol message, no data to parse
                }
                _ => {
                    println!("Received unknown/unhandled record type: 0x{:02x}", content_type);
                }
            }
            
            offset += 5 + length;
        }
        
        // Analyze certificate visibility based on TLS version and handshake completion
        if result.tls_version == "1.3" && handshake_complete {
            certificate_visible = result.certificate_info.is_some();
            if !certificate_visible {
                println!("TLS 1.3 handshake complete but certificate not visible (likely encrypted)");
            }
            
            // If we offered early data but server didn't respond with it, mark as rejected
            if result.tls_features.early_data_status == EarlyDataStatus::NotOffered {
                // We sent early_data in ClientHello, so if not found in response, it was rejected
                result.tls_features.early_data_status = EarlyDataStatus::Rejected;
            }
        } else if result.tls_version == "1.2" {
            certificate_visible = result.certificate_info.is_some();
        }
        
        // Store certificate visibility in result for analysis
        result.certificate_visible = certificate_visible;
        result.handshake_complete = handshake_complete;
        
        Ok(result)
    }

    fn parse_handshake_record(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        let mut offset = 0;
        
        // Parse all handshake messages in this record
        while offset < data.len() {
            if offset + 4 > data.len() {
                println!("Not enough data for handshake message header at offset {}", offset);
                break;
            }
            
            let handshake_type = data[offset];
            let length = u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
            
            println!("Handshake message: type=0x{:02x}, length={}", handshake_type, length);
            
            if offset + 4 + length > data.len() {
                println!("Incomplete handshake message. Need {} bytes, have {} bytes", 
                         offset + 4 + length, data.len());
                break;
            }
            
            let handshake_data = &data[offset + 4..offset + 4 + length];
            
            match handshake_type {
                HANDSHAKE_TYPE_SERVER_HELLO => {
                    println!("Processing ServerHello");
                    result.raw_server_hello = handshake_data.to_vec();
                    self.parse_server_hello(handshake_data, result)?;
                }
                HANDSHAKE_TYPE_CERTIFICATE => {
                    println!("Processing Certificate");
                    result.raw_certificate = handshake_data.to_vec();
                    self.parse_certificate(handshake_data, result)?;
                }
                0x08 => { // EncryptedExtensions
                    println!("Processing EncryptedExtensions");
                    self.parse_encrypted_extensions(handshake_data, result)?;
                }
                0x0f => { // CertificateVerify
                    println!("Processing CertificateVerify");
                    self.parse_certificate_verify(handshake_data, result)?;
                }
                0x14 => { // Finished
                    println!("Processing Finished");
                    // Finished message - handshake complete
                }
                _ => {
                    println!("Skipping unknown handshake type: 0x{:02x}", handshake_type);
                }
            }
            
            offset += 4 + length;
        }
        
        Ok(())
    }

    fn parse_server_hello(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        if data.len() < 38 {
            return Err(anyhow!("ServerHello too short"));
        }
        
        let mut offset = 0;
        
        // Protocol Version
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let legacy_version = match version {
            0x0304 => "1.3".to_string(),
            0x0303 => "1.2".to_string(),
            0x0302 => "1.1".to_string(),
            0x0301 => "1.0".to_string(),
            _ => format!("Unknown(0x{:04x})", version),
        };
        offset += 2;
        
        // Random (32 bytes)
        offset += 32;
        
        // Session ID
        if offset >= data.len() {
            return Ok(());
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;
        
        // Cipher Suite
        if offset + 2 > data.len() {
            return Ok(());
        }
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        result.cipher_suite = self.cipher_suite_map
            .get(&cipher_suite)
            .cloned()
            .unwrap_or_else(|| format!("Unknown(0x{:04x})", cipher_suite));
        offset += 2;
        
        // Compression Method
        if offset >= data.len() {
            return Ok(());
        }
        offset += 1;
        
        // Extensions
        let mut supported_versions_found = false;
        if offset + 2 <= data.len() {
            let extensions_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            
            if offset + extensions_length <= data.len() {
                let extensions_data = &data[offset..offset + extensions_length];
                supported_versions_found = self.parse_extensions(extensions_data, result)?;
            }
        }
        
        // If no supported_versions extension found, use legacy version
        if !supported_versions_found && result.tls_version == "Unknown" {
            result.tls_version = legacy_version;
            println!("No supported_versions extension found, using legacy version: {}", result.tls_version);
        }
        
        Ok(())
    }

    fn parse_extensions(&self, data: &[u8], result: &mut HandshakeResult) -> Result<bool> {
        let mut offset = 0;
        let mut supported_versions_found = false;
        
        while offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            println!("Parsing extension: type=0x{:04x}, length={}", ext_type, ext_length);
            
            if offset + ext_length > data.len() {
                break;
            }
            
            let ext_data = &data[offset..offset + ext_length];
            
            match ext_type {
                0x002b => { // supported_versions
                    println!("Found supported_versions extension, data: {:?}", ext_data);
                    self.parse_supported_versions_extension(ext_data, result)?;
                    supported_versions_found = true;
                }
                0x000d => { // signature_algorithms
                    println!("Found signature_algorithms extension, data: {:?}", ext_data);
                    self.parse_signature_algorithms_extension(ext_data, result)?;
                }
                EXT_KEY_SHARE => {
                    println!("Found key_share extension, data: {:?}", ext_data);
                    self.parse_key_share_extension(ext_data, result)?;
                }
                EXT_PQC_KEM => {
                    result.pqc_extensions.kem = true;
                }
                EXT_PQC_KEM_GROUP => {
                    result.pqc_extensions.kem_group = true;
                }
                EXT_ALPN => {
                    println!("Found ALPN extension, data: {:?}", ext_data);
                    if let Ok(alpn_protocol) = self.parse_alpn_extension(ext_data) {
                        result.tls_features.alpn = Some(alpn_protocol);
                    }
                }
                EXT_STATUS_REQUEST | EXT_STATUS_REQUEST_V2 => {
                    println!("Found status_request extension (OCSP stapling)");
                    result.tls_features.ocsp_stapling = true;
                }
                EXT_EARLY_DATA => {
                    println!("Found early_data extension");
                    result.tls_features.early_data_status = EarlyDataStatus::Accepted;
                }
                EXT_PRE_SHARED_KEY => {
                    println!("Found pre_shared_key extension (PSK resumption)");
                    result.tls_features.session_ticket = Some(true);
                }
                EXT_SESSION_TICKET => {
                    println!("Found session_ticket extension support");
                    result.tls_features.session_ticket = Some(true);
                }
                _ => {
                    println!("Skipping unknown extension: 0x{:04x}", ext_type);
                }
            }
            
            offset += ext_length;
        }
        
        Ok(supported_versions_found)
    }

    fn parse_supported_versions_extension(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        println!("Parsing supported_versions extension with {} bytes: {:?}", data.len(), data);
        
        // In ServerHello, supported_versions extension contains only the selected version (2 bytes)
        // In ClientHello, it contains length + list of versions
        if data.len() >= 2 {
            let major = data[0];
            let minor = data[1];
            println!("TLS version from supported_versions: {}.{}", major, minor);
            
            match (major, minor) {
                (3, 4) => {
                    result.tls_version = "1.3".to_string();
                    println!("TLS version determined from supported_versions: 1.3");
                }
                (3, 3) => {
                    result.tls_version = "1.2".to_string();
                    println!("TLS version determined from supported_versions: 1.2");
                }
                (3, 2) => {
                    result.tls_version = "1.1".to_string();
                    println!("TLS version determined from supported_versions: 1.1");
                }
                (3, 1) => {
                    result.tls_version = "1.0".to_string();
                    println!("TLS version determined from supported_versions: 1.0");
                }
                _ => {
                    println!("Unknown TLS version in supported_versions: {}.{}", major, minor);
                }
            }
        } else {
            println!("supported_versions extension too short: need 2 bytes, have {} bytes", data.len());
        }
        
        println!("Final TLS version after supported_versions: {}", result.tls_version);
        Ok(())
    }

    fn parse_key_share_extension(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        if data.len() < 2 { // Must have at least group ID
            return Ok(());
        }
        
        // In ServerHello, key share contains a single entry: group (2 bytes) + key_exchange_length (2 bytes) + key
        let group = u16::from_be_bytes([data[0], data[1]]);
        let key_exchange_name = constants::get_group_name(group);
        
        // If a PQC group is detected, it implies a KEM is being used.
        if constants::is_pqc_group(group) {
            println!("PQC key share group found: {} (0x{:04x})", key_exchange_name, group);
            result.pqc_extensions.kem = true;
            result.pqc_extensions.kem_group = true;
        }
        
        result.key_exchange.push(key_exchange_name);
        
        Ok(())
    }

    fn parse_certificate(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        if data.len() < 3 {
            return Ok(());
        }
        
        // Certificates length (3 bytes)
        let certs_length = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        let offset = 3;
        
        if offset + certs_length > data.len() {
            return Ok(());
        }
        
        let certs_data = &data[offset..offset + certs_length];
        let mut cert_offset = 0;

        // Parse certificate chain
        while cert_offset < certs_data.len() {
            if cert_offset + 3 > certs_data.len() {
                break;
            }
            let cert_length = u32::from_be_bytes([0, certs_data[cert_offset], certs_data[cert_offset + 1], certs_data[cert_offset + 2]]) as usize;
            cert_offset += 3;
            
            if cert_offset + cert_length > certs_data.len() {
                break;
            }
            
            let cert_data = &certs_data[cert_offset..cert_offset + cert_length];
            
            // Use x509-parser to parse the certificate
            match X509Certificate::from_der(cert_data) {
                Ok((_rem, cert)) => {
                    let sig_alg_oid = cert.signature_algorithm.algorithm.to_string();
                    let pkey_alg_oid = cert.public_key().algorithm.algorithm.to_string();

                    println!("Certificate parsed: subject='{}', sig_oid='{}'", cert.subject(), sig_alg_oid);

                    // For the first certificate in the chain, update the result
                    if result.certificate_info.is_none() {
                        result.certificate_info = Some(CertificateInfo {
                            subject: cert.subject().to_string(),
                            public_key_algorithm: pkey_alg_oid,
                            signature_algorithm: sig_alg_oid.clone(),
                            key_size: None, // simplified
                        });
                    }

                    // Check if the signature algorithm is PQC
                    if constants::is_pqc_oid(&sig_alg_oid) {
                        println!("Found PQC signature OID in certificate: {}", sig_alg_oid);
                        if !result.pqc_signature_algorithms.contains(&sig_alg_oid) {
                             result.pqc_signature_algorithms.push(sig_alg_oid);
                        }
                    }
                }
                Err(e) => {
                    println!("Error parsing X.509 certificate: {}", e);
                }
            }
            
            cert_offset += cert_length;
        }
        
        Ok(())
    }

    fn parse_encrypted_extensions(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        // Parse EncryptedExtensions for additional PQC information
        if data.len() < 2 {
            return Ok(());
        }
        
        let extensions_length = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + extensions_length {
            return Ok(());
        }
        
        let extensions_data = &data[2..2 + extensions_length];
        println!("Parsing EncryptedExtensions with {} bytes", extensions_data.len());
        self.parse_extensions(extensions_data, result)?;
        
        Ok(())
    }

    fn parse_certificate_verify(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        // Parse CertificateVerify for signature algorithm information
        if data.len() < 2 {
            return Ok(());
        }
        
        let signature_scheme = u16::from_be_bytes([data[0], data[1]]);
        println!("CertificateVerify signature scheme: 0x{:04x}", signature_scheme);
        
        // Check if this is a PQC signature algorithm
        if crate::constants::is_pqc_signature_algorithm(signature_scheme) {
            let algorithm_name = crate::constants::get_signature_algorithm_name(signature_scheme);
            println!("CertificateVerify uses PQC signature: {}", algorithm_name);
            result.pqc_signature_algorithms.push(algorithm_name);
        }
        
        // Update certificate info if we have it
        if let Some(ref mut cert_info) = result.certificate_info {
            let signature_name = if crate::constants::is_pqc_signature_algorithm(signature_scheme) {
                crate::constants::get_signature_algorithm_name(signature_scheme)
            } else {
                match signature_scheme {
                    0x0401 => "rsa_pkcs1_sha256".to_string(),
                    0x0403 => "ecdsa_secp256r1_sha256".to_string(),
                    0x0804 => "rsa_pss_rsae_sha256".to_string(),
                    _ => format!("unknown(0x{:04x})", signature_scheme),
                }
            };
            cert_info.signature_algorithm = signature_name;
        }
        
        Ok(())
    }

    fn parse_signature_algorithms_extension(&self, data: &[u8], result: &mut HandshakeResult) -> Result<()> {
        if data.len() < 2 {
            return Ok(());
        }
        
        let algorithms_length = u16::from_be_bytes([data[0], data[1]]) as usize;
        println!("Signature algorithms length: {}", algorithms_length);
        
        if data.len() < 2 + algorithms_length {
            return Ok(());
        }
        
        let algorithms_data = &data[2..2 + algorithms_length];
        
        // Parse signature algorithms (2 bytes each)
        for i in (0..algorithms_data.len()).step_by(2) {
            if i + 1 < algorithms_data.len() {
                let algorithm = u16::from_be_bytes([algorithms_data[i], algorithms_data[i + 1]]);
                println!("Signature algorithm: 0x{:04x}", algorithm);
                
                // Check for PQC signature algorithms using constants
                if crate::constants::is_pqc_signature_algorithm(algorithm) {
                    let algorithm_name = crate::constants::get_signature_algorithm_name(algorithm);
                    println!("Found PQC signature algorithm: {}", algorithm_name);
                    result.pqc_signature_algorithms.push(algorithm_name);
                }
            }
        }
        
        Ok(())
    }

    fn parse_alpn_extension(&self, data: &[u8]) -> Result<String> {
        if data.len() < 3 {
            return Err(anyhow!("ALPN extension data too short"));
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + list_len {
            return Err(anyhow!("ALPN list length mismatch"));
        }

        let proto_len = data[2] as usize;
        if data.len() < 3 + proto_len {
            return Err(anyhow!("ALPN protocol length mismatch"));
        }

        let protocol_name = String::from_utf8_lossy(&data[3..3 + proto_len]).to_string();
        println!("ALPN protocol negotiated: {}", protocol_name);
        Ok(protocol_name)
    }
} 