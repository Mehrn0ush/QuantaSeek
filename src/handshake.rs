use crate::{HandshakeProfile, HandshakeResult};
use crate::parser::TlsParser;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, anyhow};
use hex;
use ring::rand::{SystemRandom, SecureRandom};
use serde::{Serialize, Deserialize};
use std::time::Instant;

// TLS Constants
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_1_2: u16 = 0x0303;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

// Extension IDs
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PQC_KEM: u16 = 0xfe33; // Hypothetical PQC KEM extension
const EXT_PQC_KEM_GROUP: u16 = 0xfe34; // Hypothetical PQC KEM group extension
const EXT_STATUS_REQUEST: u16 = 0x0005; // For OCSP Stapling
const EXT_EARLY_DATA: u16 = 0x002a; // For 0-RTT support

// Named Groups - Updated with real-world PQC identifiers
const NAMED_GROUP_X25519: u16 = 0x001d;
const NAMED_GROUP_SECP256R1: u16 = 0x0017;
const NAMED_GROUP_X25519_KYBER512: u16 = 0xfe30; // X25519Kyber512Draft00 (obsolete)
const NAMED_GROUP_X25519_KYBER768: u16 = 0x6399; // X25519Kyber768Draft00 
const NAMED_GROUP_X25519_MLKEM768: u16 = 0x11ec; // X25519MLKEM768 (recommended)
const NAMED_GROUP_P256_KYBER768: u16 = 0x639a; // P256Kyber768Draft00

// Signature Algorithms - Updated with IETF draft values
const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_RSA_PSS_SHA256: u16 = 0x0804;
const SIG_DILITHIUM2: u16 = 0x0b01; // IETF draft Dilithium2
const SIG_DILITHIUM3: u16 = 0x0b02; // IETF draft Dilithium3
const SIG_DILITHIUM5: u16 = 0x0b03; // IETF draft Dilithium5

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

    pub async fn perform_handshake(&self, mut stream: TcpStream, hostname: &str) -> Result<HandshakeResult> {
        let start_time = Instant::now();
        
        // Construct ClientHello based on profile
        let client_hello = self.build_client_hello(hostname)?;
        
        println!("Sending ClientHello ({} bytes) to {}", client_hello.len(), hostname);
        
        // Send ClientHello
        stream.write_all(&client_hello).await?;
        
        println!("ClientHello sent, waiting for response...");
        
        // Read complete TLS response with proper reassembly
        let mut all_records = Vec::new();
        
        // Read multiple TLS records until we get encrypted data or connection closes
        loop {
            match self.read_tls_record(&mut stream).await {
                Ok(record) => {
                    // Check if this is encrypted data (Application Data) before pushing
                    let is_encrypted = record.len() >= 5 && record[0] == 0x17;
                    
                    all_records.push(record);
                    
                    if is_encrypted {
                        println!("Received encrypted data, stopping handshake parsing");
                        break;
                    }
                }
                Err(e) => {
                    println!("Error reading TLS record: {}", e);
                    break;
                }
            }
        }
        
        if all_records.is_empty() {
            return Err(anyhow!("No response from server"));
        }
        
        // Combine all records into a single buffer
        let mut buffer = Vec::new();
        for record in &all_records {
            buffer.extend_from_slice(record);
        }
        
        println!("Received {} TLS records, total {} bytes", all_records.len(), buffer.len());
        println!("First 32 bytes: {}", hex::encode(&buffer[..std::cmp::min(32, buffer.len())]));
        
        // Parse TLS messages
        let parser = TlsParser::new();
        let mut result = parser.parse_handshake_response(&buffer).await?;
        
        // Add timing and profile information
        let duration = start_time.elapsed();
        result.handshake_duration_ms = Some(duration.as_millis() as u64);
        result.client_profile_used = self.profile;
        
        Ok(result)
    }

    async fn read_tls_record(&self, stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut record = Vec::new();
        
        // Read TLS record header (5 bytes)
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        record.extend_from_slice(&header);
        
        // Extract record length
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        println!("Reading TLS record: type=0x{:02x}, length={}", header[0], length);
        
        // Read the complete record body
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await?;
        record.extend_from_slice(&body);
        
        Ok(record)
    }

    fn get_cipher_suites(&self) -> Vec<u16> {
        match self.profile {
            HandshakeProfile::CloudflarePqc => vec![
                0x11ec, // TLS_HYBRID_X25519_MLKEM768_SHA384
                0x6399, // TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384
                0x1301, // TLS_AES_128_GCM_SHA256 (fallback)
                0x1302, // TLS_AES_256_GCM_SHA384 (fallback)
                0x1303, // TLS_CHACHA20_POLY1305_SHA256 (fallback)
            ],
            HandshakeProfile::HybridPqc => vec![
                0x11ec, // TLS_HYBRID_X25519_MLKEM768_SHA384
                0x6399, // TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384
                0x1301, // TLS_AES_128_GCM_SHA256 (fallback)
            ],
            HandshakeProfile::PqcOnly => vec![
                0x11ec, // TLS_HYBRID_X25519_MLKEM768_SHA384
                0x6399, // TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384
            ],
            HandshakeProfile::Standard => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
            ],
        }
    }

    fn build_client_hello(&self, hostname: &str) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        
        // TLS Record Header (5 bytes)
        message.push(TLS_CONTENT_TYPE_HANDSHAKE);  // 0x16
        message.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());  // 0x0303
        
        // We'll fill in the length later
        let length_pos = message.len();
        message.extend_from_slice(&[0, 0]);
        
        // Handshake Header (4 bytes)
        message.push(HANDSHAKE_TYPE_CLIENT_HELLO);  // 0x01
        
        // We'll fill in the handshake length later
        let handshake_length_pos = message.len();
        message.extend_from_slice(&[0, 0, 0]);
        
        let handshake_start = message.len();
        
        // Client Version (2 bytes) - legacy_version for TLS 1.3
        message.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());  // 0x0303
        
        // Random (32 bytes) - using secure random
        let mut random = [0u8; 32];
        let rng = SystemRandom::new();
        rng.fill(&mut random).map_err(|_| anyhow!("Failed to generate random bytes"))?;
        message.extend_from_slice(&random);
        
        // Session ID (1 byte - empty for TLS 1.3)
        message.push(0);
        
        // Cipher Suites (2 bytes length + suites)
        let cipher_suites = self.get_cipher_suites();
        message.extend_from_slice(&(cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in cipher_suites {
            message.extend_from_slice(&suite.to_be_bytes());
        }
        
        // Compression Methods (2 bytes - null only)
        message.push(1);  // Length
        message.push(0);  // Null compression
        
        // Extensions
        let extensions = self.build_extensions(hostname)?;
        message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        message.extend_from_slice(&extensions);
        
        // Fill in lengths
        let handshake_length = message.len() - handshake_start;
        let handshake_length_bytes = [
            ((handshake_length >> 16) & 0xff) as u8,
            ((handshake_length >> 8) & 0xff) as u8,
            (handshake_length & 0xff) as u8,
        ];
        message[handshake_length_pos..handshake_length_pos + 3].copy_from_slice(&handshake_length_bytes);
        
        let record_length = message.len() - 5;  // Exclude record header
        let record_length_bytes = (record_length as u16).to_be_bytes();
        message[length_pos..length_pos + 2].copy_from_slice(&record_length_bytes);
        
        Ok(message)
    }

    fn build_extensions(&self, hostname: &str) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();
        
        match self.profile {
            HandshakeProfile::CloudflarePqc => {
                // Re-ordering extensions. Common practice is SNI first.
                self.add_sni_extension(&mut extensions, hostname);
                self.add_supported_versions_tls13_only(&mut extensions);
                self.add_supported_groups_ultra_minimal(&mut extensions);
                
                // Move feature requests earlier
                self.add_alpn_extension(&mut extensions);
                self.add_status_request_extension(&mut extensions);
                self.add_psk_modes_extension(&mut extensions);
                self.add_early_data_extension(&mut extensions);
                
                self.add_signature_algorithms_ultra_minimal(&mut extensions);
                self.add_key_share_ultra_minimal(&mut extensions);
            },
            HandshakeProfile::HybridPqc => {
                self.add_sni_extension(&mut extensions, hostname);
                self.add_supported_versions_tls13_only(&mut extensions);
                self.add_supported_groups_ultra_minimal(&mut extensions);
                self.add_alpn_extension(&mut extensions);
                self.add_signature_algorithms_ultra_minimal(&mut extensions);
                self.add_key_share_ultra_minimal(&mut extensions);
            },
            HandshakeProfile::PqcOnly => {
                self.add_sni_extension(&mut extensions, hostname);
                self.add_supported_versions_tls13_only(&mut extensions);
                self.add_supported_groups_pqc_only(&mut extensions);
                self.add_signature_algorithms_pqc_only(&mut extensions);
                self.add_key_share_pqc_only(&mut extensions);
            },
            HandshakeProfile::Standard => {
                // Ultra-minimal: only 3 essential extensions for other profiles
                self.add_sni_extension(&mut extensions, hostname);
                self.add_minimal_signature_algorithms(&mut extensions);
                self.add_supported_versions_extension(&mut extensions);
            }
        }
        
        Ok(extensions)
    }

    fn add_sni_extension(&self, extensions: &mut Vec<u8>, hostname: &str) {
        extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        
        // Calculate correct lengths
        let hostname_len = hostname.len();
        let name_list_entry_len = 1 + 2 + hostname_len; // type(1) + length(2) + hostname
        let server_name_list_len = name_list_entry_len;
        let ext_length = 2 + server_name_list_len; // list_length(2) + list_content
        
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Server name list length
        extensions.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        
        // Name type (hostname = 0)
        extensions.push(0);
        
        // Hostname length and data
        extensions.extend_from_slice(&(hostname_len as u16).to_be_bytes());
        extensions.extend_from_slice(hostname.as_bytes());
    }

    fn add_minimal_signature_algorithms(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        
        // Only essential signature algorithms
        let algorithms = vec![
            SIG_ECDSA_SECP256R1_SHA256, // Primary for Cloudflare
            SIG_RSA_PSS_SHA256,
        ];
        
        // Extension length (2 bytes)
        let ext_length = 2 + algorithms.len() * 2;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Algorithms list length (2 bytes)
        extensions.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());
        
        // Algorithms
        for algorithm in algorithms {
            extensions.extend_from_slice(&algorithm.to_be_bytes());
        }
    }

    fn add_supported_versions_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes()); // Extension length
        extensions.push(2); // Versions list length
        extensions.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
    }

    fn add_pqc_extensions(&self, extensions: &mut Vec<u8>) {
        // Add hypothetical PQC KEM extension
        extensions.extend_from_slice(&EXT_PQC_KEM.to_be_bytes());
        extensions.extend_from_slice(&0u16.to_be_bytes()); // Empty extension for now
        
        // Add hypothetical PQC KEM group extension
        extensions.extend_from_slice(&EXT_PQC_KEM_GROUP.to_be_bytes());
        extensions.extend_from_slice(&0u16.to_be_bytes()); // Empty extension for now
    }

    fn add_supported_versions_tls13_only(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        
        // Extension length (2 bytes)
        extensions.extend_from_slice(&3u16.to_be_bytes());
        
        // Versions list length (1 byte)
        extensions.push(2);
        
        // TLS 1.3 version (2 bytes)
        extensions.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
    }

    fn add_supported_groups_ultra_minimal(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        
        let groups = match self.profile {
            HandshakeProfile::CloudflarePqc => vec![
                0xfe30, // x25519_kyber768_r3 (0xfe30)
                0x11ec, // x25519_mlkem768 (0x11ec)
                0x001c, // kyber768_r3 (0x001c)
                NAMED_GROUP_X25519, // 0x001d (fallback)
            ],
            HandshakeProfile::HybridPqc => vec![
                0x11ec, // x25519_mlkem768 (0x11ec)
                0x6399, // x25519_kyber768 (0x6399)
                NAMED_GROUP_X25519, // 0x001d (fallback)
            ],
            _ => vec![
                NAMED_GROUP_X25519, // 0x001d (standard, compatible)
            ],
        };
        
        // Extension length (2 bytes)
        let ext_length = 2 + groups.len() * 2;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Groups list length (2 bytes)
        extensions.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        
        // Groups
        for &group in &groups {
            extensions.extend_from_slice(&(group as u16).to_be_bytes());
        }
    }

    fn add_supported_groups_pqc_only(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        
        let groups = vec![
            0x11ec, // x25519_mlkem768 (0x11ec)
            0x6399, // x25519_kyber768 (0x6399)
            0x001c, // kyber768_r3 (0x001c)
        ];
        
        // Extension length (2 bytes)
        let ext_length = 2 + groups.len() * 2;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Groups list length (2 bytes)
        extensions.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        
        // Groups
        for &group in &groups {
            extensions.extend_from_slice(&(group as u16).to_be_bytes());
        }
    }

    fn add_signature_algorithms_ultra_minimal(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        
        let algorithms = match self.profile {
            HandshakeProfile::CloudflarePqc => vec![
                0x0807, // rsa_pss_sha256
                0x0403, // ed25519
                0x0401, // ecdsa_secp256r1_sha256
                SIG_DILITHIUM2, // 0x0b01 (IETF draft Dilithium2)
                SIG_DILITHIUM3, // 0x0b02 (IETF draft Dilithium3)
            ],
            HandshakeProfile::HybridPqc => vec![
                0x0403, // ed25519
                0x0401, // ecdsa_secp256r1_sha256
                SIG_DILITHIUM3, // 0x0b02 (IETF draft Dilithium3)
            ],
            _ => vec![
                SIG_ECDSA_SECP256R1_SHA256, // Primary for Cloudflare
            ],
        };
        
        // Extension length (2 bytes)
        let ext_length = 2 + algorithms.len() * 2;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Algorithms list length (2 bytes)
        extensions.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());
        
        // Algorithms
        for algorithm in algorithms {
            extensions.extend_from_slice(&algorithm.to_be_bytes());
        }
    }

    fn add_signature_algorithms_pqc_only(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        
        let algorithms = vec![
            SIG_DILITHIUM2, // 0x0b01 (IETF draft Dilithium2)
            SIG_DILITHIUM3, // 0x0b02 (IETF draft Dilithium3)
            SIG_DILITHIUM5, // 0x0b03 (IETF draft Dilithium5)
        ];
        
        // Extension length (2 bytes)
        let ext_length = 2 + algorithms.len() * 2;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Algorithms list length (2 bytes)
        extensions.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());
        
        // Algorithms
        for algorithm in algorithms {
            extensions.extend_from_slice(&algorithm.to_be_bytes());
        }
    }

    fn add_key_share_ultra_minimal(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        
        let key_shares = match self.profile {
            HandshakeProfile::CloudflarePqc => {
                // Generate hybrid key shares for PQC groups
                let mut shares = Vec::new();
                
                // x25519_kyber768_r3 hybrid key share
                let x25519_kyber_key = vec![0x22; 32 + 1184]; // X25519 (32) + Kyber768 (1184)
                shares.push((0xfe30, x25519_kyber_key));
                
                // x25519_mlkem768 hybrid key share  
                let x25519_mlkem_key = vec![0x22; 32 + 1184]; // X25519 (32) + ML-KEM768 (1184)
                shares.push((0x11ec, x25519_mlkem_key));
                
                // kyber768_r3 key share
                let kyber_key = vec![0x22; 1184]; // Kyber768 (1184)
                shares.push((0x001c, kyber_key));
                
                // Fallback X25519 key share
                let x25519_key = vec![0x22; 32];
                shares.push((NAMED_GROUP_X25519, x25519_key));
                
                shares
            },
            HandshakeProfile::HybridPqc => {
                let mut shares = Vec::new();
                
                // x25519_mlkem768 hybrid key share  
                let x25519_mlkem_key = vec![0x22; 32 + 1184]; // X25519 (32) + ML-KEM768 (1184)
                shares.push((0x11ec, x25519_mlkem_key));
                
                // x25519_kyber768 hybrid key share
                let x25519_kyber_key = vec![0x22; 32 + 1184]; // X25519 (32) + Kyber768 (1184)
                shares.push((0x6399, x25519_kyber_key));
                
                // Fallback X25519 key share
                let x25519_key = vec![0x22; 32];
                shares.push((NAMED_GROUP_X25519, x25519_key));
                
                shares
            },
            _ => {
                // Only send X25519 key share with minimal size (32 bytes)
                let key = vec![0x22; 32]; // X25519 public key (32 bytes)
                vec![(NAMED_GROUP_X25519, key)]
            }
        };
        
        // Build all key share entries
        let mut key_share_entries = Vec::new();
        for (group, key) in key_shares {
            let mut entry = Vec::new();
            entry.extend_from_slice(&(group as u16).to_be_bytes());
            entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
            entry.extend_from_slice(&key);
            key_share_entries.push(entry);
        }
        
        // Calculate total length
        let total_length: usize = key_share_entries.iter().map(|entry| entry.len()).sum();
        
        // Extension length (2 bytes)
        let ext_length = 2 + total_length;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Client key shares length (2 bytes)
        extensions.extend_from_slice(&(total_length as u16).to_be_bytes());
        
        // Key share entries
        for entry in key_share_entries {
            extensions.extend_from_slice(&entry);
        }
    }

    fn add_key_share_pqc_only(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        
        let key_shares = vec![
            // x25519_mlkem768 hybrid key share  
            (0x11ec, vec![0x22; 32 + 1184]), // X25519 (32) + ML-KEM768 (1184)
            // x25519_kyber768 hybrid key share
            (0x6399, vec![0x22; 32 + 1184]), // X25519 (32) + Kyber768 (1184)
            // kyber768_r3 key share
            (0x001c, vec![0x22; 1184]), // Kyber768 (1184)
        ];
        
        // Build all key share entries
        let mut key_share_entries = Vec::new();
        for (group, key) in key_shares {
            let mut entry = Vec::new();
            entry.extend_from_slice(&(group as u16).to_be_bytes());
            entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
            entry.extend_from_slice(&key);
            key_share_entries.push(entry);
        }
        
        // Calculate total length
        let total_length: usize = key_share_entries.iter().map(|entry| entry.len()).sum();
        
        // Extension length (2 bytes)
        let ext_length = 2 + total_length;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Client key shares length (2 bytes)
        extensions.extend_from_slice(&(total_length as u16).to_be_bytes());
        
        // Key share entries
        for entry in key_share_entries {
            extensions.extend_from_slice(&entry);
        }
    }

    fn add_early_data_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_EARLY_DATA.to_be_bytes());
        // Extension length (0 for empty extension in ClientHello)
        extensions.extend_from_slice(&0u16.to_be_bytes());
    }

    fn add_psk_modes_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_PSK_KEY_EXCHANGE_MODES.to_be_bytes());
        // Extension length
        extensions.extend_from_slice(&2u16.to_be_bytes());
        // KE Modes list length (1 byte)
        extensions.push(1);
        // psk_dhe_ke (1 byte) - indicates resumption with (EC)DHE
        extensions.push(1);
    }

    fn add_status_request_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_STATUS_REQUEST.to_be_bytes());
        // Extension length
        extensions.extend_from_slice(&5u16.to_be_bytes());
        // Status type: OCSP (1)
        extensions.push(1);
        // Responder ID list length (0)
        extensions.extend_from_slice(&[0, 0]);
        // Request extensions length (0)
        extensions.extend_from_slice(&[0, 0]);
    }

    fn add_alpn_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&EXT_ALPN.to_be_bytes());
        
        // Only send h2 protocol
        let protocols = vec!["h2".as_bytes()];
        
        // Calculate total length
        let mut protocol_list_len = 0;
        for protocol in &protocols {
            protocol_list_len += 1 + protocol.len();
        }
        
        // Extension length (2 bytes)
        let ext_length = 2 + protocol_list_len;
        extensions.extend_from_slice(&(ext_length as u16).to_be_bytes());
        
        // Protocol list length (2 bytes)
        extensions.extend_from_slice(&(protocol_list_len as u16).to_be_bytes());
        
        // Protocols
        for protocol in protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol);
        }
    }
} 