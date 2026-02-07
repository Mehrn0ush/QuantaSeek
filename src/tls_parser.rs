use anyhow::{anyhow, Result};

/// TLS message types
#[derive(Debug, Clone, PartialEq)]
pub enum TlsMessageType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

/// TLS extension types
#[derive(Debug, Clone, PartialEq)]
pub enum TlsExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    KeyShare = 51,
    SupportedVersions = 43,
    // PQC extensions
    KemExtension = 65024,      // 0xFE00
    KemGroupExtension = 65025, // 0xFE01
}

/// PQC group identification
/// FIXED: Updated to match IANA registry - PQC groups are not in a single range
/// Instead, we check for specific IANA-registered codepoints
///
/// ML-KEM: 512-514
/// Hybrid groups: 4587-4592, 25497-25498 (legacy)
/// Private use range: 65024-65279 (not standardized, implementation-specific)
pub const PQC_GROUP_MLKEM_MIN: u16 = 512;
pub const PQC_GROUP_MLKEM_MAX: u16 = 514;
pub const PQC_GROUP_HYBRID_MIN: u16 = 4587;
pub const PQC_GROUP_HYBRID_MAX: u16 = 4592;
pub const PQC_GROUP_LEGACY_KYBER_MIN: u16 = 25497;
pub const PQC_GROUP_LEGACY_KYBER_MAX: u16 = 25498;

/// TLS message parser for PQC detection
pub struct TlsMessageParser;

impl Default for TlsMessageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsMessageParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse ServerHello message to extract cipher suite
    /// TLS 1.3 cipher suites: 0x1301 (TLS_AES_128_GCM_SHA256), 0x1302 (TLS_AES_256_GCM_SHA384), 0x1303 (TLS_CHACHA20_POLY1305_SHA256)
    /// FIXED: Handles both formats:
    ///   1. Full TLS record (with TLS record header: content_type + version + length)
    ///   2. Raw handshake message only (without TLS record header, starts with handshake type)
    pub fn parse_server_hello_cipher_suite(&self, data: &[u8]) -> Result<Option<String>> {
        if data.len() < 4 {
            return Err(anyhow!("ServerHello too short"));
        }

        let offset = 0;

        // FIXED: Check if data starts with TLS record header (0x16) or handshake message (0x02)
        // If it starts with 0x16, it's a full TLS record; if it starts with 0x02, it's just the handshake message
        let (handshake_start, handshake_length) = if data[offset] == 0x16 {
            // Full TLS record format: [content_type(1)] [version(2)] [length(2)] [handshake_message...]
            if data.len() < 5 {
                return Err(anyhow!("TLS record header incomplete"));
            }

            // Check TLS version (should be 0x0303 for TLS 1.2 or 0x0304 for TLS 1.3)
            if data[offset + 1] != 0x03 || (data[offset + 2] != 0x03 && data[offset + 2] != 0x04) {
                return Err(anyhow!("Invalid TLS version in record header"));
            }

            let record_length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            if offset + 5 + record_length > data.len() {
                return Err(anyhow!("TLS record extends beyond available data"));
            }

            // Handshake message starts after TLS record header (5 bytes)
            let record_start = offset + 5;
            if record_start + 4 > data.len() {
                return Err(anyhow!("Not enough data for handshake message header"));
            }

            // Check handshake message type (ServerHello = 2)
            if data[record_start] != 2 {
                return Err(anyhow!("Not a ServerHello message"));
            }

            // Get handshake message length
            let handshake_len =
                Self::u24_to_u32(&data[record_start + 1..record_start + 4])? as usize;
            (record_start, handshake_len)
        } else if data[offset] == 2 {
            // Raw handshake message format: [handshake_type(1)] [length(3)] [body...]
            if data.len() < 4 {
                return Err(anyhow!("Handshake message header incomplete"));
            }

            let handshake_len = Self::u24_to_u32(&data[offset + 1..offset + 4])? as usize;
            (offset, handshake_len)
        } else {
            // FIXED: Try to find ServerHello handshake message in buffer (offset-robust)
            // This handles cases where data has prefixes (e.g., QUIC CRYPTO frames)
            if let Some((hs_start, hs_len)) = Self::find_server_hello_handshake(data) {
                // Found ServerHello, use it
                let (handshake_start, handshake_length) = (hs_start, hs_len);

                // Validate handshake message length
                if handshake_start + 4 + handshake_length > data.len() {
                    return Err(anyhow!("Handshake message extends beyond available data"));
                }

                // ServerHello structure:
                // - Handshake type (1 byte) = 2
                // - Length (3 bytes)
                // - TLS version (2 bytes)
                // - Random (32 bytes)
                // - Session ID length (1 byte) + Session ID (variable)
                // - Cipher suite (2 bytes) <- This is what we need
                // - Compression method (1 byte)
                // - Extensions (variable)

                let handshake_body_start = handshake_start + 4;
                if handshake_body_start + 38 > data.len() {
                    return Err(anyhow!("Not enough data for ServerHello header"));
                }

                // Skip TLS version (2 bytes) + Random (32 bytes) = 34 bytes
                let session_id_length_pos = handshake_body_start + 34;
                if session_id_length_pos >= data.len() {
                    return Err(anyhow!("Not enough data for session ID length"));
                }

                let session_id_length = data[session_id_length_pos] as usize;
                let cipher_suite_pos = session_id_length_pos + 1 + session_id_length;

                if cipher_suite_pos + 2 > data.len() {
                    return Err(anyhow!("Not enough data for cipher suite"));
                }

                // Extract cipher suite (2 bytes, big-endian)
                let cipher_suite =
                    u16::from_be_bytes([data[cipher_suite_pos], data[cipher_suite_pos + 1]]);

                // Map cipher suite to name
                let cipher_suite_name = match cipher_suite {
                    0x1301 => "TLS13_AES_128_GCM_SHA256",
                    0x1302 => "TLS13_AES_256_GCM_SHA384",
                    0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
                    _ => return Ok(Some(format!("Unknown(0x{:04x})", cipher_suite))),
                };

                return Ok(Some(cipher_suite_name.to_string()));
            }

            // Fallback: Try to find ServerHello in TLS records
            return self.parse_server_hello_cipher_suite_from_records(data);
        };

        // Validate handshake message length
        if handshake_start + 4 + handshake_length > data.len() {
            return Err(anyhow!("Handshake message extends beyond available data"));
        }

        // ServerHello structure:
        // - Handshake type (1 byte) = 2
        // - Length (3 bytes)
        // - TLS version (2 bytes)
        // - Random (32 bytes)
        // - Session ID length (1 byte) + Session ID (variable)
        // - Cipher suite (2 bytes) <- This is what we need
        // - Compression method (1 byte)
        // - Extensions (variable)

        let handshake_body_start = handshake_start + 4;
        if handshake_body_start + 38 > data.len() {
            return Err(anyhow!("Not enough data for ServerHello header"));
        }

        // Skip TLS version (2 bytes) + Random (32 bytes) = 34 bytes
        let session_id_length_pos = handshake_body_start + 34;
        if session_id_length_pos >= data.len() {
            return Err(anyhow!("Not enough data for session ID length"));
        }

        let session_id_length = data[session_id_length_pos] as usize;
        let cipher_suite_pos = session_id_length_pos + 1 + session_id_length;

        if cipher_suite_pos + 2 > data.len() {
            return Err(anyhow!("Not enough data for cipher suite"));
        }

        // Extract cipher suite (2 bytes, big-endian)
        let cipher_suite = u16::from_be_bytes([data[cipher_suite_pos], data[cipher_suite_pos + 1]]);

        // Map cipher suite to name
        let cipher_suite_name = match cipher_suite {
            0x1301 => "TLS13_AES_128_GCM_SHA256",
            0x1302 => "TLS13_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => return Ok(Some(format!("Unknown(0x{:04x})", cipher_suite))),
        };

        Ok(Some(cipher_suite_name.to_string()))
    }

    /// Helper function to parse ServerHello from TLS records (fallback for complex cases)
    fn parse_server_hello_cipher_suite_from_records(&self, data: &[u8]) -> Result<Option<String>> {
        // Find ServerHello message in TLS records
        let mut offset = 0;
        while offset + 5 <= data.len() {
            // Check TLS record header
            if data[offset] != 0x16 {
                // Handshake content type
                offset += 1;
                continue;
            }

            // Check TLS version (should be 0x0303 for TLS 1.2 or 0x0304 for TLS 1.3)
            if offset + 3 > data.len()
                || (data[offset + 1] != 0x03
                    || (data[offset + 2] != 0x03 && data[offset + 2] != 0x04))
            {
                offset += 1;
                continue;
            }

            // Get record length
            if offset + 5 > data.len() {
                break;
            }
            let record_length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

            if offset + 5 + record_length > data.len() {
                break; // Record extends beyond available data
            }

            // Check if this is a handshake message
            let record_start = offset + 5;
            if record_start + 4 > data.len() {
                offset += 5 + record_length;
                continue;
            }

            // Check handshake message type (ServerHello = 2)
            if data[record_start] != 2 {
                offset += 5 + record_length;
                continue;
            }

            // Get handshake message length
            let handshake_length =
                Self::u24_to_u32(&data[record_start + 1..record_start + 4])? as usize;

            if record_start + 4 + handshake_length > data.len() {
                break; // Handshake message extends beyond available data
            }

            // ServerHello structure:
            let handshake_body_start = record_start + 4;
            if handshake_body_start + 38 > data.len() {
                break; // Not enough data for ServerHello header
            }

            // Skip TLS version (2 bytes) + Random (32 bytes) = 34 bytes
            let session_id_length_pos = handshake_body_start + 34;
            if session_id_length_pos >= data.len() {
                break;
            }

            let session_id_length = data[session_id_length_pos] as usize;
            let cipher_suite_pos = session_id_length_pos + 1 + session_id_length;

            if cipher_suite_pos + 2 > data.len() {
                break; // Not enough data for cipher suite
            }

            // Extract cipher suite (2 bytes, big-endian)
            let cipher_suite =
                u16::from_be_bytes([data[cipher_suite_pos], data[cipher_suite_pos + 1]]);

            // Map cipher suite to name
            let cipher_suite_name = match cipher_suite {
                0x1301 => "TLS13_AES_128_GCM_SHA256",
                0x1302 => "TLS13_AES_256_GCM_SHA384",
                0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
                _ => return Ok(Some(format!("Unknown(0x{:04x})", cipher_suite))),
            };

            return Ok(Some(cipher_suite_name.to_string()));
        }

        Ok(None)
    }

    /// Helper function to convert 3-byte big-endian to u32
    fn u24_to_u32(bytes: &[u8]) -> Result<u32> {
        if bytes.len() < 3 {
            return Err(anyhow!("Not enough bytes for u24"));
        }
        Ok(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32))
    }

    /// Find ServerHello handshake message in buffer (offset-robust)
    /// Searches for the actual start of ServerHello message, handling prefixes and QUIC data
    /// Returns (handshake_start_offset, handshake_length) if found
    pub fn find_server_hello_handshake(data: &[u8]) -> Option<(usize, usize)> {
        // Search for ServerHello handshake message (type 0x02)
        // We need at least 6 bytes: type(1) + length(3) + legacy_version(2)
        for i in 0..data.len().saturating_sub(6) {
            if data[i] != 0x02 {
                continue; // Not a handshake message
            }

            // Parse u24 length
            if i + 3 >= data.len() {
                continue;
            }
            let len = match Self::u24_to_u32(&data[i + 1..i + 4]) {
                Ok(l) => l as usize,
                Err(_) => continue,
            };

            let body_start = i + 4;
            if body_start + 2 > data.len() {
                continue;
            }

            // Check legacy_version in ServerHello should be 0x03 0x03 (TLS 1.2 legacy version)
            // TLS 1.3 ServerHello also uses 0x03 0x03 for legacy_version
            if data[body_start] != 0x03 || data[body_start + 1] != 0x03 {
                continue;
            }

            // Validate that the message fits within the buffer
            if i + 4 + len <= data.len() {
                return Some((i, len));
            }
        }
        None
    }

    /// Extract ServerHello bytes from QUIC CRYPTO frame data (suggestion 8.1 from SCAN_REPORT_ANALYSIS).
    /// QUIC carries TLS handshake messages in CRYPTO frames; this locates the ServerHello and returns
    /// a copy for cipher suite parsing. Use when the QUIC stack exposes handshake/CRYPTO stream data.
    /// Returns None if no valid ServerHello is found.
    pub fn try_extract_server_hello_from_quic_crypto(data: &[u8]) -> Option<Vec<u8>> {
        let (start, len) = Self::find_server_hello_handshake(data)?;
        let end = start + 4 + len; // handshake header (4) + body
        if end <= data.len() {
            Some(data[start..end].to_vec())
        } else {
            None
        }
    }

    /// Parse CertificateVerify handshake to extract signature scheme (suggestion 8.2).
    /// Use when decrypted TLS 1.3 handshake bytes are available (e.g. from a rustls callback).
    /// CertificateVerify format: [handshake_type(1)=0x0f] [length(3)] [DigitallySigned: scheme(2) + signature(variable)].
    /// Returns the 2-byte SignatureScheme codepoint if found.
    pub fn parse_certificate_verify_signature_scheme(data: &[u8]) -> Option<u16> {
        const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;
        if data.len() < 6 {
            return None;
        }
        // Search for CertificateVerify (type 0x0f) in buffer (handshake or TLS record payload)
        for i in 0..data.len().saturating_sub(6) {
            if data[i] != HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                continue;
            }
            let _body_len = match Self::u24_to_u32(&data[i + 1..i + 4]) {
                Ok(l) => l as usize,
                Err(_) => continue,
            };
            if i + 4 + 2 > data.len() {
                continue;
            }
            let scheme = u16::from_be_bytes([data[i + 4], data[i + 5]]);
            return Some(scheme);
        }
        None
    }

    /// Parse ServerHello message to extract selected group from key_share extension
    /// FIXED: In TLS 1.3, the selected group is in key_share extension (0x0033), not supported_groups
    /// supported_groups only appears in ClientHello; ServerHello uses key_share to indicate the selected group
    pub fn parse_server_hello_group(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 6 {
            return Err(anyhow!("ServerHello too short"));
        }

        // FIXED: Check if ServerHello is at byte 0, otherwise search for it
        let (handshake_start, handshake_length) = if data[0] == TlsMessageType::ServerHello as u8 {
            // ServerHello at byte 0
            let msg_len = Self::u24_to_u32(&data[1..4])? as usize;
            (0, msg_len)
        } else {
            // Search for ServerHello in buffer (offset-robust)
            match Self::find_server_hello_handshake(data) {
                Some((start, len)) => (start, len),
                None => return Err(anyhow!("ServerHello not found in buffer")),
            }
        };

        // Validate handshake message length
        if handshake_start + 4 + handshake_length > data.len() {
            return Err(anyhow!("ServerHello message incomplete"));
        }

        // Skip handshake header (type + length = 4 bytes) and protocol version (2 bytes)
        // handshake_start is the offset where ServerHello starts, so we add 4 for header + 2 for version
        let mut pos = handshake_start + 4 + 2; // Skip handshake header (4 bytes) + protocol version (2 bytes)

        // Skip random (32 bytes)
        pos += 32;

        // Skip session ID
        if pos >= data.len() {
            return Err(anyhow!("ServerHello truncated at session ID"));
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Skip cipher suite (2 bytes)
        if pos + 1 >= data.len() {
            return Err(anyhow!("ServerHello truncated at cipher suite"));
        }
        pos += 2;

        // Skip compression method (1 byte)
        if pos >= data.len() {
            return Err(anyhow!("ServerHello truncated at compression"));
        }
        pos += 1;

        // Parse extensions
        if pos + 1 >= data.len() {
            return Err(anyhow!("ServerHello truncated at extensions"));
        }

        let extensions_len = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        pos += 2;

        let extensions_end = pos + extensions_len as usize;
        if extensions_end > data.len() {
            return Err(anyhow!("Extensions length exceeds message"));
        }

        // Parse each extension
        while pos < extensions_end {
            if pos + 3 >= extensions_end {
                return Err(anyhow!("Extension header truncated"));
            }

            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_len = ((data[pos + 2] as u16) << 8) | (data[pos + 3] as u16);
            pos += 4;

            if pos + ext_len as usize > extensions_end {
                return Err(anyhow!("Extension data truncated"));
            }

            // FIXED: In TLS 1.3, check for key_share extension (0x0033) instead of supported_groups
            // The key_share extension contains the selected group ID
            if ext_type == TlsExtensionType::KeyShare as u16 {
                let result = self.parse_key_share_extension(&data[pos..pos + ext_len as usize]);
                return result;
            }

            pos += ext_len as usize;
        }

        Ok(None)
    }

    /// Parse key_share extension to extract selected group ID
    /// FIXED: key_share extension format: ClientHello has list, ServerHello has single entry
    /// ServerHello key_share: group (2 bytes) + key_exchange_length (2 bytes) + key_exchange_data (variable)
    fn parse_key_share_extension(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 2 {
            return Err(anyhow!("Key share extension too short"));
        }

        // In ServerHello, key_share contains a single entry:
        // - group (2 bytes, big-endian)
        // - key_exchange_length (2 bytes, big-endian)
        // - key_exchange_data (variable length)
        let selected_group = ((data[0] as u16) << 8) | (data[1] as u16);

        // Return the selected group ID (can be classical or PQC)
        Ok(Some(selected_group))
    }

    /// Parse supported_groups extension (used in ClientHello, not ServerHello)
    /// NOTE: This is kept for reference but is not used for PQC detection in TLS 1.3
    /// In TLS 1.3, ServerHello uses key_share extension, not supported_groups
    fn parse_supported_groups_extension(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 2 {
            return Err(anyhow!("Supported groups extension too short"));
        }

        let groups_len = ((data[0] as u16) << 8) | (data[1] as u16);
        if data.len() < (groups_len + 2) as usize {
            return Err(anyhow!("Supported groups data truncated"));
        }

        // Parse groups list
        let mut pos = 2;
        let groups_end = pos + groups_len as usize;

        while pos < groups_end {
            if pos + 1 >= groups_end {
                return Err(anyhow!("Group entry truncated"));
            }

            let group = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);

            // Check if this is a PQC group (using IANA codepoints)
            if self.is_pqc_group(group) {
                return Ok(Some(group));
            }

            pos += 2;
        }

        Ok(None)
    }

    /// Parse EncryptedExtensions message to check for KEM extensions
    pub fn parse_encrypted_extensions_kem(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 6 {
            return Err(anyhow!("EncryptedExtensions too short"));
        }

        // Check message type
        if data[0] != TlsMessageType::EncryptedExtensions as u8 {
            return Err(anyhow!("Not an EncryptedExtensions message"));
        }

        // Parse message length (3 bytes, big-endian)
        let msg_len = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

        if data.len() < (msg_len + 4) as usize {
            return Err(anyhow!("EncryptedExtensions message incomplete"));
        }

        // Skip protocol version (2 bytes)
        let mut pos = 6;

        // Parse extensions
        if pos + 1 >= data.len() {
            return Err(anyhow!("EncryptedExtensions truncated at extensions"));
        }

        let extensions_len = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        pos += 2;

        let extensions_end = pos + extensions_len as usize;
        if extensions_end > data.len() {
            return Err(anyhow!("Extensions length exceeds message"));
        }

        // Parse each extension
        while pos < extensions_end {
            if pos + 3 >= extensions_end {
                return Err(anyhow!("Extension header truncated"));
            }

            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_len = ((data[pos + 2] as u16) << 8) | (data[pos + 3] as u16);
            pos += 4;

            if pos + ext_len as usize > extensions_end {
                return Err(anyhow!("Extension data truncated"));
            }

            // NOTE: KEM extensions (0xFE00/0xFE01) are experimental and not standardized
            // In practice, PQC groups are negotiated via key_share extension using IANA-registered group IDs
            // These extensions are kept for backward compatibility but may not be used in real implementations
            if ext_type == TlsExtensionType::KemExtension as u16 {
                return self.parse_kem_extension(&data[pos..pos + ext_len as usize]);
            }

            if ext_type == TlsExtensionType::KemGroupExtension as u16 {
                return self.parse_kem_group_extension(&data[pos..pos + ext_len as usize]);
            }

            pos += ext_len as usize;
        }

        Ok(None)
    }

    /// Parse KEM extension to extract selected KEM ID
    fn parse_kem_extension(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 2 {
            return Err(anyhow!("KEM extension too short"));
        }

        // KEM extension contains selected_kem_id (2 bytes)
        let kem_id = ((data[0] as u16) << 8) | (data[1] as u16);

        // Validate that this is a PQC KEM ID (using IANA codepoints)
        if self.is_pqc_group(kem_id) {
            Ok(Some(kem_id))
        } else {
            Ok(None)
        }
    }

    /// Parse KEM group extension to extract selected KEM group
    fn parse_kem_group_extension(&self, data: &[u8]) -> Result<Option<u16>> {
        if data.len() < 2 {
            return Err(anyhow!("KEM group extension too short"));
        }

        // KEM group extension contains selected_kem_group (2 bytes)
        let kem_group = ((data[0] as u16) << 8) | (data[1] as u16);

        // Validate that this is a PQC group (using IANA codepoints)
        if self.is_pqc_group(kem_group) {
            Ok(Some(kem_group))
        } else {
            Ok(None)
        }
    }

    /// Map PQC group ID to algorithm name
    /// FIXED: Updated to match IANA registry codepoints
    pub fn group_id_to_algorithm(&self, group_id: u16) -> Option<String> {
        match group_id {
            // ML-KEM family (IANA: 512-514)
            512 => Some("ML-KEM-512".to_string()),
            513 => Some("ML-KEM-768".to_string()),
            514 => Some("ML-KEM-1024".to_string()),

            // Hybrid groups (IANA: 4587-4592)
            4587 => Some("X25519ML-KEM-512".to_string()),
            4588 => Some("X25519ML-KEM-768".to_string()),
            4589 => Some("X25519ML-KEM-1024".to_string()),
            4590 => Some("P256ML-KEM-512".to_string()),
            4591 => Some("P256ML-KEM-768".to_string()),
            4592 => Some("P256ML-KEM-1024".to_string()),

            // Legacy Kyber groups (IANA: 25497-25498, obsolete)
            25497 => Some("X25519Kyber768Draft00".to_string()),
            25498 => Some("X25519Kyber512Draft00".to_string()),

            // Classical groups (for reference, not PQC)
            0x001d => Some("X25519".to_string()),
            0x0017 => Some("P-256".to_string()),
            0x0018 => Some("P-384".to_string()),
            0x0019 => Some("P-521".to_string()),

            // Unknown PQC groups (fallback)
            _ if self.is_pqc_group(group_id) => Some(format!("PQC-Group-{}", group_id)),
            _ => None,
        }
    }

    /// Validate if a group ID is a PQC group
    /// FIXED: Updated to check IANA-registered PQC codepoints
    pub fn is_pqc_group(&self, group_id: u16) -> bool {
        // ML-KEM groups (512-514)
        if (PQC_GROUP_MLKEM_MIN..=PQC_GROUP_MLKEM_MAX).contains(&group_id) {
            return true;
        }

        // Hybrid groups (4587-4592)
        if (PQC_GROUP_HYBRID_MIN..=PQC_GROUP_HYBRID_MAX).contains(&group_id) {
            return true;
        }

        // Legacy Kyber groups (25497-25498)
        if (PQC_GROUP_LEGACY_KYBER_MIN..=PQC_GROUP_LEGACY_KYBER_MAX).contains(&group_id) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_group_range() {
        let parser = TlsMessageParser::new();

        // Test IANA-registered PQC groups
        assert!(parser.is_pqc_group(512)); // ML-KEM-512
        assert!(parser.is_pqc_group(513)); // ML-KEM-768
        assert!(parser.is_pqc_group(514)); // ML-KEM-1024
        assert!(parser.is_pqc_group(4588)); // X25519ML-KEM-768
        assert!(parser.is_pqc_group(25497)); // X25519Kyber768Draft00 (legacy)
        assert!(!parser.is_pqc_group(0x001d)); // X25519 (classical)
        assert!(!parser.is_pqc_group(0x0000));
    }

    #[test]
    fn test_group_id_to_algorithm() {
        let parser = TlsMessageParser::new();

        assert_eq!(
            parser.group_id_to_algorithm(512),
            Some("ML-KEM-512".to_string())
        );
        assert_eq!(
            parser.group_id_to_algorithm(513),
            Some("ML-KEM-768".to_string())
        );
        assert_eq!(
            parser.group_id_to_algorithm(514),
            Some("ML-KEM-1024".to_string())
        );
        assert_eq!(
            parser.group_id_to_algorithm(4588),
            Some("X25519ML-KEM-768".to_string())
        );
        assert_eq!(
            parser.group_id_to_algorithm(25497),
            Some("X25519Kyber768Draft00".to_string())
        );
        assert_eq!(
            parser.group_id_to_algorithm(0x001d),
            Some("X25519".to_string())
        ); // Classical
        assert_eq!(parser.group_id_to_algorithm(0x0000), None);
    }
}
