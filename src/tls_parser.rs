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

/// TLS extension types used by the parser
#[derive(Debug, Clone, PartialEq)]
pub enum TlsExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    KeyShare = 51,
    SupportedVersions = 43,
}

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
                    0x1303 => "TLS13_CHACHA20_POLY1305_SHA256",
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
            0x1303 => "TLS13_CHACHA20_POLY1305_SHA256",
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
                0x1303 => "TLS13_CHACHA20_POLY1305_SHA256",
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

    /// Map a named-group codepoint to its IANA registry name.
    /// Returns None for codepoints that are not in [`crate::constants::NAMED_GROUPS`].
    pub fn group_id_to_algorithm(&self, group_id: u16) -> Option<String> {
        crate::constants::named_group(group_id).map(|g| g.name.to_string())
    }

    /// True if the group includes a post-quantum KEM (hybrid or pure).
    pub fn is_pqc_group(&self, group_id: u16) -> bool {
        crate::constants::is_pqc_group(group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_group_range() {
        let parser = TlsMessageParser::new();
        assert!(parser.is_pqc_group(512)); // MLKEM512
        assert!(parser.is_pqc_group(513)); // MLKEM768
        assert!(parser.is_pqc_group(514)); // MLKEM1024
        assert!(parser.is_pqc_group(4587)); // SecP256r1MLKEM768
        assert!(parser.is_pqc_group(4588)); // X25519MLKEM768
        assert!(parser.is_pqc_group(25497)); // X25519Kyber768Draft00 (obsolete)
        assert!(!parser.is_pqc_group(0x001d)); // x25519
        assert!(!parser.is_pqc_group(0x0000));
    }

    #[test]
    fn test_group_id_to_algorithm() {
        let parser = TlsMessageParser::new();
        assert_eq!(
            parser.group_id_to_algorithm(513).as_deref(),
            Some("MLKEM768")
        );
        assert_eq!(
            parser.group_id_to_algorithm(4587).as_deref(),
            Some("SecP256r1MLKEM768")
        );
        assert_eq!(
            parser.group_id_to_algorithm(4588).as_deref(),
            Some("X25519MLKEM768")
        );
        assert_eq!(
            parser.group_id_to_algorithm(4589).as_deref(),
            Some("SecP384r1MLKEM1024")
        );
        assert_eq!(
            parser.group_id_to_algorithm(25498).as_deref(),
            Some("SecP256r1Kyber768Draft00")
        );
        assert_eq!(
            parser.group_id_to_algorithm(0x001d).as_deref(),
            Some("x25519")
        );
        assert_eq!(parser.group_id_to_algorithm(0x0000), None);
    }

    #[test]
    fn test_parse_server_hello_group_x25519mlkem768() {
        // Minimal TLS 1.3 ServerHello: legacy_version, random, empty session id,
        // cipher suite 0x1301, null compression, key_share extension (group 0x11ec).
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id len
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        let key_share = [0x11, 0xec, 0x00, 0x00];
        let mut exts = vec![0x00, 0x33, 0x00, key_share.len() as u8];
        exts.extend_from_slice(&key_share);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![0x02, 0x00, 0x00, body.len() as u8];
        msg.extend_from_slice(&body);

        let parser = TlsMessageParser::new();
        assert_eq!(parser.parse_server_hello_group(&msg).unwrap(), Some(0x11ec));
        assert_eq!(
            parser
                .parse_server_hello_cipher_suite(&msg)
                .unwrap()
                .as_deref(),
            Some("TLS13_AES_128_GCM_SHA256")
        );
    }
}
