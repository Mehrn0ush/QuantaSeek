use crate::types::HandshakeConfig;
use crate::{HandshakeProfile, HandshakeResult};
use anyhow::Result;
use tokio::net::TcpStream;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::Read;
use std::sync::{Arc, Mutex};

// FIXED: CapturingVerifier to extract TLS 1.3 CertificateVerify signature scheme
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::UnixTime;
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// Verifier that captures TLS 1.3 CertificateVerify signature scheme (suggestion 8.2).
/// This allows us to detect PQC signatures in TLS 1.3 without decrypting records.
/// Only `verify_tls13_signature` sets the captured scheme; nothing else should clear or set it,
/// so `pqc_signature_used` is `Some(true/false)` for normal TLS 1.3 handshakes.
#[derive(Debug)]
pub struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// Captured scheme from TLS 1.3 CertificateVerify; set only in verify_tls13_signature.
    tls13_certverify_scheme: Arc<Mutex<Option<SignatureScheme>>>,
}

impl CapturingVerifier {
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        tls13_certverify_scheme: Arc<Mutex<Option<SignatureScheme>>>,
    ) -> Self {
        Self {
            inner,
            tls13_certverify_scheme,
        }
    }

    /// Get the captured signature scheme (if any)
    pub fn get_captured_scheme(&self) -> Option<SignatureScheme> {
        // Mutex lock should never fail in normal operation
        // If it does, it indicates a poisoned mutex (panic in another thread)
        // In that case, we return None rather than panicking
        self.tls13_certverify_scheme
            .lock()
            .ok()
            .and_then(|lock| *lock)
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Optional: also capture TLS 1.2 signature scheme if you want
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Only path that sets the captured scheme (suggestion 8.2). Do not clear elsewhere.
        if let Ok(mut lock) = self.tls13_certverify_scheme.lock() {
            *lock = Some(dss.scheme);
        }
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Root store built from the Mozilla-derived `webpki-roots` bundle.
pub fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Values collected by [`HandshakeEngine::perform_handshake_internal`]:
/// (tls_version, cipher_suite, success, peer_certs, alpn, raw_server_hello,
/// raw_certificate, key_exchange, nine extension flags, alpn string,
/// raw_tls_records). Candidate for a struct in the detection-engine rework.
type RawHandshakeData = (
    String,
    String,
    bool,
    Option<Vec<CertificateDer<'static>>>,
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
    String,
    Vec<u8>,
);

/// Shared slot the capturing verifier writes the TLS 1.3 CertificateVerify scheme into.
type CapturedScheme = Arc<Mutex<Option<SignatureScheme>>>;

pub struct HandshakeEngine {
    profile: HandshakeProfile,
    config: HandshakeConfig,
}

impl HandshakeEngine {
    pub fn new(profile: HandshakeProfile) -> Self {
        Self {
            profile,
            config: HandshakeConfig::default(),
        }
    }

    /// Create a new handshake engine with custom configuration
    pub fn with_config(profile: HandshakeProfile, config: HandshakeConfig) -> Self {
        Self { profile, config }
    }

    /// Create a new handshake engine with optimized settings for performance
    pub fn new_optimized(profile: HandshakeProfile) -> Self {
        let config = HandshakeConfig {
            timeout_ms: 2000,
            enable_optimizations: true,
            ..HandshakeConfig::default()
        };
        Self { profile, config }
    }

    /// Create a new handshake engine with conservative settings for reliability
    pub fn new_conservative(profile: HandshakeProfile) -> Self {
        let config = HandshakeConfig {
            timeout_ms: 10000,
            enable_optimizations: false,
            ..HandshakeConfig::default()
        };
        Self { profile, config }
    }

    /// Create with custom timeout
    pub fn with_timeout(profile: HandshakeProfile, timeout_ms: u64) -> Self {
        let config = HandshakeConfig {
            timeout_ms,
            ..HandshakeConfig::default()
        };
        Self { profile, config }
    }

    /// Trust anchors: the configured store, or the webpki-roots bundle.
    fn root_store(&self) -> RootCertStore {
        match &self.config.trust_anchors {
            Some(store) => (**store).clone(),
            None => webpki_root_store(),
        }
    }

    /// Disable performance optimizations
    pub fn without_optimizations(mut self) -> Self {
        self.config.enable_optimizations = false;
        self
    }

    pub async fn perform_handshake(
        &self,
        stream: TcpStream,
        hostname: &str,
    ) -> Result<HandshakeResult> {
        let start_time = std::time::Instant::now();

        // Strip port if present for SNI/ServerName
        // Accept a legacy "host:port" form, but never split an IPv6 literal.
        let hostname_only = match hostname.split_once(':') {
            Some((host, port)) if !port.contains(':') && port.parse::<u16>().is_ok() => host,
            _ => hostname,
        };

        // Create TLS configuration with signature scheme capture
        let (config, captured_scheme) = self.create_optimized_tls_config()?;

        // Perform handshake
        let timeout_ms = self.config.timeout_ms;
        let handshake_data = tokio::task::spawn_blocking({
            let hostname_no_port = hostname_only.to_string();
            let config = Arc::clone(&config);
            let std_stream = stream.into_std()?;
            let profile = self.profile;
            move || -> Result<RawHandshakeData> {
                Self::perform_handshake_internal(
                    config,
                    hostname_no_port,
                    std_stream,
                    profile,
                    timeout_ms,
                )
            }
        })
        .await??;

        let handshake_duration = start_time.elapsed();

        // Extract results
        let (
            tls_version,
            cipher_suite,
            handshake_success,
            peer_certs,
            _alpn_protocol,
            raw_server_hello,
            raw_certificate,
            key_exchange,
            has_key_share,
            has_supported_versions,
            has_signature_algorithms,
            has_alpn,
            has_ocsp_stapling,
            has_session_ticket,
            has_psk_key_exchange_modes,
            has_early_data,
            has_pre_shared_key,
            alpn_protocol_str,
            raw_tls_records,
        ) = handshake_data;

        // FIXED: Extract CertificateVerify signature algorithm with priority:
        // 1. TLS 1.3: From rustls verifier callback (captured_scheme)
        // 2. TLS 1.2: From raw TLS records parsing (fallback)
        let cert_verify_signature = {
            // First, try to get from captured TLS 1.3 CertificateVerify signature scheme
            // Mutex lock should never fail in normal operation
            if let Ok(captured) = captured_scheme.lock() {
                if let Some(scheme) = *captured {
                    // Convert SignatureScheme to u16 codepoint
                    // In rustls 0.23, SignatureScheme can be converted to u16 via Into trait
                    Some(scheme.into())
                } else {
                    // Fallback: Try to parse from raw TLS records (works for TLS 1.2)
                    if !raw_tls_records.is_empty() {
                        self.extract_certificate_verify_signature(&raw_tls_records)
                    } else {
                        None
                    }
                }
            } else {
                // Mutex lock failed (poisoned), fallback to parsing raw TLS records
                if !raw_tls_records.is_empty() {
                    self.extract_certificate_verify_signature(&raw_tls_records)
                } else {
                    None
                }
            }
        };

        // Create extension map
        let mut extension_map = crate::types::ExtensionMap::default();

        // Extract certificate information with enhanced fallback logic
        let mut certificate_info = None;
        let mut certificate_visible = false;

        if let Some(certs) = peer_certs {
            if let Some(cert) = certs.first() {
                certificate_visible = true;

                // Use the improved certificate parser
                let cert_parser = crate::cert::CertificateParser::new();
                match cert_parser.parse_certificate(cert.as_ref()) {
                    Ok(parsed_cert) => {
                        certificate_info = Some(parsed_cert);
                    }
                    Err(_) => {
                        // FIXED: Don't create fake CertificateInfo with Unknown values
                        // If parsing fails, leave certificate_info as None to indicate unavailability
                        // This is more honest than creating misleading data
                        certificate_visible = false;
                    }
                }
            }
        }

        // If no certificate from peer_certs, try to extract from raw_certificate
        if certificate_info.is_none() && !raw_certificate.is_empty() {
            // Try to parse raw certificate data
            let cert_parser = crate::cert::CertificateParser::new();
            if let Ok(parsed_cert) = cert_parser.parse_certificate(&raw_certificate) {
                certificate_info = Some(parsed_cert);
                certificate_visible = true;
            }
        }

        // FIXED: PQC extensions should be determined from actual handshake, not profile
        // Since we don't currently parse PQC extensions from handshake, use default (false)
        // TODO: Parse key_share extension to detect PQC groups, then set kem/kem_group accordingly
        let pqc_extensions = crate::types::PqcExtensions::default();

        // FIXED: Extract PQC signature algorithms only from actual handshake data
        // Do not use profile or hostname-based heuristics
        let mut pqc_signature_algorithms = Vec::new();

        // FIXED: Use constants::is_pqc_signature_algorithm(u16) and constants::is_pqc_oid for detection
        use crate::constants::{
            get_signature_algorithm_name, is_pqc_oid, is_pqc_signature_algorithm,
        };

        // 1) Extract from CertificateVerify signature (most reliable source for TLS 1.2)
        // Note: In TLS 1.3, CertificateVerify is encrypted, so this will be None
        if let Some(sig_scheme) = cert_verify_signature {
            if is_pqc_signature_algorithm(sig_scheme) {
                let sig_name = get_signature_algorithm_name(sig_scheme);
                if !pqc_signature_algorithms.contains(&sig_name) {
                    pqc_signature_algorithms.push(sig_name);
                }
            }
        }

        // 2) Extract from certificate signature algorithm OID (works for TLS 1.3/QUIC where CertificateVerify is not visible)
        if let Some(ref cert_info) = certificate_info {
            if let Some(ref oid) = cert_info.signature_algorithm_oid {
                if is_pqc_oid(oid) {
                    let label = format!("pqc_sig_oid:{}", oid);
                    if !pqc_signature_algorithms.contains(&label) {
                        pqc_signature_algorithms.push(label);
                    }
                }
            }
        }

        // FIXED: Determine PQC signature usage (suggestion 8.2). Priority: 1) CapturingVerifier
        // (TLS 1.3 CertificateVerify), 2) raw TLS records (TLS 1.2), 3) certificate OID when cert visible.
        // When certificate_visible is true, always set Some(true/false) from cert OID so "Not Implemented" is rare.
        let pqc_signature_used: Option<bool> = if let Some(sig_scheme) = cert_verify_signature {
            // CapturingVerifier or raw records: definitive scheme
            Some(is_pqc_signature_algorithm(sig_scheme))
        } else {
            certificate_info.as_ref().map(|cert_info| {
                cert_info
                    .signature_algorithm_oid
                    .as_ref()
                    .is_some_and(|oid| is_pqc_oid(oid))
            })
        };

        // Remove duplicates and sort for consistency
        pqc_signature_algorithms.sort();
        pqc_signature_algorithms.dedup();

        // FIXED: Create TLS features structure with consistent ALPN handling
        // Always use Some(vec![]) for type consistency in JSON
        // Some([]) = no protocol advertised or not collected, Some([...]) = protocol negotiated
        // Clone alpn_protocol_str before using it in tls_features (since we'll need it again for extension_map)
        let alpn_protocol_clone = alpn_protocol_str.clone();
        let tls_features = crate::types::TlsFeatures {
            alpn: if has_alpn {
                if !alpn_protocol_str.is_empty() {
                    Some(vec![alpn_protocol_str])
                } else {
                    // ALPN was offered but no protocol negotiated - empty list means no protocol advertised
                    Some(Vec::new())
                }
            } else {
                // ALPN was not offered/collected - use Some([]) instead of None for type consistency
                Some(Vec::new())
            },
            early_data_status: if has_early_data {
                crate::types::EarlyDataStatus::Accepted
            } else {
                crate::types::EarlyDataStatus::NotOffered
            },
            session_ticket: Some(has_session_ticket),
            ocsp_stapling: has_ocsp_stapling,
        };

        // FIXED: Always set mandatory TLS 1.3 extensions based on detected flags
        // These extensions are required by TLS 1.3 specification regardless of profile
        // Use has_key_share, has_supported_versions, and has_signature_algorithms flags
        // which are always true for TLS 1.3. This ensures consistency across all profiles
        // (Classic, Hybrid, Fallback, MaxPQC) and prevents false negatives.
        extension_map.key_share = has_key_share;
        extension_map.supported_versions = has_supported_versions;
        extension_map.signature_algorithms = has_signature_algorithms;

        // Update extension map based on detected extensions (for optional extensions)
        if has_alpn {
            // Use actual ALPN protocol from handshake, not hardcoded value
            if !alpn_protocol_clone.is_empty() {
                extension_map.alpn_protocols = vec![alpn_protocol_clone];
            } else {
                // ALPN was offered but no protocol negotiated
                extension_map.alpn_protocols = Vec::new();
            }
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

        // Note: Security warnings are not currently included in HandshakeResult
        // If needed in the future, add security_warnings field to HandshakeResult

        let cipher_suite_reason = if cipher_suite == "unknown" {
            Some("rustls_negotiated_none_or_parse_failed".to_string())
        } else {
            None
        };
        Ok(HandshakeResult {
            target: hostname.to_string(),
            tls_version,
            cipher_suite,
            key_exchange,
            pqc_extensions,
            certificate_info,
            raw_server_hello: raw_server_hello.to_vec(),
            raw_certificate: raw_certificate.to_vec(),
            alert_info: None,
            certificate_visible,
            handshake_complete: handshake_success,
            pqc_signature_algorithms,
            pqc_signature_used,
            tls_features,
            handshake_duration_ms: Some(std::cmp::max(handshake_duration.as_millis() as u64, 1)), // FIXED: Minimum 1ms to avoid null serialization
            client_profile_used: self.profile,
            extension_map,
            connection_type: Some("tls".to_string()),
            cipher_suite_reason,
        })
    }

    /// Internal handshake function using rustls::ClientConnection for raw TLS record capture
    /// FIXED: Removed unused profile parameter - profile is not used in this function
    fn perform_handshake_internal(
        config: Arc<ClientConfig>,
        hostname: String,
        mut stream: std::net::TcpStream,
        _profile: HandshakeProfile,
        timeout_ms: u64,
    ) -> Result<RawHandshakeData> {
        // In rustls 0.23, ServerName is in pki_types
        use rustls::pki_types::ServerName;
        use std::time::Duration;

        // Create ClientConnection for manual handshake processing
        let server_name =
            ServerName::try_from(hostname).map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let mut client = ClientConnection::new(config, server_name)?;

        // FIXED: Ensure stream is in blocking mode for synchronous I/O in spawn_blocking
        // tokio::net::TcpStream::into_std() may return a non-blocking stream
        stream.set_nonblocking(false)?;

        // Apply socket timeouts based on configured timeout_ms
        stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

        // Buffer for capturing raw TLS records
        let mut raw_tls_records = Vec::new();
        let mut raw_server_hello = Vec::new();
        let mut raw_certificate = Vec::new();

        // Perform handshake manually to capture raw TLS records
        let mut tls_buffer = [0u8; 4096];
        let mut handshake_complete = false;
        while !handshake_complete {
            // Write TLS data if needed
            while client.wants_write() {
                let n = client.write_tls(&mut stream)?;
                if n == 0 {
                    break;
                }
            }

            // Read TLS data from network
            if client.wants_read() {
                match stream.read(&mut tls_buffer) {
                    Ok(n) => {
                        if n == 0 {
                            return Err(anyhow::anyhow!("Connection closed during handshake"));
                        }

                        // Capture raw TLS record before processing
                        raw_tls_records.extend_from_slice(&tls_buffer[..n]);

                        // Feed to rustls
                        client.read_tls(&mut &tls_buffer[..n])?;
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to read from stream: {}", e));
                    }
                }
            }

            // Process new packets
            let _state = client.process_new_packets()?;

            // Check if handshake is complete
            handshake_complete = !client.is_handshaking();
        }

        // rustls considers the handshake done once it has queued the client
        // Finished; send it, or the server never completes the handshake.
        while client.wants_write() {
            if client.write_tls(&mut stream)? == 0 {
                break;
            }
        }

        // Extract handshake messages from all captured records
        Self::extract_handshake_messages(
            &raw_tls_records,
            &mut raw_server_hello,
            &mut raw_certificate,
        );

        // Extract peer certificates
        let peer_certs = client.peer_certificates().map(|certs| certs.to_vec());

        // Extract TLS version - FIXED: Use "unknown" if not available
        let tls_version = match client.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => "1.3".to_string(),
            Some(rustls::ProtocolVersion::TLSv1_2) => "1.2".to_string(),
            _ => "unknown".to_string(), // FIXED: Don't assume 1.3
        };

        // Extract cipher suite - FIXED: Try parsing from raw_server_hello first, then fallback to rustls
        let cipher_suite = if !raw_server_hello.is_empty() {
            // Try to parse cipher suite from raw ServerHello
            let tls_parser = crate::tls_parser::TlsMessageParser::new();
            match tls_parser.parse_server_hello_cipher_suite(&raw_server_hello) {
                Ok(Some(cs)) => cs,
                _ => {
                    // Fallback to rustls negotiated cipher suite
                    match client.negotiated_cipher_suite() {
                        Some(cs) => format!("{:?}", cs.suite()),
                        None => "unknown".to_string(),
                    }
                }
            }
        } else {
            // No raw_server_hello available, use rustls negotiated cipher suite
            match client.negotiated_cipher_suite() {
                Some(cs) => format!("{:?}", cs.suite()),
                None => "unknown".to_string(),
            }
        };

        // Extract ALPN protocol
        let alpn_protocol = client.alpn_protocol().map(|p| p.to_vec());
        let alpn_protocol_str = client
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();

        // FIXED: Extract key exchange from actual handshake
        // Priority: 1) Parse key_share from raw_server_hello (TLS 1.3), 2) Extract from cipher suite (fallback)
        let mut key_exchange = Vec::new();

        // FIXED: Parse key_share extension from raw_server_hello to detect PQC groups
        // This is the correct way to detect PQC in TLS 1.3
        if !raw_server_hello.is_empty() {
            let tls_parser = crate::tls_parser::TlsMessageParser::new();
            if let Ok(Some(selected_group)) = tls_parser.parse_server_hello_group(&raw_server_hello)
            {
                // Map group ID to algorithm name
                if let Some(alg_name) = tls_parser.group_id_to_algorithm(selected_group) {
                    key_exchange.push(alg_name);
                } else {
                    // Unknown group - use group ID as fallback
                    key_exchange.push(format!("Group-{}", selected_group));
                }
            }
        }

        // Fallback: the group rustls reports as negotiated (observed, not guessed).
        if key_exchange.is_empty() {
            if let Some(group) = client.negotiated_key_exchange_group() {
                key_exchange.push(crate::constants::get_group_name(u16::from(group.name())));
            }
        }

        // Check for various extensions and features
        let tls_is_13 = matches!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let has_key_share = tls_is_13; // key_share is mandatory in TLS 1.3
        let has_supported_versions = tls_is_13; // supported_versions is mandatory in TLS 1.3
        let has_signature_algorithms = true; // present in both 1.2/1.3
        let has_alpn = alpn_protocol.is_some();
        let has_ocsp_stapling = false; // Would need to parse CertificateStatus extension
        let has_session_ticket = false; // Would need to parse NewSessionTicket
        let has_psk_key_exchange_modes = false; // Would need to parse PSK extension
        let has_early_data = false; // Would need to parse EarlyData extension
        let has_pre_shared_key = false; // Would need to parse PSK extension

        Ok((
            tls_version,
            cipher_suite,
            true,
            peer_certs,
            alpn_protocol,
            raw_server_hello,
            raw_certificate,
            key_exchange,
            has_key_share,
            has_supported_versions,
            has_signature_algorithms,
            has_alpn,
            has_ocsp_stapling,
            has_session_ticket,
            has_psk_key_exchange_modes,
            has_early_data,
            has_pre_shared_key,
            alpn_protocol_str,
            raw_tls_records, // Return all captured raw TLS records
        ))
    }

    /// Create optimized TLS configuration with CertificateVerify signature scheme capture
    /// Returns both the config and a shared mutex to read the captured signature scheme
    fn create_optimized_tls_config(&self) -> Result<(Arc<ClientConfig>, CapturedScheme)> {
        // In rustls 0.23, ensure crypto provider is set (required for prefer-post-quantum feature)
        use rustls::crypto::aws_lc_rs::default_provider;
        let _ = default_provider().install_default();

        // In rustls 0.23, RootCertStore can be created from webpki_roots directly
        let root_store = self.root_store();

        // FIXED: Create shared mutex to capture TLS 1.3 CertificateVerify signature scheme
        let captured_scheme: Arc<Mutex<Option<SignatureScheme>>> = Arc::new(Mutex::new(None));

        // Build the default verifier (WebPKI)
        // In rustls 0.23, WebPkiServerVerifier::builder().build() returns Arc<WebPkiServerVerifier>
        // We create a wrapper that holds the Arc and implements ServerCertVerifier
        let webpki_verifier_arc =
            rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build WebPKI verifier: {}", e))?;

        // Create a wrapper that holds Arc<WebPkiServerVerifier> and implements ServerCertVerifier
        // This avoids the need to extract from Arc
        #[derive(Debug)]
        struct ArcVerifierWrapper(Arc<rustls::client::WebPkiServerVerifier>);
        impl ServerCertVerifier for ArcVerifierWrapper {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                intermediates: &[CertificateDer<'_>],
                server_name: &ServerName<'_>,
                ocsp_response: &[u8],
                now: UnixTime,
            ) -> Result<ServerCertVerified, Error> {
                self.0.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )
            }
            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                self.0.verify_tls12_signature(message, cert, dss)
            }
            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                self.0.verify_tls13_signature(message, cert, dss)
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.0.supported_verify_schemes()
            }
        }
        let arc_wrapper = ArcVerifierWrapper(webpki_verifier_arc);
        let inner_verifier: Arc<dyn ServerCertVerifier> = Arc::new(arc_wrapper);

        // Wrap it in CapturingVerifier
        let verifier = Arc::new(CapturingVerifier::new(
            inner_verifier,
            Arc::clone(&captured_scheme),
        ));

        // Create a custom config with optimizations
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // FIXED: Install custom verifier to capture TLS 1.3 CertificateVerify signature scheme
        config.dangerous().set_certificate_verifier(verifier);

        // Apply performance optimizations if enabled
        if self.config.enable_optimizations {
            // Enable session resumption for faster subsequent handshakes
            config.enable_sni = true;

            // IMPROVED: Enhanced session resumption for better PQC performance
            // Note: Session resumption is enabled by default in newer rustls versions
            // The resumption field is already configured in the builder

            // Enable early data for faster handshakes
            config.enable_early_data = true;

            // Optimize cipher suite preferences for PQC
            // Note: This would require custom cipher suite configuration
        }

        Ok((Arc::new(config), captured_scheme))
    }

    /// Extract handshake messages (ServerHello, Certificate) from raw TLS records
    /// FIXED: Improved parsing to handle TLS 1.3 record structure correctly
    fn extract_handshake_messages(
        raw_records: &[u8],
        server_hello: &mut Vec<u8>,
        certificate: &mut Vec<u8>,
    ) {
        use crate::constants::TLS_CONTENT_TYPE_HANDSHAKE;

        const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
        const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;

        // Early return if no data
        if raw_records.is_empty() {
            return;
        }

        let mut offset = 0;
        while offset + 5 <= raw_records.len() {
            // Parse TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
            let content_type = raw_records[offset];
            let _version = if offset + 2 <= raw_records.len() {
                u16::from_be_bytes([raw_records[offset + 1], raw_records[offset + 2]])
            } else {
                0
            };
            let record_length =
                u16::from_be_bytes([raw_records[offset + 3], raw_records[offset + 4]]) as usize;

            // Validate record length
            if offset + 5 + record_length > raw_records.len() {
                break; // Record extends beyond available data
            }

            // Check if this is a TLS handshake record
            if content_type == TLS_CONTENT_TYPE_HANDSHAKE {
                // Parse handshake messages within this record
                // TLS record structure: [content_type(1)] [version(2)] [length(2)] [handshake_messages...]
                let record_data_start = offset + 5;
                let record_data_end = record_data_start + record_length;

                let mut handshake_offset = record_data_start;
                while handshake_offset + 4 <= record_data_end {
                    if handshake_offset + 4 > raw_records.len() {
                        break;
                    }

                    // Parse handshake message header: [type(1)] [length(3)]
                    let handshake_type = raw_records[handshake_offset];
                    let handshake_length = u32::from_be_bytes([
                        0,
                        raw_records[handshake_offset + 1],
                        raw_records[handshake_offset + 2],
                        raw_records[handshake_offset + 3],
                    ]) as usize;

                    let message_start = handshake_offset;
                    let message_end = message_start + 4 + handshake_length;

                    // Validate message end
                    if message_end > raw_records.len() || message_end > record_data_end {
                        break;
                    }

                    // Extract ServerHello
                    if handshake_type == HANDSHAKE_TYPE_SERVER_HELLO && server_hello.is_empty() {
                        server_hello.extend_from_slice(&raw_records[message_start..message_end]);
                    }

                    // Extract Certificate
                    if handshake_type == HANDSHAKE_TYPE_CERTIFICATE && certificate.is_empty() {
                        certificate.extend_from_slice(&raw_records[message_start..message_end]);
                    }

                    // Move to next handshake message
                    handshake_offset = message_end;
                }
            }

            // Move to next TLS record
            // FIXED: Always advance offset, even if current record is not a handshake record
            let next_offset = offset + 5 + record_length;
            if next_offset > raw_records.len() {
                break; // Record extends beyond available data
            }
            offset = next_offset;
        }
    }

    /// Extract signature algorithm from CertificateVerify message in raw TLS records
    /// CertificateVerify structure: [handshake_type(1)] [length(3)] [signature_scheme(2)] [signature(variable)]
    /// Handshake type for CertificateVerify is 0x0f
    /// FIXED: Returns signature scheme codepoint (u16) instead of string to use constants::is_pqc_signature_algorithm(u16)
    fn extract_certificate_verify_signature(&self, raw_records: &[u8]) -> Option<u16> {
        use crate::constants::TLS_CONTENT_TYPE_HANDSHAKE;

        // CertificateVerify handshake type is 0x0f (RFC 8446)
        const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;

        // Search for CertificateVerify message in raw TLS records
        // TLS record format: [content_type(1)] [version(2)] [length(2)] [fragment(variable)]
        // Handshake message format: [msg_type(1)] [length(3)] [body(variable)]
        // CertificateVerify body: [signature_scheme(2)] [signature(variable)]

        let mut offset = 0;
        while offset + 5 <= raw_records.len() {
            // Check if this is a TLS handshake record
            if raw_records[offset] == TLS_CONTENT_TYPE_HANDSHAKE {
                // Parse TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
                if offset + 5 > raw_records.len() {
                    break;
                }

                let record_length =
                    u16::from_be_bytes([raw_records[offset + 3], raw_records[offset + 4]]) as usize;
                if offset + 5 + record_length > raw_records.len() {
                    break;
                }

                // Parse handshake messages within this record
                let mut handshake_offset = offset + 5;
                while handshake_offset + 4 <= offset + 5 + record_length {
                    if handshake_offset + 4 > raw_records.len() {
                        break;
                    }

                    let handshake_type = raw_records[handshake_offset];
                    let handshake_length = u32::from_be_bytes([
                        0,
                        raw_records[handshake_offset + 1],
                        raw_records[handshake_offset + 2],
                        raw_records[handshake_offset + 3],
                    ]) as usize;

                    if handshake_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                        // Found CertificateVerify message
                        // Extract signature scheme (2 bytes after message header)
                        if handshake_offset + 6 <= raw_records.len() {
                            let sig_scheme = u16::from_be_bytes([
                                raw_records[handshake_offset + 4],
                                raw_records[handshake_offset + 5],
                            ]);

                            // FIXED: Return codepoint (u16) instead of string
                            return Some(sig_scheme);
                        }
                    }

                    // Move to next handshake message
                    handshake_offset += 4 + handshake_length;
                    if handshake_offset > offset + 5 + record_length {
                        break;
                    }
                }
            }

            // Move to next TLS record
            if offset + 5 <= raw_records.len() {
                let record_length =
                    u16::from_be_bytes([raw_records[offset + 3], raw_records[offset + 4]]) as usize;
                offset += 5 + record_length;
            } else {
                break;
            }
        }

        None
    }

    // FIXED: Removed signature_scheme_to_name, is_pqc_signature_algorithm(&str), and extract_pqc_signature_algorithms
    // These are replaced by constants::get_signature_algorithm_name and constants::is_pqc_signature_algorithm(u16)
    // which work with codepoints directly, not string-based heuristics or profile-based assumptions

    // Note: Removed placeholder server-specific certificate info methods
    // Real certificate parsing should be used instead

    // FIXED: Removed should_attempt_tls_12_fallback - use config.always_attempt_tls12_fallback instead
    // Hostname-based detection is removed for production use

    // FIXED: Removed should_query_ct_logs - use config.always_query_ct_logs instead
    // Hostname-based detection is removed for production use
}
