//! One TLS handshake through rustls, recording what was observed.
//!
//! The engine drives a `rustls::ClientConnection` over a blocking socket so
//! that every record the server sends can be kept as evidence. Everything in
//! [`Observation`] comes from that handshake; nothing is defaulted.

use crate::types::{HandshakeConfig, HandshakeProfile};
use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Root store built from the Mozilla-derived `webpki-roots` bundle.
pub fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// ServerHello.random value that marks a HelloRetryRequest (RFC 8446 §4.1.3):
/// SHA-256("HelloRetryRequest").
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// What one completed handshake showed.
#[derive(Debug, Clone)]
pub struct Observation {
    /// "1.3" or "1.2", as negotiated.
    pub tls_version: Option<String>,
    /// Negotiated cipher suite codepoint.
    pub cipher_suite: Option<u16>,
    /// Negotiated key-exchange group codepoint, as rustls used it.
    pub negotiated_group: Option<u16>,
    /// The server sent a HelloRetryRequest before its ServerHello.
    pub hello_retry_request: bool,
    /// Scheme of the server's handshake signature: CertificateVerify in
    /// TLS 1.3, ServerKeyExchange in TLS 1.2.
    pub server_signature_scheme: Option<u16>,
    /// Certificates the server sent, leaf first, as sent.
    pub peer_chain: Vec<CertificateDer<'static>>,
    /// Every plaintext ServerHello / HelloRetryRequest handshake message received.
    pub server_hellos: Vec<Vec<u8>>,
    pub duration: Duration,
}

/// Verifier that delegates to WebPKI and records the server's signature scheme.
#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    scheme: Arc<Mutex<Option<SignatureScheme>>>,
}

impl CapturingVerifier {
    fn record(&self, scheme: SignatureScheme) {
        if let Ok(mut slot) = self.scheme.lock() {
            *slot = Some(scheme);
        }
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
        self.record(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss.scheme);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

type CapturedScheme = Arc<Mutex<Option<SignatureScheme>>>;

pub struct HandshakeEngine {
    profile: HandshakeProfile,
    config: HandshakeConfig,
}

impl HandshakeEngine {
    pub fn new(profile: HandshakeProfile) -> Self {
        Self::with_config(profile, HandshakeConfig::default())
    }

    pub fn with_config(profile: HandshakeProfile, config: HandshakeConfig) -> Self {
        Self { profile, config }
    }

    fn root_store(&self) -> RootCertStore {
        match &self.config.trust_anchors {
            Some(store) => (**store).clone(),
            None => webpki_root_store(),
        }
    }

    /// The ClientConfig for this profile, plus the slot the verifier writes into.
    fn client_config(&self) -> Result<(Arc<ClientConfig>, CapturedScheme)> {
        use rustls::crypto::aws_lc_rs::default_provider;
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: self.profile.kx_groups(),
            ..default_provider()
        });
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.profile.tls13_only() {
            &[&rustls::version::TLS13]
        } else {
            rustls::DEFAULT_VERSIONS
        };
        let roots = Arc::new(self.root_store());
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.clone(),
            provider.clone(),
        )
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build certificate verifier: {}", e))?;
        let scheme: CapturedScheme = Arc::new(Mutex::new(None));
        let verifier = Arc::new(CapturingVerifier {
            inner: webpki,
            scheme: scheme.clone(),
        });

        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| anyhow::anyhow!("invalid TLS configuration for profile: {}", e))?
            .with_root_certificates((*roots).clone())
            .with_no_client_auth();
        config.dangerous().set_certificate_verifier(verifier);
        Ok((Arc::new(config), scheme))
    }

    /// Complete one handshake over `stream`, sending `server_name` as SNI and
    /// validating the certificate against it.
    pub async fn perform_handshake(
        &self,
        stream: TcpStream,
        server_name: &str,
    ) -> Result<Observation> {
        let (config, scheme) = self.client_config()?;
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| anyhow::anyhow!("invalid server name '{}'", server_name))?;
        let std_stream = stream.into_std()?;
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let start = Instant::now();

        let (client, records) =
            tokio::task::spawn_blocking(move || drive(config, name, std_stream, timeout)).await??;

        let captured = scheme.lock().ok().and_then(|s| *s);
        let server_hellos = server_hello_messages(&records);
        Ok(Observation {
            tls_version: match client.protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3".to_string()),
                Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2".to_string()),
                _ => None,
            },
            cipher_suite: client
                .negotiated_cipher_suite()
                .map(|cs| u16::from(cs.suite())),
            negotiated_group: client
                .negotiated_key_exchange_group()
                .map(|g| u16::from(g.name())),
            hello_retry_request: server_hellos
                .first()
                .is_some_and(|m| is_hello_retry_request(m)),
            server_signature_scheme: captured.map(u16::from),
            peer_chain: client
                .peer_certificates()
                .map(|c| c.iter().map(|d| d.clone().into_owned()).collect())
                .unwrap_or_default(),
            server_hellos,
            duration: start.elapsed(),
        })
    }
}

/// Blocking handshake loop. Returns the connection and every byte received.
fn drive(
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    mut stream: std::net::TcpStream,
    timeout: Duration,
) -> Result<(ClientConnection, Vec<u8>)> {
    let mut client = ClientConnection::new(config, name)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut received = Vec::new();
    let mut buf = [0u8; 16384];
    while client.is_handshaking() {
        while client.wants_write() {
            if client.write_tls(&mut stream)? == 0 {
                break;
            }
        }
        if client.wants_read() {
            let n = match stream.read(&mut buf) {
                Ok(0) => {
                    // rustls may have read a fatal alert in the last record.
                    client.process_new_packets()?;
                    return Err(anyhow::Error::new(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed during handshake",
                    )));
                }
                Ok(n) => n,
                // Keep the io::Error as the source so timeouts stay classifiable.
                Err(e) => return Err(anyhow::Error::new(e).context("failed to read from stream")),
            };
            received.extend_from_slice(&buf[..n]);
            // read_tls consumes at most 4096 bytes per call (rustls
            // deframer READ_SIZE); feed the whole read, processing as we go.
            let mut pending = &buf[..n];
            while !pending.is_empty() {
                if client.read_tls(&mut pending)? == 0 {
                    break;
                }
                client.process_new_packets()?;
            }
        }
    }
    // rustls considers the handshake done once it has queued the client
    // Finished; send it, or the server never completes the handshake.
    while client.wants_write() {
        if client.write_tls(&mut stream)? == 0 {
            break;
        }
    }
    let _ = stream.flush();
    Ok((client, received))
}

/// ServerHello (type 2) handshake messages in plaintext handshake records.
/// Stops at the first record that is not a handshake record, since in
/// TLS 1.3 everything after the ServerHello is encrypted.
pub fn server_hello_messages(records: &[u8]) -> Vec<Vec<u8>> {
    const HANDSHAKE: u8 = crate::constants::TLS_CONTENT_TYPE_HANDSHAKE;
    const CHANGE_CIPHER_SPEC: u8 = crate::constants::TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 5 <= records.len() {
        let content_type = records[offset];
        let len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        let end = offset + 5 + len;
        if end > records.len() {
            break;
        }
        match content_type {
            HANDSHAKE => {
                let body = &records[offset + 5..end];
                let mut pos = 0;
                while pos + 4 <= body.len() {
                    let msg_len =
                        u32::from_be_bytes([0, body[pos + 1], body[pos + 2], body[pos + 3]])
                            as usize;
                    let msg_end = pos + 4 + msg_len;
                    if msg_end > body.len() {
                        break;
                    }
                    if body[pos] == 2 {
                        out.push(body[pos..msg_end].to_vec());
                    }
                    pos = msg_end;
                }
            }
            // TLS 1.3 middlebox-compatibility CCS sits between the HRR and the
            // second ServerHello; skip it.
            CHANGE_CIPHER_SPEC => {}
            _ => break,
        }
        offset = end;
    }
    out
}

/// True if a ServerHello message carries the HelloRetryRequest random.
pub fn is_hello_retry_request(server_hello: &[u8]) -> bool {
    // type(1) length(3) legacy_version(2) random(32)
    server_hello.len() >= 38 && server_hello[6..38] == HELLO_RETRY_REQUEST_RANDOM
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![content_type, 0x03, 0x03];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    fn server_hello(random: [u8; 32]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&random);
        body.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 0]);
        let mut msg = vec![2, 0, 0, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn finds_hrr_then_server_hello_across_ccs() {
        let mut records = record(22, &server_hello(HELLO_RETRY_REQUEST_RANDOM));
        records.extend(record(20, &[1]));
        records.extend(record(22, &server_hello([7; 32])));
        records.extend(record(23, &[0xAA; 10])); // encrypted, stops parsing
        let hellos = server_hello_messages(&records);
        assert_eq!(hellos.len(), 2);
        assert!(is_hello_retry_request(&hellos[0]));
        assert!(!is_hello_retry_request(&hellos[1]));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let full = record(22, &server_hello([1; 32]));
        for cut in 0..full.len() {
            let _ = server_hello_messages(&full[..cut]);
        }
    }
}
