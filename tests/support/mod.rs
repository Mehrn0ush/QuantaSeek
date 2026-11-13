//! In-process TLS test servers with known configurations.
//!
//! Every test server listens on 127.0.0.1 with an ephemeral port, uses a
//! certificate from a per-test CA, and offers only the key-exchange groups the
//! test asks for. Nothing here touches the network beyond loopback.

#![allow(dead_code, unused_imports)]

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub use kx_group::{
    MLKEM1024, MLKEM768, SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519, X25519MLKEM768,
};

/// A throwaway CA that issues leaf certificates.
pub struct TestPki {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestPki {
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{name} Test CA"));
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { issuer }
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// Root store containing only this CA.
    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut store = RootCertStore::empty();
        store.add(self.ca_der()).unwrap();
        Arc::new(store)
    }

    /// Leaf certificate for `sans` (DNS names or IP literals) with common name `cn`.
    pub fn leaf(&self, cn: &str, sans: &[&str]) -> Identity {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Identity {
            chain: vec![cert.der().clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }
}

pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// What a test server offers and how it answers after the handshake.
pub struct ServerSpec {
    pub identity: Identity,
    pub groups: Vec<&'static dyn SupportedKxGroup>,
    /// Raw HTTP response written after the first request, if any.
    pub http_response: Option<String>,
}

/// Facts the server records about each accepted handshake.
#[derive(Debug, Clone, Default)]
pub struct Accepted {
    pub sni: Option<String>,
    pub group: Option<u16>,
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub accepted: Arc<Mutex<Vec<Accepted>>>,
    /// TCP connections accepted, whether or not the handshake succeeded.
    pub connections: Arc<Mutex<usize>>,
}

impl TestServer {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Handshakes the server completed, waiting briefly for at least `n`.
    pub async fn accepted_at_least(&self, n: usize) -> Vec<Accepted> {
        for _ in 0..100 {
            let got = self.accepted.lock().unwrap().clone();
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.accepted.lock().unwrap().clone()
    }

    pub fn accepted(&self) -> Vec<Accepted> {
        self.accepted.lock().unwrap().clone()
    }

    pub fn connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }
}

pub async fn spawn(spec: ServerSpec) -> TestServer {
    let provider = CryptoProvider {
        kx_groups: spec.groups,
        ..aws_lc_rs::default_provider()
    };
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(spec.identity.chain, spec.identity.key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(Mutex::new(0usize));
    let http_response = spec.http_response;

    let (acc, conns) = (accepted.clone(), connections.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            *conns.lock().unwrap() += 1;
            let acceptor = acceptor.clone();
            let acc = acc.clone();
            let http_response = http_response.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                {
                    let conn = tls.get_ref().1;
                    acc.lock().unwrap().push(Accepted {
                        sni: conn.server_name().map(str::to_string),
                        group: conn
                            .negotiated_key_exchange_group()
                            .map(|g| u16::from(g.name())),
                    });
                }
                let mut buf = vec![0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        if let Some(resp) = &http_response {
                            let _ = tls.write_all(resp.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                        return;
                    }
                }
            });
        }
    });

    TestServer {
        addr,
        accepted,
        connections,
    }
}

/// Install the process-wide rustls provider the scanner expects.
pub fn init() {
    let _ = aws_lc_rs::default_provider().install_default();
}

/// A server that accepts TCP connections and never sends anything.
pub async fn spawn_silent() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    addr
}

/// A loopback port with nothing listening on it.
pub async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}
