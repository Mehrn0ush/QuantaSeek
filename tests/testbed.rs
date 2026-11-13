//! Integration tests against the Docker testbed (`testbed/compose.yml`).
//!
//!   docker compose -f testbed/compose.yml up -d --build --wait
//!   cargo test --features testbed --test testbed
//!
//! Expected values come from each server's configuration in compose.yml and
//! were confirmed independently with `openssl s_client` (testbed/confirm.sh),
//! never by accepting what QuantaSeek printed.
//!
//! Tests named `m3_*` are `#[ignore]`d: they state what the M3 detection
//! engine must report for a server the scanner cannot see today. Their
//! companions without the prefix assert today's truthful output.
//!
//! If the testbed is not running, each test prints a message and returns,
//! unless QUANTASEEK_TESTBED_REQUIRED=1 (set in CI), which makes it fail.
#![cfg(feature = "testbed")]

use quanta_seek::report::ScanReport;
use quanta_seek::scan::{scan_target, ScanOptions};
use quanta_seek::types::{ErrorCategory, HandshakeConfig};
use quanta_seek::HandshakeProfile;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

struct Server {
    name: &'static str,
    port: u16,
}

const X25519MLKEM768: Server = Server {
    name: "x25519mlkem768",
    port: 44301,
};
const SECP256R1MLKEM768: Server = Server {
    name: "secp256r1mlkem768",
    port: 44302,
};
const SECP384R1MLKEM1024: Server = Server {
    name: "secp384r1mlkem1024",
    port: 44303,
};
const MLKEM1024: Server = Server {
    name: "mlkem1024",
    port: 44304,
};
const MLKEM512: Server = Server {
    name: "mlkem512",
    port: 44305,
};
const CLASSICAL: Server = Server {
    name: "classical",
    port: 44306,
};
const HRR_SECP384R1: Server = Server {
    name: "hrr-secp384r1",
    port: 44307,
};
const TLS12_CLASSICAL: Server = Server {
    name: "tls12-classical",
    port: 44308,
};
const CERT_MLDSA65: Server = Server {
    name: "cert-mldsa65",
    port: 44311,
};
const CERT_MLDSA65_INTERMEDIATE: Server = Server {
    name: "cert-mldsa65-intermediate",
    port: 44312,
};
const CERT_SLHDSA_CA: Server = Server {
    name: "cert-slhdsa-ca",
    port: 44313,
};
const CERT_EXPIRED: Server = Server {
    name: "cert-expired",
    port: 44314,
};
const CERT_MISMATCH: Server = Server {
    name: "cert-mismatch",
    port: 44315,
};
const CERT_SELF_SIGNED: Server = Server {
    name: "cert-self-signed",
    port: 44316,
};
const GO_X25519MLKEM768: Server = Server {
    name: "go-x25519mlkem768",
    port: 44321,
};

fn run_dir(server: &Server) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testbed/run")
        .join(server.name)
}

/// The server's exported CA, or None (with a message) if the testbed is down.
fn trust_anchors(server: &Server) -> Option<Arc<rustls::RootCertStore>> {
    let path = run_dir(server).join("ca.pem");
    let up = path.exists()
        && std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", server.port).parse().unwrap(),
            Duration::from_secs(1),
        )
        .is_ok();
    if !up {
        let msg = format!(
            "testbed server '{}' is not running (no {} or nothing on 127.0.0.1:{}); \
             start it with: docker compose -f testbed/compose.yml up -d --build --wait",
            server.name,
            path.display(),
            server.port
        );
        if std::env::var("QUANTASEEK_TESTBED_REQUIRED").as_deref() == Ok("1") {
            panic!("{msg}");
        }
        eprintln!("SKIPPED: {msg}");
        return None;
    }
    let mut store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&path).unwrap() {
        store.add(cert.unwrap()).unwrap();
    }
    Some(Arc::new(store))
}

/// SHA-256 (hex) of each certificate the server is configured to send.
fn served_chain_sha256(server: &Server) -> Vec<String> {
    CertificateDer::pem_file_iter(run_dir(server).join("chain.pem"))
        .unwrap()
        .map(|c| {
            let der = c.unwrap();
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der.as_ref())
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .collect()
}

async fn scan(server: &Server, profile: HandshakeProfile) -> Option<ScanReport> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let anchors = trust_anchors(server)?;
    let opts = ScanOptions {
        connect_timeout: Duration::from_secs(3),
        handshake: HandshakeConfig {
            trust_anchors: Some(anchors),
            timeout_ms: 5000,
        },
        ..ScanOptions::default()
    };
    Some(scan_target(&opts, &format!("localhost:{}", server.port), &profile).await)
}

fn group(r: &ScanReport) -> (&str, &str, &str) {
    let g = r
        .tls
        .as_ref()
        .expect("tls")
        .key_exchange
        .as_ref()
        .expect("group");
    (g.name.as_str(), g.kind.as_str(), g.status.as_str())
}

fn assert_derived(r: &ScanReport, kex: &str, chain: &str, sig: &str) {
    let p = r.pqc.as_ref().expect("pqc");
    for d in [
        &p.key_exchange,
        &p.certificate_chain,
        &p.handshake_signature,
    ] {
        assert_eq!(d.provenance, "derived");
        assert!(!d.basis.is_empty());
    }
    assert_eq!(
        (
            p.key_exchange.value.as_str(),
            p.certificate_chain.value.as_str(),
            p.handshake_signature.value.as_str()
        ),
        (kex, chain, sig)
    );
}

fn assert_server_result(r: &ScanReport, code: &str) -> String {
    assert!(!r.completed());
    assert!(r.tls.is_none() && r.certificate_chain.is_empty() && r.pqc.is_none());
    let e = r.outcome.error.as_ref().expect("error");
    assert_eq!(
        (e.code.as_str(), e.category),
        (code, ErrorCategory::ServerResult),
        "{e:?}"
    );
    e.message.clone()
}

fn assert_rejected_no_shared_group(r: &ScanReport) {
    assert_server_result(r, "handshake_rejected");
    let e = r.outcome.error.as_ref().unwrap();
    assert_eq!(e.alert.as_deref(), Some("HandshakeFailure"));
    assert_eq!(e.interpretation.as_ref().unwrap().provenance, "inferred");
}

/// Leaf is the ECDSA P-256 certificate issued by the server's ECDSA root,
/// and the server signed the handshake with `scheme`.
fn assert_ecdsa_leaf_with(r: &ScanReport, server: &Server, scheme: &str) {
    let leaf = &r.certificate_chain[0];
    assert_eq!(leaf.public_key.name, "ECDSA");
    assert_eq!(leaf.public_key.size_bits, Some(256));
    assert_eq!(leaf.signature.name, "ECDSA-SHA256");
    assert_eq!(leaf.signature.family, "classical");
    let sha: Vec<String> = r
        .certificate_chain
        .iter()
        .map(|c| c.sha256.clone())
        .collect();
    assert_eq!(sha, served_chain_sha256(server));
    assert_eq!(
        r.tls
            .as_ref()
            .unwrap()
            .server_signature_scheme
            .as_ref()
            .unwrap()
            .name,
        scheme
    );
}

fn assert_ecdsa_leaf(r: &ScanReport, server: &Server) {
    // TLS 1.3: ecdsa_secp256r1_sha256 is the only scheme for a P-256 key.
    assert_ecdsa_leaf_with(r, server, "ecdsa_secp256r1_sha256");
}

// ---------------------------------------------------------------- key exchange

#[tokio::test]
async fn x25519mlkem768_server() {
    let Some(r) = scan(&X25519MLKEM768, HandshakeProfile::Default).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("X25519MLKEM768", "hybrid", "standard"));
    assert!(!r.tls.as_ref().unwrap().hello_retry_request);
    assert_ecdsa_leaf(&r, &X25519MLKEM768);
    assert_derived(&r, "hybrid", "classical", "classical");

    let Some(r) = scan(&X25519MLKEM768, HandshakeProfile::Classical).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);
}

#[tokio::test]
async fn secp256r1mlkem768_server() {
    // The default profile does not offer SecP256r1MLKEM768.
    let Some(r) = scan(&SECP256R1MLKEM768, HandshakeProfile::Default).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);

    // The hybrid profile offers it second, after a X25519MLKEM768 key share,
    // so the server answers with a HelloRetryRequest.
    let Some(r) = scan(&SECP256R1MLKEM768, HandshakeProfile::Hybrid).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("SecP256r1MLKEM768", "hybrid", "standard"));
    assert!(r.tls.as_ref().unwrap().hello_retry_request);
    assert_eq!(r.evidence.server_hellos_hex.len(), 2);
    assert_ecdsa_leaf(&r, &SECP256R1MLKEM768);
    assert_derived(&r, "hybrid", "classical", "classical");
}

#[tokio::test]
async fn secp384r1mlkem1024_server_is_invisible_today() {
    // rustls 0.23.46 cannot offer SecP384r1MLKEM1024.
    let Some(r) = scan(&SECP384R1MLKEM1024, HandshakeProfile::All).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);
}

#[tokio::test]
#[ignore = "M3: needs the per-group prober; rustls cannot offer SecP384r1MLKEM1024"]
async fn m3_secp384r1mlkem1024_server_group_is_reported() {
    let Some(r) = scan(&SECP384R1MLKEM1024, HandshakeProfile::All).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("SecP384r1MLKEM1024", "hybrid", "standard"));
}

#[tokio::test]
async fn mlkem1024_server() {
    let Some(r) = scan(&MLKEM1024, HandshakeProfile::Mlkem).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("MLKEM1024", "pure_pq", "draft"));
    assert!(!r.tls.as_ref().unwrap().hello_retry_request); // MLKEM1024 is the first share
    assert_ecdsa_leaf(&r, &MLKEM1024);
    assert_derived(&r, "pure_pq", "classical", "classical");

    let Some(r) = scan(&MLKEM1024, HandshakeProfile::Default).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);
}

#[tokio::test]
async fn mlkem512_server_is_invisible_today() {
    let Some(r) = scan(&MLKEM512, HandshakeProfile::All).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);
}

#[tokio::test]
#[ignore = "M3: needs the per-group prober; rustls cannot offer MLKEM512"]
async fn m3_mlkem512_server_group_is_reported() {
    let Some(r) = scan(&MLKEM512, HandshakeProfile::All).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("MLKEM512", "pure_pq", "draft"));
}

#[tokio::test]
async fn classical_server() {
    for profile in [HandshakeProfile::Classical, HandshakeProfile::Default] {
        let Some(r) = scan(&CLASSICAL, profile).await else {
            return;
        };
        assert!(r.completed(), "{profile:?}: {:?}", r.outcome.error);
        assert_eq!(
            group(&r),
            ("x25519", "classical", "standard"),
            "{profile:?}"
        );
        assert_eq!(r.tls.as_ref().unwrap().version, "1.3");
        assert_ecdsa_leaf(&r, &CLASSICAL);
        assert_derived(&r, "classical", "classical", "classical");
    }
    for profile in [HandshakeProfile::Hybrid, HandshakeProfile::Mlkem] {
        let Some(r) = scan(&CLASSICAL, profile).await else {
            return;
        };
        assert_rejected_no_shared_group(&r);
    }
}

#[tokio::test]
async fn hello_retry_request_server() {
    let Some(r) = scan(&HRR_SECP384R1, HandshakeProfile::Default).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("secp384r1", "classical", "standard"));
    assert!(r.tls.as_ref().unwrap().hello_retry_request);
    assert_eq!(r.evidence.server_hellos_hex.len(), 2);
    assert_derived(&r, "classical", "classical", "classical");
}

#[tokio::test]
async fn tls12_server() {
    let Some(r) = scan(&TLS12_CLASSICAL, HandshakeProfile::Classical).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    let tls = r.tls.as_ref().unwrap();
    assert_eq!(tls.version, "1.2");
    assert_eq!(group(&r), ("x25519", "classical", "standard"));
    assert!(
        tls.cipher_suite.name.starts_with("TLS_ECDHE_ECDSA_WITH_"),
        "{}",
        tls.cipher_suite.name
    );
    // TLS 1.2 ServerKeyExchange: rustls offers ECDSA+SHA-384 first, and the
    // P-256 key signs with it (confirm.sh, rustls-ordered -sigalgs check).
    assert_ecdsa_leaf_with(&r, &TLS12_CLASSICAL, "ecdsa_secp384r1_sha384");
    assert_derived(&r, "classical", "classical", "classical");

    // A TLS 1.3-only profile against a TLS 1.2-only server: protocol_version alert.
    let Some(r) = scan(&TLS12_CLASSICAL, HandshakeProfile::Hybrid).await else {
        return;
    };
    assert_server_result(&r, "handshake_rejected");
    assert_eq!(
        r.outcome.error.as_ref().unwrap().alert.as_deref(),
        Some("ProtocolVersion")
    );
}

// ---------------------------------------------------------------- certificates

#[tokio::test]
async fn mldsa65_chain_server() {
    let Some(r) = scan(&CERT_MLDSA65, HandshakeProfile::Default).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    let leaf = &r.certificate_chain[0];
    assert_eq!(leaf.subject, "CN=QuantaSeek testbed leaf (mldsa65)");
    assert_eq!(leaf.issuer, "CN=QuantaSeek testbed root (mldsa65)");
    assert_eq!(
        (
            leaf.public_key.name.as_str(),
            leaf.public_key.family.as_str()
        ),
        ("id-ml-dsa-65", "ml_dsa")
    );
    assert_eq!(leaf.public_key.oid, "2.16.840.1.101.3.4.3.18");
    assert_eq!(
        (leaf.signature.name.as_str(), leaf.signature.family.as_str()),
        ("id-ml-dsa-65", "ml_dsa")
    );
    let sig = r
        .tls
        .as_ref()
        .unwrap()
        .server_signature_scheme
        .as_ref()
        .unwrap();
    assert_eq!(
        (sig.name.as_str(), sig.post_quantum),
        ("mldsa65", Some(true))
    );
    let sha: Vec<String> = r
        .certificate_chain
        .iter()
        .map(|c| c.sha256.clone())
        .collect();
    assert_eq!(sha, served_chain_sha256(&CERT_MLDSA65));
    assert_derived(&r, "hybrid", "post_quantum", "post_quantum");
}

#[tokio::test]
async fn mldsa65_intermediate_server() {
    let Some(r) = scan(&CERT_MLDSA65_INTERMEDIATE, HandshakeProfile::Default).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(r.certificate_chain.len(), 2);
    let (leaf, inter) = (&r.certificate_chain[0], &r.certificate_chain[1]);
    assert_eq!(leaf.public_key.name, "ECDSA");
    assert_eq!(
        (leaf.signature.name.as_str(), leaf.signature.family.as_str()),
        ("id-ml-dsa-65", "ml_dsa")
    );
    assert_eq!(inter.subject, "CN=QuantaSeek testbed inter (mldsa65)");
    assert_eq!(
        (
            inter.public_key.name.as_str(),
            inter.public_key.family.as_str()
        ),
        ("id-ml-dsa-65", "ml_dsa")
    );
    assert_eq!(
        (
            inter.signature.name.as_str(),
            inter.signature.family.as_str()
        ),
        ("ECDSA-SHA256", "classical")
    );
    let sha: Vec<String> = r
        .certificate_chain
        .iter()
        .map(|c| c.sha256.clone())
        .collect();
    assert_eq!(sha, served_chain_sha256(&CERT_MLDSA65_INTERMEDIATE));
    assert_derived(&r, "hybrid", "mixed", "classical");
}

#[tokio::test]
async fn slhdsa_signed_chain_is_rejected_today() {
    // rustls-webpki 0.103 cannot verify SLH-DSA signatures; OpenSSL verifies
    // this chain (confirm.sh), so the rejection is a scanner limitation.
    let Some(r) = scan(&CERT_SLHDSA_CA, HandshakeProfile::Default).await else {
        return;
    };
    assert_server_result(&r, "certificate_rejected");
}

#[tokio::test]
#[ignore = "M3: chain must be reported even when webpki cannot verify it (SLH-DSA)"]
async fn m3_slhdsa_signed_chain_is_reported() {
    let Some(r) = scan(&CERT_SLHDSA_CA, HandshakeProfile::Default).await else {
        return;
    };
    let leaf = r.certificate_chain.first().expect("chain reported");
    assert_eq!(leaf.signature.name, "id-slh-dsa-sha2-128s");
    assert_eq!(leaf.signature.family, "slh_dsa");
}

#[tokio::test]
async fn invalid_certificates_are_rejected_today() {
    for (server, reason) in [
        (&CERT_EXPIRED, "certificate expired"),
        (&CERT_MISMATCH, "not valid for name"),
        (&CERT_SELF_SIGNED, "UnknownIssuer"),
    ] {
        let Some(r) = scan(server, HandshakeProfile::Default).await else {
            return;
        };
        let message = assert_server_result(&r, "certificate_rejected");
        assert!(message.contains(reason), "{}: {message}", server.name);
    }
}

#[tokio::test]
#[ignore = "M3: chains that fail validation must still be reported, marked not validated"]
async fn m3_invalid_certificates_are_reported() {
    for server in [&CERT_EXPIRED, &CERT_MISMATCH, &CERT_SELF_SIGNED] {
        let Some(r) = scan(server, HandshakeProfile::Default).await else {
            return;
        };
        let sha: Vec<String> = r
            .certificate_chain
            .iter()
            .map(|c| c.sha256.clone())
            .collect();
        assert_eq!(sha, served_chain_sha256(server), "{}", server.name);
    }
}

// ---------------------------------------------------------------- second implementation

#[tokio::test]
async fn go_x25519mlkem768_server() {
    let Some(r) = scan(&GO_X25519MLKEM768, HandshakeProfile::Default).await else {
        return;
    };
    assert!(r.completed(), "{:?}", r.outcome.error);
    assert_eq!(group(&r), ("X25519MLKEM768", "hybrid", "standard"));
    assert_ecdsa_leaf(&r, &GO_X25519MLKEM768);
    assert_derived(&r, "hybrid", "classical", "classical");

    let Some(r) = scan(&GO_X25519MLKEM768, HandshakeProfile::Classical).await else {
        return;
    };
    assert_rejected_no_shared_group(&r);
}
