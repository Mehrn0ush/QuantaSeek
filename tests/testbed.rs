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
//! companions without the prefix assert today's truthful output. When M3
//! delivers a capability, its `m3_*` test is folded into the companion.
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

const HYBRID_AND_CLASSICAL: Server = Server {
    name: "hybrid-and-classical",
    port: 44309,
};
const MIDDLEBOX_1024: Server = Server {
    name: "middlebox-1024",
    port: 44331,
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
    scan_with(server, profile, None).await
}

/// Scan with `--probe` (20 ms spacing to keep the suite fast).
async fn probe(server: &Server) -> Option<quanta_seek::report::ProbeReport> {
    let opts = quanta_seek::probe::ProbeOptions {
        spacing: Duration::from_millis(20),
        ..Default::default()
    };
    let r = scan_with(server, HandshakeProfile::Default, Some(opts)).await?;
    Some(r.probe.expect("probe section"))
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// Accepted sets confirmed by confirm.sh (`expect_set`), sorted.
fn set(items: &[&str]) -> Vec<String> {
    sorted(&items.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

async fn scan_with(
    server: &Server,
    profile: HandshakeProfile,
    probe: Option<quanta_seek::probe::ProbeOptions>,
) -> Option<ScanReport> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let anchors = trust_anchors(server)?;
    let opts = ScanOptions {
        connect_timeout: Duration::from_secs(3),
        handshake: HandshakeConfig {
            trust_anchors: Some(anchors),
            timeout_ms: 5000,
        },
        probe,
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
    assert!(r.tls.is_none());
    let e = r.outcome.error.as_ref().expect("error");
    assert_eq!(
        (e.code.as_str(), e.category),
        (code, ErrorCategory::ServerResult),
        "{e:?}"
    );
    e.message.clone()
}

/// The handshake was refused before any certificate was presented.
fn assert_no_certificates(r: &ScanReport) {
    assert!(r.certificate_chain.is_empty() && r.pqc.is_none());
    assert_eq!(r.certificate_validation.status, "not_reached");
}

/// The chain was presented and rejected; it is still reported as sent.
fn assert_rejected_chain_reported(r: &ScanReport, server: &Server) {
    assert_server_result(r, "certificate_rejected");
    assert_eq!(r.certificate_validation.status, "invalid");
    assert!(r.certificate_validation.reason.is_some());
    let sha: Vec<String> = r
        .certificate_chain
        .iter()
        .map(|c| c.sha256.clone())
        .collect();
    assert_eq!(sha, served_chain_sha256(server), "{}", server.name);
    let p = r.pqc.as_ref().expect("pqc derived from the chain");
    assert_eq!(p.key_exchange.value, "unknown");
}

fn assert_rejected_no_shared_group(r: &ScanReport) {
    assert_server_result(r, "handshake_rejected");
    assert_no_certificates(r);
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
async fn secp384r1mlkem1024_server_found_by_probe() {
    // Was m3_secp384r1mlkem1024_server_group_is_reported. That test asked for
    // a completed rustls handshake on a group rustls cannot offer; the M3
    // capability is the prober reporting the group, which this asserts.
    let Some(p) = probe(&SECP384R1MLKEM1024).await else {
        return;
    };
    assert_eq!(sorted(&p.accepted_groups), set(&["SecP384r1MLKEM1024"]));
    let g = p
        .groups
        .iter()
        .find(|g| g.group.name == "SecP384r1MLKEM1024")
        .unwrap();
    assert_eq!(g.result, "accepted");
    assert_eq!(p.provenance, "observed");
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
async fn mlkem512_server_found_by_probe() {
    // Was m3_mlkem512_server_group_is_reported (see above).
    let Some(p) = probe(&MLKEM512).await else {
        return;
    };
    assert_eq!(sorted(&p.accepted_groups), set(&["MLKEM512"]));
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
async fn slhdsa_signed_chain_is_rejected_but_reported() {
    // rustls-webpki 0.103 cannot verify SLH-DSA signatures; OpenSSL verifies
    // this chain (confirm.sh), so the rejection is a scanner limitation.
    // The chain is still reported as presented.
    let Some(r) = scan(&CERT_SLHDSA_CA, HandshakeProfile::Default).await else {
        return;
    };
    assert_rejected_chain_reported(&r, &CERT_SLHDSA_CA);
    let leaf = &r.certificate_chain[0];
    assert_eq!(leaf.signature.name, "id-slh-dsa-sha2-128s");
    assert_eq!(leaf.signature.family, "slh_dsa");
    assert_eq!(leaf.public_key.name, "ECDSA");
    assert_eq!(
        r.pqc.as_ref().unwrap().certificate_chain.value,
        "post_quantum"
    );
}

#[tokio::test]
async fn invalid_certificates_are_rejected_but_reported() {
    for (server, reason) in [
        (&CERT_EXPIRED, "certificate expired"),
        (&CERT_MISMATCH, "not valid for name"),
        (&CERT_SELF_SIGNED, "UnknownIssuer"),
    ] {
        let Some(r) = scan(server, HandshakeProfile::Default).await else {
            return;
        };
        assert_rejected_chain_reported(&r, server);
        let why = r.certificate_validation.reason.as_deref().unwrap();
        assert!(why.contains(reason), "{}: {why}", server.name);
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

// ---------------------------------------------------------------- prober

#[tokio::test]
async fn probe_accepted_sets_match_openssl() {
    // Every expected set is an `expect_set` line in confirm.sh.
    for (server, expected) in [
        (&X25519MLKEM768, set(&["X25519MLKEM768"])),
        (&SECP256R1MLKEM768, set(&["SecP256r1MLKEM768"])),
        (&MLKEM1024, set(&["MLKEM1024"])),
        (&CLASSICAL, set(&["x25519", "secp256r1"])),
        (&HRR_SECP384R1, set(&["secp384r1"])),
        (&HYBRID_AND_CLASSICAL, set(&["x25519", "X25519MLKEM768"])),
        (&GO_X25519MLKEM768, set(&["X25519MLKEM768"])),
    ] {
        let Some(p) = probe(server).await else { return };
        assert_eq!(sorted(&p.accepted_groups), expected, "{}", server.name);
        assert!(!p.budget_exhausted, "{}", server.name);
    }
}

#[tokio::test]
async fn probe_preference_and_downgrade_on_openssl() {
    let Some(p) = probe(&HYBRID_AND_CLASSICAL).await else {
        return;
    };
    // confirm.sh: with both shares, OpenSSL 3.5.9 follows the client's order.
    assert_eq!(p.preference.len(), 2);
    for pref in &p.preference {
        assert_eq!(pref.selected.as_ref(), Some(&pref.offered[0]), "{pref:?}");
    }
    // confirm.sh: PQ listed without a share, x25519 share sent -> OpenSSL
    // accepts x25519 with one ServerHello (no HRR).
    let d = p.downgrade.expect("downgrade");
    assert_eq!(d.behaviour, "accepted_classical_share");
    assert_eq!(d.reply_group.as_deref(), Some("x25519"));
    // RFC 8446 §4.1.4: a supported group listed without a key share gets a
    // HelloRetryRequest for that group. (confirm.sh shows OpenSSL's HRR when
    // the share is for an unsupported group; a zero-share ClientHello cannot
    // be sent with s_client.)
    for h in &p.hello_retry {
        assert_eq!(h.result, "hello_retry_request", "{h:?}");
        assert_eq!(h.requested_group.as_deref(), Some(h.group.as_str()));
    }
}

#[tokio::test]
async fn probe_sees_tls12_only_server_refuse_tls13() {
    // confirm.sh: a TLS 1.3 offer gets a protocol_version alert.
    let Some(p) = probe(&TLS12_CLASSICAL).await else {
        return;
    };
    assert!(p.accepted_groups.is_empty());
    let x = p.groups.iter().find(|g| g.group.name == "x25519").unwrap();
    assert_eq!(
        (x.result.as_str(), x.alert.as_deref()),
        ("rejected", Some("protocol_version"))
    );
}

#[tokio::test]
async fn probe_detects_client_hello_size_intolerance() {
    // Ground truth by construction (testbed/go/main.go middlebox closes when
    // the first record exceeds 1024 bytes) and confirm.sh (a small
    // ClientHello passes, an X25519MLKEM768 one gets no ServerHello).
    let Some(p) = probe(&MIDDLEBOX_1024).await else {
        return;
    };
    assert_eq!(p.accepted_groups, vec!["x25519".to_string()]);
    let pq = p
        .groups
        .iter()
        .find(|g| g.group.name == "X25519MLKEM768")
        .unwrap();
    assert_eq!(
        pq.result, "closed",
        "large key share closed by the middlebox"
    );
    let t = p.client_hello_tolerance.expect("tolerance");
    assert_eq!(t.baseline, "ok");
    assert_eq!(t.padded, "closed");
    assert_eq!(
        t.split_records, "ok",
        "512-byte records pass the first-record check"
    );
    // The proxy reads the 5-byte record header with ReadFull, so a record
    // split across TCP segments is judged by its (small) length: passes.
    assert_eq!(t.split_segments, "ok");
}

// ---------------------------------------------------------------- findings

fn finding_ids(r: &ScanReport) -> Vec<String> {
    r.assessment
        .as_ref()
        .unwrap()
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect()
}

fn not_evaluated_ids(r: &ScanReport) -> Vec<String> {
    r.assessment
        .as_ref()
        .unwrap()
        .not_evaluated
        .iter()
        .map(|n| n.id.clone())
        .collect()
}

fn has(r: &ScanReport, id: &str) -> bool {
    finding_ids(r).iter().any(|f| f == id)
}

async fn probed(server: &Server) -> Option<ScanReport> {
    let opts = quanta_seek::probe::ProbeOptions {
        spacing: Duration::from_millis(20),
        ..Default::default()
    };
    scan_with(server, HandshakeProfile::Default, Some(opts)).await
}

/// Positive and negative testbed fixture per rule. Expected values follow
/// from each server's configuration and confirm.sh, not from scanner output.
#[tokio::test]
async fn rules_on_testbed_fixtures() {
    let Some(pq) = scan(&X25519MLKEM768, HandshakeProfile::Default).await else {
        return;
    };
    let Some(classical) = scan(&CLASSICAL, HandshakeProfile::Default).await else {
        return;
    };
    let Some(tls12) = scan(&TLS12_CLASSICAL, HandshakeProfile::Classical).await else {
        return;
    };
    let Some(mlkem1024) = scan(&MLKEM1024, HandshakeProfile::Mlkem).await else {
        return;
    };
    let Some(mldsa) = scan(&CERT_MLDSA65, HandshakeProfile::Default).await else {
        return;
    };
    let Some(expired) = scan(&CERT_EXPIRED, HandshakeProfile::Default).await else {
        return;
    };
    let Some(slhdsa) = scan(&CERT_SLHDSA_CA, HandshakeProfile::Default).await else {
        return;
    };
    let Some(hybrid_probe) = probed(&HYBRID_AND_CLASSICAL).await else {
        return;
    };
    let Some(classical_probe) = probed(&CLASSICAL).await else {
        return;
    };
    let Some(middlebox_probe) = probed(&MIDDLEBOX_1024).await else {
        return;
    };

    // QS-TLS-001: TLS 1.2 negotiated.
    assert!(has(&tls12, "QS-TLS-001"));
    assert!(!has(&pq, "QS-TLS-001"));
    // QS-KEX-001: classical key exchange negotiated.
    assert!(has(&classical, "QS-KEX-001"));
    assert!(!has(&pq, "QS-KEX-001"));
    // QS-KEX-002: OpenSSL accepts the classical share (confirm.sh). The
    // negative case (rustls retries for the PQ group) is in tests/probe.rs.
    assert!(has(&hybrid_probe, "QS-KEX-002"));
    assert!(not_evaluated_ids(&pq).contains(&"QS-KEX-002".to_string()));
    // QS-KEX-004: no PQ group accepted by the prober.
    assert!(has(&classical_probe, "QS-KEX-004"));
    assert!(!has(&hybrid_probe, "QS-KEX-004"));
    // QS-KEX-005: padded ClientHello dropped by the middlebox.
    assert!(has(&middlebox_probe, "QS-KEX-005"));
    assert!(!has(&classical_probe, "QS-KEX-005"));
    // QS-KEX-010: not ML-KEM-1024.
    assert!(has(&pq, "QS-KEX-010"));
    assert!(!has(&mlkem1024, "QS-KEX-010"));
    // QS-CERT-001 / QS-CERT-002: classical chain and handshake signature.
    assert!(has(&pq, "QS-CERT-001") && has(&pq, "QS-CERT-002"));
    assert!(!has(&mldsa, "QS-CERT-001") && !has(&mldsa, "QS-CERT-002"));
    // QS-CERT-003: no HashML-DSA fixture can be built (testbed/README.md);
    // negative only here, positive in src/findings/rules.rs.
    assert!(!has(&mldsa, "QS-CERT-003"));
    // QS-CERT-004: invalid chain; not evaluated where webpki cannot verify.
    assert!(has(&expired, "QS-CERT-004"));
    assert!(!has(&pq, "QS-CERT-004"));
    assert!(!has(&slhdsa, "QS-CERT-004"));
    assert!(not_evaluated_ids(&slhdsa).contains(&"QS-CERT-004".to_string()));

    // Every finding is derived from observed fields.
    for r in [
        &pq,
        &classical,
        &tls12,
        &expired,
        &hybrid_probe,
        &middlebox_probe,
    ] {
        for f in &r.assessment.as_ref().unwrap().findings {
            assert_eq!(f.provenance, "derived");
            assert!(!f.evidence.is_empty(), "{}", f.id);
            assert!(!f.references.is_empty(), "{}", f.id);
        }
    }
}

#[tokio::test]
async fn nist_policy_applies_its_clauses() {
    let policy = quanta_seek::findings::policy("nist-ir-8547").unwrap();
    let Some(anchors) = trust_anchors(&CLASSICAL) else {
        return;
    };
    let opts = ScanOptions {
        connect_timeout: Duration::from_secs(3),
        handshake: HandshakeConfig {
            trust_anchors: Some(anchors),
            timeout_ms: 5000,
        },
        policy: Some(policy),
        ..ScanOptions::default()
    };
    let r = scan_target(
        &opts,
        &format!("localhost:{}", CLASSICAL.port),
        &HandshakeProfile::Default,
    )
    .await;
    let a = r.assessment.as_ref().unwrap();
    assert_eq!(a.policy.as_ref().unwrap().id, "nist-ir-8547");
    let kex = a
        .findings
        .iter()
        .find(|f| f.id == "QS-KEX-001")
        .expect("QS-KEX-001");
    let clause = kex.policy.as_ref().unwrap();
    assert_eq!(clause.clause, "4.1.2, Table 4");
    assert!(clause.deadline.as_deref().unwrap().contains("2035"));
    // QS-KEX-010 is not part of the NIST pack (NIST recommends ML-KEM-768).
    assert!(a.findings.iter().all(|f| f.id != "QS-KEX-010"));
}
