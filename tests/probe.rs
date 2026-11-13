//! The prober against in-process rustls servers with known group sets.

mod support;

use quanta_seek::probe::ProbeOptions;
use quanta_seek::report::ProbeReport;
use quanta_seek::scan::{scan_target, ScanOptions};
use quanta_seek::types::HandshakeConfig;
use quanta_seek::HandshakeProfile;
use rustls::crypto::SupportedKxGroup;
use std::time::Duration;
use support::*;

async fn probe(
    groups: Vec<&'static dyn SupportedKxGroup>,
    budget: u32,
) -> (ProbeReport, TestServer) {
    init();
    let pki = TestPki::new("probe");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups,
        http_response: None,
    })
    .await;
    let opts = ScanOptions {
        connect_timeout: Duration::from_secs(2),
        handshake: HandshakeConfig {
            trust_anchors: Some(pki.roots()),
            timeout_ms: 2000,
        },
        probe: Some(ProbeOptions {
            max_probes: budget,
            spacing: Duration::ZERO,
            reply_timeout: Duration::from_secs(2),
        }),
        ..ScanOptions::default()
    };
    let report = scan_target(
        &opts,
        &format!("localhost:{}", server.port()),
        &HandshakeProfile::Default,
    )
    .await;
    assert!(!report.not_requested.contains(&"probe".to_string()));
    (report.probe.expect("probe section"), server)
}

fn result<'a>(p: &'a ProbeReport, group: &str) -> &'a str {
    p.groups
        .iter()
        .find(|g| g.group.name == group)
        .map(|g| g.result.as_str())
        .unwrap()
}

#[tokio::test]
async fn enumerates_exactly_the_server_groups() {
    let (p, _) = probe(vec![SECP256R1MLKEM768, MLKEM1024, X25519], 40).await;
    assert_eq!(p.provenance, "observed");
    assert_eq!(
        p.accepted_groups,
        vec!["x25519", "MLKEM1024", "SecP256r1MLKEM768"]
    );
    for g in ["secp256r1", "secp384r1", "X25519MLKEM768", "MLKEM768"] {
        assert_eq!(result(&p, g), "rejected", "{g}");
    }
    let rejected = p
        .groups
        .iter()
        .find(|g| g.group.name == "X25519MLKEM768")
        .unwrap();
    assert_eq!(rejected.alert.as_deref(), Some("handshake_failure"));
    // Groups without a key-share generator are listed, not silently skipped.
    let kyber = p
        .groups
        .iter()
        .find(|g| g.group.name == "X25519Kyber768Draft00")
        .unwrap();
    assert_eq!(kyber.result, "not_probed");
    assert!(kyber.detail.is_some());
}

#[tokio::test]
async fn hello_retry_and_downgrade_probes() {
    let (p, _) = probe(vec![X25519MLKEM768, X25519], 40).await;
    assert_eq!(p.accepted_groups, vec!["x25519", "X25519MLKEM768"]);
    // Listed without a key share: RFC 8446 §4.1.4 HelloRetryRequest.
    for h in &p.hello_retry {
        assert_eq!(h.result, "hello_retry_request", "{h:?}");
        assert_eq!(h.requested_group.as_deref(), Some(h.group.as_str()));
    }
    // Ground truth from the rustls 0.23.46 server source (server/hs.rs
    // choose_suite_and_kx_group; server/tls13.rs): the server picks the first
    // group in the client's supported_groups order that it supports, and
    // sends a HelloRetryRequest when no key share matches that group.
    let d = p.downgrade.expect("downgrade probe");
    assert_eq!(
        (d.pq_group.as_str(), d.classical_group.as_str()),
        ("X25519MLKEM768", "x25519")
    );
    assert_eq!(d.behaviour, "retried_for_pq_group");
    assert_eq!(d.reply_group.as_deref(), Some("X25519MLKEM768"));
    // Same rule: with both shares sent, the client's first listed group wins.
    assert_eq!(p.preference.len(), 2);
    for pref in &p.preference {
        assert_eq!(pref.result, "server_hello", "{pref:?}");
        assert_eq!(pref.selected.as_ref(), Some(&pref.offered[0]), "{pref:?}");
    }
    let t = p.client_hello_tolerance.expect("tolerance");
    assert_eq!(
        (
            t.baseline.as_str(),
            t.padded.as_str(),
            t.split_records.as_str()
        ),
        ("ok", "ok", "ok")
    );
}

#[tokio::test]
async fn budget_is_enforced() {
    let (p, server) = probe(vec![X25519], 3).await;
    assert_eq!(p.probes_sent, 3);
    assert!(p.budget_exhausted);
    assert!(p
        .groups
        .iter()
        .any(|g| g.detail.as_deref() == Some("probe budget exhausted")));
    // One handshake plus three probes.
    assert_eq!(server.connections(), 4);
}
