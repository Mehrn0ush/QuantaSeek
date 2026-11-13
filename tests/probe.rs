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
    probe_with(
        groups,
        ProbeOptions {
            max_probes: budget,
            spacing: Duration::ZERO,
            reply_timeout: Duration::from_secs(2),
        },
    )
    .await
}

async fn probe_with(
    groups: Vec<&'static dyn SupportedKxGroup>,
    probe_opts: ProbeOptions,
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
        probe: Some(probe_opts),
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
    // Only x25519 is a classical candidate on this server: one case.
    assert_eq!(p.downgrade.len(), 1);
    let d = &p.downgrade[0];
    assert_eq!(d.offered, vec!["X25519MLKEM768", "x25519"]);
    assert_eq!(d.key_share, "x25519");
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

#[tokio::test]
async fn default_spacing_is_at_least_100ms_with_jitter() {
    let defaults = ProbeOptions::default();
    assert_eq!(defaults.max_probes, 40);
    assert!(defaults.spacing >= Duration::from_millis(100));
    let (p, server) = probe_with(
        vec![X25519],
        ProbeOptions {
            max_probes: 5,
            ..ProbeOptions::default()
        },
    )
    .await;
    assert_eq!(p.probes_sent, 5);
    assert_eq!(p.spacing_ms, 100);
    let times = server.accept_times.lock().unwrap().clone();
    assert_eq!(times.len(), 6); // one handshake + five probes
    for pair in times[1..].windows(2) {
        let gap = pair[1] - pair[0];
        // spacing plus jitter of at most half of it (small scheduling slack).
        assert!(gap >= Duration::from_millis(100), "{gap:?}");
        assert!(gap < Duration::from_millis(400), "{gap:?}");
    }
}

#[tokio::test]
async fn probing_aborts_after_repeated_connect_failures() {
    init();
    let scan = ScanOptions {
        connect_timeout: Duration::from_secs(1),
        ..ScanOptions::default()
    };
    let opts = ProbeOptions {
        spacing: Duration::ZERO,
        ..ProbeOptions::default()
    };
    let port = closed_port().await;
    let p = quanta_seek::probe::probe(&scan, &opts, "127.0.0.1", port, "localhost").await;
    assert!(p.aborted);
    assert_eq!(
        p.probes_sent,
        quanta_seek::probe::ABORT_AFTER_CONNECT_FAILURES
    );
    assert!(p.accepted_groups.is_empty());
    let skipped = p
        .groups
        .iter()
        .filter(|g| {
            g.detail.as_deref() == Some("probing aborted after repeated connection failures")
        })
        .count();
    assert!(skipped > 0);
}

#[tokio::test]
async fn qs_kex_002_passes_when_server_retries_for_pq() {
    // Negative fixture for QS-KEX-002: rustls retries for the PQ group
    // (see hello_retry_and_downgrade_probes for the source reference).
    init();
    let pki = TestPki::new("kex002");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519MLKEM768, X25519],
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
            spacing: Duration::ZERO,
            ..ProbeOptions::default()
        }),
        ..ScanOptions::default()
    };
    let r = scan_target(
        &opts,
        &format!("localhost:{}", server.port()),
        &HandshakeProfile::Default,
    )
    .await;
    let a = r.assessment.unwrap();
    assert!(a.findings.iter().all(|f| f.id != "QS-KEX-002"));
    assert!(a.not_evaluated.iter().all(|n| n.id != "QS-KEX-002"));
}

/// A server accepting three classical groups and two hybrids: the case where
/// "first accepted groups in registry order" picks only classical ones.
async fn many_groups(budget: u32) -> (ProbeReport, TestServer) {
    probe(
        vec![
            SECP256R1,
            SECP384R1,
            X25519,
            SECP256R1MLKEM768,
            X25519MLKEM768,
        ],
        budget,
    )
    .await
}

#[tokio::test]
async fn preference_pairs_every_pq_group_with_x25519() {
    let (p, _) = many_groups(40).await;
    assert_eq!(
        sorted_names(&p.accepted_groups),
        sorted_names(&[
            "secp256r1",
            "secp384r1",
            "x25519",
            "SecP256r1MLKEM768",
            "X25519MLKEM768"
        ])
    );
    for pq in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
        for order in [[pq, "x25519"], ["x25519", pq]] {
            assert!(
                p.preference.iter().any(|x| x.offered == order),
                "missing preference probe {order:?}; got {:?}",
                p.preference.iter().map(|x| &x.offered).collect::<Vec<_>>()
            );
        }
    }
}

#[tokio::test]
async fn hello_retry_covers_every_accepted_pq_group() {
    let (p, _) = many_groups(40).await;
    let groups: Vec<&str> = p.hello_retry.iter().map(|h| h.group.as_str()).collect();
    for pq in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
        assert!(groups.contains(&pq), "{groups:?}");
    }
}

#[tokio::test]
async fn tolerance_uses_x25519_like_real_clients() {
    let (p, _) = many_groups(40).await;
    assert_eq!(p.client_hello_tolerance.expect("tolerance").group, "x25519");
}

fn sorted_names<S: AsRef<str>>(v: &[S]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|s| s.as_ref().to_string()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn downgrade_runs_x25519_then_secp256r1_with_every_pq_group() {
    let (p, _) = many_groups(40).await;
    let cases: Vec<(&str, Vec<String>)> = p
        .downgrade
        .iter()
        .map(|d| (d.key_share.as_str(), d.offered.clone()))
        .collect();
    let pq_then = |c: &str| {
        vec![
            "SecP256r1MLKEM768".to_string(),
            "X25519MLKEM768".to_string(),
            c.to_string(),
        ]
    };
    assert_eq!(
        cases,
        vec![
            ("x25519", pq_then("x25519")),
            ("secp256r1", pq_then("secp256r1"))
        ]
    );
    // rustls retries for the first listed group (a PQ group) in both cases.
    assert!(p
        .downgrade
        .iter()
        .all(|d| d.behaviour == "retried_for_pq_group"));
    // secp384r1 is accepted but is not a classical candidate.
    assert!(p
        .preference
        .iter()
        .all(|x| !x.offered.contains(&"secp384r1".to_string())));
    assert!(!p.budget_exhausted);
    assert!(p.probes_sent <= 40);
}

#[tokio::test]
async fn budget_skips_lowest_priority_probes_and_rules_say_not_evaluated() {
    // 10 enumeration probes + 1 downgrade + 4 tolerance + 2 HRR = 17.
    // With 17 the PQ-vs-x25519 preference pairs and the secp256r1 downgrade
    // case are skipped, and reported as not_probed.
    let (p, _) = many_groups(17).await;
    assert!(p.budget_exhausted);
    assert_eq!(p.probes_sent, 17);
    assert_eq!(p.downgrade[0].behaviour, "retried_for_pq_group");
    assert_eq!(p.downgrade[1].key_share, "secp256r1");
    assert_eq!(p.downgrade[1].behaviour, "not_probed");
    assert_eq!(
        p.downgrade[1].detail.as_deref(),
        Some("probe budget exhausted")
    );
    assert!(!p.preference.is_empty());
    assert!(p.preference.iter().all(|x| x.result == "not_probed"));
    assert_eq!(p.client_hello_tolerance.as_ref().unwrap().baseline, "ok");

    // QS-KEX-002 is not evaluated (one case skipped), not passed.
    let mut report = report_with(p);
    report.assessment = Some(quanta_seek::findings::assess(&report, None));
    let a = report.assessment.unwrap();
    let ne = a
        .not_evaluated
        .iter()
        .find(|n| n.id == "QS-KEX-002")
        .expect("not evaluated");
    assert!(
        ne.reason.contains("secp256r1 share: not_probed"),
        "{}",
        ne.reason
    );
    assert!(a.findings.iter().all(|f| f.id != "QS-KEX-002"));
}

/// A minimal completed report carrying `probe`, for rule evaluation.
fn report_with(probe: ProbeReport) -> quanta_seek::report::ScanReport {
    let obs = quanta_seek::Observation {
        tls_version: Some("1.3".into()),
        cipher_suite: Some(0x1301),
        negotiated_group: Some(4588),
        hello_retry_request: false,
        server_signature_scheme: Some(0x0403),
        peer_chain: vec![],
        server_hellos: vec![],
        duration: Duration::ZERO,
    };
    let ctx = quanta_seek::report::ReportContext {
        input: "t".into(),
        host: Some("t".into()),
        port: Some(443),
        server_name: Some("t".into()),
        address: None,
        profile: HandshakeProfile::Default,
        custom_trust_store: true,
        redirects_requested: false,
        started_at: chrono::Utc::now(),
        duration: Duration::ZERO,
    };
    quanta_seek::report::ScanReport::build(ctx, Some(&obs), None, None, None, Some(probe))
}
