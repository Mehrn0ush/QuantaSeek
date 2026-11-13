//! Profiles change what the ClientHello offers; failures are classified.

mod support;

use quanta_seek::scan::{scan_target, ScanOptions};
use quanta_seek::types::{ErrorCategory, HandshakeConfig, ScanResult};
use quanta_seek::HandshakeProfile;
use rustls::crypto::SupportedKxGroup;
use std::time::Duration;
use support::*;

fn options(pki: &TestPki) -> ScanOptions {
    ScanOptions {
        connect_timeout: Duration::from_secs(2),
        handshake: HandshakeConfig {
            trust_anchors: Some(pki.roots()),
            timeout_ms: 1500,
            ..HandshakeConfig::default()
        },
        ..ScanOptions::default()
    }
}

async fn scan_server(
    groups: Vec<&'static dyn SupportedKxGroup>,
    profile: HandshakeProfile,
) -> (ScanResult, TestServer) {
    init();
    let pki = TestPki::new("profiles");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups,
        http_response: None,
    })
    .await;
    let target = format!("localhost:{}", server.port());
    let result = scan_target(&options(&pki), &target, &profile)
        .await
        .unwrap();
    (result, server)
}

#[tokio::test]
async fn classical_profile_offers_no_pq_group() {
    let (result, server) =
        scan_server(vec![X25519MLKEM768, X25519], HandshakeProfile::Classical).await;
    assert!(result.handshake_complete, "{:?}", result.error);
    assert_eq!(result.key_exchange, vec!["x25519".to_string()]);
    assert!(!result.pqc_detected);
    assert_eq!(server.accepted_at_least(1).await[0].group, Some(0x001d));
}

#[tokio::test]
async fn default_profile_prefers_x25519mlkem768() {
    let (result, _) = scan_server(vec![X25519MLKEM768, X25519], HandshakeProfile::Default).await;
    assert_eq!(result.key_exchange, vec!["X25519MLKEM768".to_string()]);
    assert!(result.pqc_detected);
}

#[tokio::test]
async fn hybrid_profile_reaches_secp256r1mlkem768() {
    let (result, server) = scan_server(vec![SECP256R1MLKEM768], HandshakeProfile::Hybrid).await;
    assert!(result.handshake_complete, "{:?}", result.error);
    assert_eq!(result.key_exchange, vec!["SecP256r1MLKEM768".to_string()]);
    assert_eq!(server.accepted_at_least(1).await[0].group, Some(4587));
}

#[tokio::test]
async fn mlkem_profile_negotiates_pure_mlkem() {
    let (result, _) = scan_server(vec![MLKEM1024, X25519], HandshakeProfile::Mlkem).await;
    assert_eq!(result.key_exchange, vec!["MLKEM1024".to_string()]);
    let (result, _) = scan_server(vec![MLKEM768], HandshakeProfile::Mlkem).await;
    assert_eq!(result.key_exchange, vec!["MLKEM768".to_string()]);
    assert_eq!(result.tls_version, "1.3");
}

#[tokio::test]
async fn profile_with_no_shared_group_is_a_server_result() {
    let (result, _) = scan_server(vec![X25519, SECP256R1], HandshakeProfile::Mlkem).await;
    assert!(!result.handshake_complete);
    let error = result.error.expect("outcome");
    assert_eq!(error.code, "handshake_rejected");
    assert_eq!(error.category, ErrorCategory::ServerResult);
    assert_eq!(error.alert.as_deref(), Some("HandshakeFailure"));
    let inference = error.interpretation.expect("inference");
    assert_eq!(inference.provenance, "inferred");
    assert!(inference.statement.contains("MLKEM1024, MLKEM768"));
}

#[tokio::test]
async fn untrusted_certificate_is_a_server_result() {
    init();
    let pki = TestPki::new("served");
    let other = TestPki::new("trusted");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519],
        http_response: None,
    })
    .await;
    let target = format!("localhost:{}", server.port());
    let result = scan_target(&options(&other), &target, &HandshakeProfile::Default)
        .await
        .unwrap();
    let error = result.error.expect("outcome");
    assert_eq!(error.code, "certificate_rejected");
    assert_eq!(error.category, ErrorCategory::ServerResult);
}

#[tokio::test]
async fn silent_server_is_a_timeout_not_a_server_result() {
    init();
    let pki = TestPki::new("silent");
    let addr = spawn_silent().await;
    let target = format!("127.0.0.1:{}", addr.port());
    let result = scan_target(&options(&pki), &target, &HandshakeProfile::Default)
        .await
        .unwrap();
    let error = result.error.expect("outcome");
    assert_eq!(error.code, "handshake_timeout");
    assert_eq!(error.category, ErrorCategory::Network);
}

#[tokio::test]
async fn refused_connection_is_a_network_failure() {
    init();
    let pki = TestPki::new("refused");
    let target = format!("127.0.0.1:{}", closed_port().await);
    let result = scan_target(&options(&pki), &target, &HandshakeProfile::Default)
        .await
        .unwrap();
    let error = result.error.expect("outcome");
    assert_eq!(error.code, "connection_refused");
    assert_eq!(error.category, ErrorCategory::Network);
}

#[test]
fn profiles_only_use_groups_rustls_implements() {
    let all: Vec<u16> = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
        .iter()
        .map(|g| u16::from(g.name()))
        .collect();
    for profile in HandshakeProfile::ALL_PROFILES {
        for g in profile.kx_groups() {
            assert!(all.contains(&u16::from(g.name())), "{:?}", profile);
        }
    }
    assert!(HandshakeProfile::Mlkem.tls13_only());
    assert!(HandshakeProfile::Hybrid.tls13_only());
    assert!(!HandshakeProfile::Classical.tls13_only());
    assert!("standard".parse::<HandshakeProfile>().is_err());
}
