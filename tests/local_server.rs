//! Deterministic tests against in-process TLS servers. No public network.

mod support;

use quanta_seek::types::HandshakeConfig;
use quanta_seek::{HandshakeEngine, HandshakeProfile};
use support::*;

fn config_trusting(pki: &TestPki) -> HandshakeConfig {
    HandshakeConfig {
        trust_anchors: Some(pki.roots()),
        timeout_ms: 2000,
        ..HandshakeConfig::default()
    }
}

#[tokio::test]
async fn handshake_engine_reports_negotiated_hybrid_group() {
    init();
    let pki = TestPki::new("engine");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: None,
    })
    .await;

    let engine =
        HandshakeEngine::with_config(HandshakeProfile::CloudflarePqc, config_trusting(&pki));
    let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let result = engine.perform_handshake(stream, "localhost").await.unwrap();

    assert_eq!(result.tls_version, "1.3");
    assert_eq!(result.key_exchange, vec!["X25519MLKEM768".to_string()]);
    let accepted = server.accepted_at_least(1).await;
    assert_eq!(accepted[0].group, Some(4588));
    assert_eq!(accepted[0].sni.as_deref(), Some("localhost"));
}
