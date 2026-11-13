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

fn scan_options(pki: &TestPki) -> quanta_seek::scan::ScanOptions {
    quanta_seek::scan::ScanOptions {
        connect_timeout: std::time::Duration::from_secs(2),
        handshake: config_trusting(pki),
        ..Default::default()
    }
}

#[tokio::test]
async fn scans_the_port_named_in_the_target() {
    init();
    let pki = TestPki::new("port");
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: None,
    })
    .await;

    let target = format!("localhost:{}", server.port());
    let result = quanta_seek::scan::scan_target(
        &scan_options(&pki),
        &target,
        &quanta_seek::types::ClientProfile::Fallback,
        false,
    )
    .await
    .unwrap();

    assert!(result.handshake_complete, "error: {:?}", result.error);
    assert_eq!(result.key_exchange, vec!["X25519MLKEM768".to_string()]);
    assert!(!server.accepted_at_least(1).await.is_empty());
}

#[test]
fn target_parsing() {
    use quanta_seek::scan::Target;
    let t = |s: &str| Target::parse(s).unwrap();
    assert_eq!(
        t("example.com"),
        Target {
            host: "example.com".into(),
            port: None
        }
    );
    assert_eq!(
        t("example.com:8443"),
        Target {
            host: "example.com".into(),
            port: Some(8443)
        }
    );
    assert_eq!(
        t("[::1]:4433"),
        Target {
            host: "::1".into(),
            port: Some(4433)
        }
    );
    assert_eq!(
        t("[2001:db8::1]"),
        Target {
            host: "2001:db8::1".into(),
            port: None
        }
    );
    assert_eq!(
        t("2001:db8::1"),
        Target {
            host: "2001:db8::1".into(),
            port: None
        }
    );
    assert!(Target::parse("example.com:0").is_err());
    assert!(Target::parse("example.com:http").is_err());
    assert!(Target::parse(":443").is_err());
    assert!(Target::parse("[::1").is_err());
}
