//! Deterministic tests against in-process TLS servers. No public network.

mod support;

use quanta_seek::report::ScanReport;
use quanta_seek::types::HandshakeConfig;
use quanta_seek::{HandshakeEngine, HandshakeProfile};
use support::*;

fn config_trusting(pki: &TestPki) -> HandshakeConfig {
    HandshakeConfig {
        trust_anchors: Some(pki.roots()),
        timeout_ms: 2000,
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

    let engine = HandshakeEngine::with_config(HandshakeProfile::Default, config_trusting(&pki));
    let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let result = engine.perform_handshake(stream, "localhost").await.unwrap();

    assert_eq!(result.tls_version.as_deref(), Some("1.3"));
    assert_eq!(result.negotiated_group, Some(4588));
    let accepted = server.accepted_at_least(1).await;
    assert_eq!(accepted[0].group, Some(4588));
    assert_eq!(accepted[0].sni.as_deref(), Some("localhost"));
}

fn group(report: &ScanReport) -> String {
    report
        .tls
        .as_ref()
        .unwrap()
        .key_exchange
        .as_ref()
        .unwrap()
        .name
        .clone()
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
    let result =
        quanta_seek::scan::scan_target(&scan_options(&pki), &target, &HandshakeProfile::Default)
            .await;

    assert!(result.completed(), "error: {:?}", result.outcome.error);
    assert_eq!(group(&result), "X25519MLKEM768");
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
    // Found by fuzzing (fuzz/fuzz_targets/target_parse.rs): an empty
    // bracketed host was accepted.
    assert!(Target::parse("[]").is_err());
    assert!(Target::parse("[]:443").is_err());
    // Brackets and bare multi-colon forms must hold an IPv6 literal.
    assert!(Target::parse("[example.com]:443").is_err());
    assert!(Target::parse("a:b:c").is_err());
}

#[tokio::test]
async fn sni_override_is_sent_and_validated() {
    init();
    let pki = TestPki::new("sni");
    let server = spawn(ServerSpec {
        identity: pki.leaf("qs.test", &["qs.test"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: None,
    })
    .await;
    let target = format!("127.0.0.1:{}", server.port());
    let profile = HandshakeProfile::Default;

    let opts = quanta_seek::scan::ScanOptions {
        sni: Some("qs.test".into()),
        ..scan_options(&pki)
    };
    let result = quanta_seek::scan::scan_target(&opts, &target, &profile).await;
    assert!(result.completed(), "error: {:?}", result.outcome.error);
    assert_eq!(
        server.accepted_at_least(1).await[0].sni.as_deref(),
        Some("qs.test")
    );

    // Without the override the name is the IP literal, which the certificate
    // does not cover, so validation fails and no handshake completes.
    let result = quanta_seek::scan::scan_target(&scan_options(&pki), &target, &profile).await;
    assert!(!result.completed());
    // A handshake that fails after TCP connects must still report an error.
    assert!(result.outcome.error.is_some());
}

async fn redirect_pair(pki: &TestPki) -> (TestServer, TestServer) {
    let destination = spawn(ServerSpec {
        identity: pki.leaf("redirect-destination", &["127.0.0.1"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: Some(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        ),
    })
    .await;
    let origin = spawn(ServerSpec {
        identity: pki.leaf("redirect-origin", &["127.0.0.1"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: Some(format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://127.0.0.1:{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            destination.port()
        )),
    })
    .await;
    (origin, destination)
}

#[tokio::test]
async fn redirects_are_not_followed_by_default() {
    init();
    let pki = TestPki::new("redirect-off");
    let (origin, destination) = redirect_pair(&pki).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let result =
        quanta_seek::scan::scan_target(&scan_options(&pki), &target, &HandshakeProfile::Default)
            .await;
    assert!(result.completed(), "error: {:?}", result.outcome.error);
    assert!(result.http_redirect.is_none());
    assert_eq!(result.certificate_chain[0].subject, "CN=redirect-origin");
    assert_eq!(destination.connections(), 0);
}

#[tokio::test]
async fn followed_redirect_never_replaces_target_certificate() {
    init();
    let pki = TestPki::new("redirect-on");
    let (origin, _destination) = redirect_pair(&pki).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let opts = quanta_seek::scan::ScanOptions {
        follow_redirects: true,
        ..scan_options(&pki)
    };
    let result = quanta_seek::scan::scan_target(&opts, &target, &HandshakeProfile::Default).await;
    assert!(result.completed(), "error: {:?}", result.outcome.error);
    // The target's own certificate is reported...
    assert_eq!(result.certificate_chain[0].subject, "CN=redirect-origin");
    // ...and the destination's certificate is reported separately.
    let redirect = result.http_redirect.expect("redirect info");
    assert!(redirect.detected);
    assert_eq!(redirect.status_code, Some(301));
    assert_eq!(
        redirect.final_destination_certificate.unwrap().subject,
        "CN=redirect-destination"
    );
}

#[tokio::test]
async fn hostname_substrings_do_not_change_behaviour() {
    // These names used to trigger the fake QUIC path, extra ports, TLS 1.2
    // auto-enable and scoring leniency. Now they are just names.
    init();
    for name in ["s2n-quic.oqstest.net", "pq-demo-test.duckdns.org"] {
        let pki = TestPki::new("names");
        let server = spawn(ServerSpec {
            identity: pki.leaf(name, &[name]),
            groups: vec![X25519MLKEM768, X25519],
            http_response: None,
        })
        .await;
        let opts = quanta_seek::scan::ScanOptions {
            connect_to: Some(server.addr),
            ..scan_options(&pki)
        };
        let result = quanta_seek::scan::scan_target(
            &opts,
            &format!("{name}:443"),
            &HandshakeProfile::Default,
        )
        .await;
        assert!(result.completed(), "{name}: {:?}", result.outcome.error);
        assert!(result.not_implemented.contains(&"quic".to_string()));
        assert_eq!(
            server.accepted_at_least(1).await[0].sni.as_deref(),
            Some(name)
        );
        // One connection, one handshake: no retries, no extra ports.
        assert_eq!(server.connections(), 1);
    }
}

#[tokio::test]
async fn large_server_flight_is_read_completely() {
    // rustls consumes at most 4096 bytes per read_tls call; a server flight
    // larger than that arriving in one socket read must not be truncated.
    init();
    let pki = TestPki::new("large");
    let names: Vec<String> = (0..400)
        .map(|i| format!("host-{i:03}.large.test"))
        .collect();
    let mut sans: Vec<&str> = vec!["localhost"];
    sans.extend(names.iter().map(String::as_str));
    let server = spawn(ServerSpec {
        identity: pki.leaf("localhost", &sans),
        groups: vec![X25519MLKEM768, X25519],
        http_response: None,
    })
    .await;
    let target = format!("localhost:{}", server.port());
    let result =
        quanta_seek::scan::scan_target(&scan_options(&pki), &target, &HandshakeProfile::Default)
            .await;
    assert!(result.completed(), "error: {:?}", result.outcome.error);
    assert_eq!(result.certificate_chain[0].san_dns.len(), 401);
}
