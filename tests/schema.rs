//! Output schema v0: committed schema matches the code, real outputs
//! validate against it, and golden outputs stay stable.

mod support;

use quanta_seek::report::{json_schema, ScanReport};
use quanta_seek::scan::{scan_target, ScanOptions};
use quanta_seek::types::HandshakeConfig;
use quanta_seek::HandshakeProfile;
use serde_json::Value;
use std::time::Duration;
use support::*;

const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/scan-result.v0.json");

fn options(pki: &TestPki) -> ScanOptions {
    ScanOptions {
        connect_timeout: Duration::from_secs(2),
        handshake: HandshakeConfig {
            trust_anchors: Some(pki.roots()),
            timeout_ms: 1500,
        },
        ..ScanOptions::default()
    }
}

#[test]
fn committed_schema_matches_generated() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_PATH).unwrap()).unwrap();
    assert_eq!(
        committed,
        json_schema(),
        "schema/scan-result.v0.json is stale: run `quantaseek --print-schema > schema/scan-result.v0.json`"
    );
}

/// Replace values that change on every run (keys, times, ports, tool version).
fn normalise(mut v: Value) -> Value {
    const VOLATILE: &[&str] = &[
        "started_at",
        "duration_ms",
        "handshake_ms",
        "serial_hex",
        "sha256",
        "not_before",
        "not_after",
        "address",
        "port",
        "input",
        "server_hellos_hex",
        "details",
        "message",
        "tool.version",
    ];
    fn walk(v: &mut Value, path: &str, key: &str) {
        match v {
            Value::Object(map) => {
                for (k, child) in map.iter_mut() {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    walk(child, &p, k);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk(child, path, key);
                }
            }
            _ => {
                if (VOLATILE.contains(&key) || VOLATILE.contains(&path)) && !v.is_null() {
                    *v = Value::String("<volatile>".into());
                }
            }
        }
    }
    walk(&mut v, "", "");
    v
}

fn check_golden(name: &str, report: &ScanReport) {
    let path = format!("{}/tests/golden/{}.json", env!("CARGO_MANIFEST_DIR"), name);
    let actual = normalise(serde_json::to_value(report).unwrap());
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap() + "\n").unwrap();
    }
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing {path}; run with UPDATE_GOLDEN=1")),
    )
    .unwrap();
    assert_eq!(actual, expected, "golden mismatch for {name}");
}

#[tokio::test]
async fn outputs_validate_and_match_golden_files() {
    init();
    let validator = jsonschema::validator_for(&json_schema()).unwrap();
    let pki = TestPki::new("schema");
    let hybrid = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519MLKEM768, X25519],
        http_response: None,
    })
    .await;
    let classical = spawn(ServerSpec {
        identity: pki.leaf("localhost", &["localhost"]),
        groups: vec![X25519],
        http_response: None,
    })
    .await;

    let cases = [
        (
            "completed_hybrid",
            scan_target(
                &options(&pki),
                &format!("localhost:{}", hybrid.port()),
                &HandshakeProfile::Default,
            )
            .await,
        ),
        (
            "rejected_no_shared_group",
            scan_target(
                &options(&pki),
                &format!("localhost:{}", classical.port()),
                &HandshakeProfile::Mlkem,
            )
            .await,
        ),
        (
            "invalid_target",
            scan_target(
                &options(&pki),
                "example.com:notaport",
                &HandshakeProfile::Default,
            )
            .await,
        ),
        (
            "refused",
            scan_target(
                &options(&pki),
                &format!("127.0.0.1:{}", closed_port().await),
                &HandshakeProfile::Classical,
            )
            .await,
        ),
    ];

    for (name, report) in &cases {
        let value = serde_json::to_value(report).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{name} does not validate: {errors:?}");
        assert_eq!(value["schema_version"], "0");
        check_golden(name, report);
    }
}
