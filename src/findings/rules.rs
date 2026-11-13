//! Rule logic. Each rule reads observed report fields and returns a finding
//! with the fields it used as evidence, a pass, or "not evaluated" with the
//! reason. Metadata for each id is in `rules/rules.toml`.

use super::Evidence;
use crate::constants::{self, GroupKind};
use crate::report::ScanReport;

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Finding(Vec<Evidence>),
    Pass,
    NotEvaluated(String),
}

use Outcome::{Finding, NotEvaluated, Pass};

fn ne(reason: &str) -> Outcome {
    NotEvaluated(reason.to_string())
}

const NO_HANDSHAKE: &str = "the handshake did not complete";
const NO_PROBE: &str = "--probe was not requested";

/// Signature families webpki 0.103 cannot verify: a chain using them is
/// "invalid" to the validator whether or not it is correctly signed.
const UNVERIFIABLE_FAMILIES: &[&str] =
    &["slh_dsa", "hash_slh_dsa", "composite_ml_dsa", "hash_ml_dsa"];

fn is_pq_group_name(name: &str) -> bool {
    constants::named_group_by_name(name).is_some_and(|g| g.kind != GroupKind::Classical)
}

/// Evaluate rule `id` against `report`.
pub fn evaluate(id: &str, report: &ScanReport) -> Outcome {
    match id {
        "QS-TLS-001" => match &report.tls {
            None => ne(NO_HANDSHAKE),
            Some(tls) if tls.version == "1.2" => Finding(vec![Evidence::new("tls.version", "1.2")]),
            Some(_) => Pass,
        },

        "QS-KEX-001" => {
            let Some(tls) = &report.tls else {
                return ne(NO_HANDSHAKE);
            };
            match &tls.key_exchange {
                None => ne("the TLS stack reported no negotiated group"),
                Some(g) if g.kind == "classical" => Finding(vec![
                    Evidence::new("tls.key_exchange.name", &g.name),
                    Evidence::new("tls.key_exchange.kind", &g.kind),
                ]),
                Some(g) if g.kind == "unregistered" => NotEvaluated(format!(
                    "negotiated group 0x{:04x} is not in the registry",
                    g.code
                )),
                Some(_) => Pass,
            }
        }

        "QS-KEX-002" => {
            let Some(probe) = &report.probe else {
                return ne(NO_PROBE);
            };
            let Some(d) = &probe.downgrade else {
                return ne("needs both an accepted post-quantum and an accepted classical group");
            };
            match d.behaviour.as_str() {
                "accepted_classical_share" => Finding(vec![
                    Evidence::new("probe.downgrade.behaviour", &d.behaviour),
                    Evidence::new("probe.downgrade.pq_group", &d.pq_group),
                    Evidence::new("probe.downgrade.classical_group", &d.classical_group),
                ]),
                "retried_for_pq_group" => Pass,
                _ => NotEvaluated(format!(
                    "downgrade probe was inconclusive (result {})",
                    d.result
                )),
            }
        }

        "QS-KEX-004" => {
            let Some(probe) = &report.probe else {
                return ne(NO_PROBE);
            };
            if probe.aborted {
                return ne("probing aborted after repeated connection failures");
            }
            if probe.accepted_groups.is_empty() {
                return ne("the server accepted none of the probed groups");
            }
            if probe.accepted_groups.iter().any(|g| is_pq_group_name(g)) {
                Pass
            } else {
                Finding(vec![Evidence::new(
                    "probe.accepted_groups",
                    probe.accepted_groups.join(", "),
                )])
            }
        }

        "QS-KEX-005" => {
            let Some(probe) = &report.probe else {
                return ne(NO_PROBE);
            };
            let Some(t) = &probe.client_hello_tolerance else {
                return ne("no accepted group to build the tolerance probes from");
            };
            if t.baseline != "ok" {
                return NotEvaluated(format!(
                    "the baseline ClientHello itself failed ({})",
                    t.baseline
                ));
            }
            if t.padded == "ok" {
                return Pass;
            }
            let mut evidence = vec![
                Evidence::new("probe.client_hello_tolerance.baseline", &t.baseline),
                Evidence::new("probe.client_hello_tolerance.padded", &t.padded),
                Evidence::new(
                    "probe.client_hello_tolerance.padded_bytes",
                    t.padded_bytes.to_string(),
                ),
            ];
            for g in &probe.groups {
                if is_pq_group_name(&g.group.name)
                    && matches!(g.result.as_str(), "closed" | "timeout")
                {
                    evidence.push(Evidence::new(
                        format!("probe.groups[{}].result", g.group.name),
                        &g.result,
                    ));
                }
            }
            Finding(evidence)
        }

        "QS-KEX-010" => {
            let Some(tls) = &report.tls else {
                return ne(NO_HANDSHAKE);
            };
            let Some(g) = &tls.key_exchange else {
                return ne("the TLS stack reported no negotiated group");
            };
            if g.pq_kem.as_deref() == Some("ML-KEM-1024") {
                Pass
            } else {
                Finding(vec![
                    Evidence::new("tls.key_exchange.name", &g.name),
                    Evidence::new(
                        "tls.key_exchange.pq_kem",
                        g.pq_kem.as_deref().unwrap_or("none"),
                    ),
                ])
            }
        }

        "QS-CERT-001" => {
            if report.certificate_chain.is_empty() {
                return ne("no certificates were received");
            }
            let evidence: Vec<Evidence> = report
                .certificate_chain
                .iter()
                .filter(|c| c.signature.family == "classical")
                .map(|c| {
                    Evidence::new(
                        format!("certificate_chain[{}].signature.name", c.position),
                        &c.signature.name,
                    )
                })
                .collect();
            if evidence.is_empty() {
                Pass
            } else {
                Finding(evidence)
            }
        }

        "QS-CERT-002" => {
            let Some(tls) = &report.tls else {
                return ne(NO_HANDSHAKE);
            };
            match &tls.server_signature_scheme {
                None => ne("no server signature scheme was captured"),
                Some(s) => match s.post_quantum {
                    Some(false) => Finding(vec![Evidence::new(
                        "tls.server_signature_scheme.name",
                        &s.name,
                    )]),
                    Some(true) => Pass,
                    None => NotEvaluated(format!(
                        "signature scheme 0x{:04x} is not in the registry",
                        s.code
                    )),
                },
            }
        }

        "QS-CERT-003" => {
            if report.certificate_chain.is_empty() {
                return ne("no certificates were received");
            }
            let mut evidence = Vec::new();
            for c in &report.certificate_chain {
                if c.public_key.family == "hash_ml_dsa" {
                    evidence.push(Evidence::new(
                        format!("certificate_chain[{}].public_key.name", c.position),
                        &c.public_key.name,
                    ));
                }
                if c.signature.family == "hash_ml_dsa" {
                    evidence.push(Evidence::new(
                        format!("certificate_chain[{}].signature.name", c.position),
                        &c.signature.name,
                    ));
                }
            }
            if evidence.is_empty() {
                Pass
            } else {
                Finding(evidence)
            }
        }

        "QS-CERT-004" => {
            let v = &report.certificate_validation;
            match v.status.as_str() {
                "valid" => Pass,
                "not_reached" => ne("the server presented no certificates"),
                _ => {
                    let unverifiable = report.certificate_chain.iter().any(|c| {
                        UNVERIFIABLE_FAMILIES.contains(&c.signature.family.as_str())
                            || c.public_key.name == "Ed448"
                    });
                    if unverifiable {
                        ne(
                            "the chain uses signature algorithms webpki 0.103 cannot verify; \
                            its validity was not determined",
                        )
                    } else {
                        Finding(vec![
                            Evidence::new("certificate_validation.status", &v.status),
                            Evidence::new(
                                "certificate_validation.reason",
                                v.reason.as_deref().unwrap_or(""),
                            ),
                        ])
                    }
                }
            }
        }

        other => NotEvaluated(format!("no logic for rule {other}")),
    }
}

#[cfg(test)]
mod tests {
    //! Positive and negative case for every rule in the catalogue, on
    //! synthetic reports. tests/testbed.rs applies the same rules to real
    //! testbed scans.
    use super::*;
    use crate::handshake::Observation;
    use crate::report::{
        AlgorithmReport, CertificateReport, DowngradeProbe, ProbeReport, ReportContext, ScanReport,
        ToleranceProbe,
    };
    use crate::types::HandshakeProfile;

    fn report(version: &str, group: u16, sig: u16) -> ScanReport {
        let obs = Observation {
            tls_version: Some(version.to_string()),
            cipher_suite: Some(0x1301),
            negotiated_group: Some(group),
            hello_retry_request: false,
            server_signature_scheme: Some(sig),
            peer_chain: vec![],
            server_hellos: vec![],
            duration: std::time::Duration::ZERO,
        };
        let ctx = ReportContext {
            input: "t".into(),
            host: Some("t".into()),
            port: Some(443),
            server_name: Some("t".into()),
            address: None,
            profile: HandshakeProfile::Default,
            custom_trust_store: false,
            redirects_requested: false,
            started_at: chrono::Utc::now(),
            duration: std::time::Duration::ZERO,
        };
        ScanReport::build(ctx, Some(&obs), None, None, None, None)
    }

    fn hybrid() -> ScanReport {
        report("1.3", 4588, 0x0403)
    }

    fn cert(
        position: usize,
        key_family: &str,
        sig_family: &str,
        sig_name: &str,
    ) -> CertificateReport {
        CertificateReport {
            position,
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            serial_hex: "01".into(),
            not_before: String::new(),
            not_after: String::new(),
            san_dns: vec![],
            san_ip: vec![],
            public_key: AlgorithmReport {
                oid: String::new(),
                name: "k".into(),
                family: key_family.into(),
                size_bits: None,
            },
            signature: AlgorithmReport {
                oid: String::new(),
                name: sig_name.into(),
                family: sig_family.into(),
                size_bits: None,
            },
            sha256: String::new(),
        }
    }

    fn probe(accepted: &[&str]) -> ProbeReport {
        ProbeReport {
            provenance: "observed".into(),
            method: String::new(),
            probes_sent: 1,
            probe_budget: 40,
            spacing_ms: 100,
            budget_exhausted: false,
            aborted: false,
            accepted_groups: accepted.iter().map(|s| s.to_string()).collect(),
            groups: vec![],
            preference: vec![],
            hello_retry: vec![],
            downgrade: None,
            client_hello_tolerance: None,
        }
    }

    fn is_finding(o: &Outcome) -> bool {
        matches!(o, Finding(e) if !e.is_empty())
    }

    #[test]
    fn qs_tls_001() {
        assert!(is_finding(&evaluate(
            "QS-TLS-001",
            &report("1.2", 0x1d, 0x0403)
        )));
        assert_eq!(evaluate("QS-TLS-001", &hybrid()), Pass);
    }

    #[test]
    fn qs_kex_001() {
        assert!(is_finding(&evaluate(
            "QS-KEX-001",
            &report("1.3", 0x1d, 0x0403)
        )));
        assert_eq!(evaluate("QS-KEX-001", &hybrid()), Pass);
        assert_eq!(evaluate("QS-KEX-001", &report("1.3", 514, 0x0403)), Pass);
        let mut failed = hybrid();
        failed.tls = None;
        assert!(matches!(evaluate("QS-KEX-001", &failed), NotEvaluated(_)));
    }

    #[test]
    fn qs_kex_002() {
        let mut r = hybrid();
        assert!(matches!(evaluate("QS-KEX-002", &r), NotEvaluated(_)));
        let mut p = probe(&["x25519", "X25519MLKEM768"]);
        let mut d = DowngradeProbe {
            pq_group: "X25519MLKEM768".into(),
            classical_group: "x25519".into(),
            behaviour: "accepted_classical_share".into(),
            result: "server_hello".into(),
            alert: None,
            reply_group: Some("x25519".into()),
            detail: None,
        };
        p.downgrade = Some(d.clone());
        r.probe = Some(p.clone());
        assert!(is_finding(&evaluate("QS-KEX-002", &r)));
        d.behaviour = "retried_for_pq_group".into();
        p.downgrade = Some(d);
        r.probe = Some(p);
        assert_eq!(evaluate("QS-KEX-002", &r), Pass);
    }

    #[test]
    fn qs_kex_004() {
        let mut r = hybrid();
        r.probe = Some(probe(&["x25519", "secp256r1"]));
        assert!(is_finding(&evaluate("QS-KEX-004", &r)));
        r.probe = Some(probe(&["x25519", "SecP384r1MLKEM1024"]));
        assert_eq!(evaluate("QS-KEX-004", &r), Pass);
        r.probe = Some(probe(&[]));
        assert!(matches!(evaluate("QS-KEX-004", &r), NotEvaluated(_)));
    }

    #[test]
    fn qs_kex_005() {
        let mut r = hybrid();
        let mut p = probe(&["x25519"]);
        let mut t = ToleranceProbe {
            group: "x25519".into(),
            baseline: "ok".into(),
            padded: "closed".into(),
            padded_bytes: 2048,
            split_records: "ok".into(),
            split_record_bytes: 512,
            split_segments: "ok".into(),
            first_segment_bytes: 64,
        };
        p.client_hello_tolerance = Some(t.clone());
        r.probe = Some(p.clone());
        assert!(is_finding(&evaluate("QS-KEX-005", &r)));
        t.padded = "ok".into();
        p.client_hello_tolerance = Some(t);
        r.probe = Some(p);
        assert_eq!(evaluate("QS-KEX-005", &r), Pass);
    }

    #[test]
    fn qs_kex_010() {
        assert!(is_finding(&evaluate("QS-KEX-010", &hybrid())));
        assert_eq!(evaluate("QS-KEX-010", &report("1.3", 4589, 0x0403)), Pass);
        assert_eq!(evaluate("QS-KEX-010", &report("1.3", 514, 0x0403)), Pass);
    }

    #[test]
    fn qs_cert_001() {
        let mut r = hybrid();
        r.certificate_chain = vec![cert(0, "classical", "classical", "ECDSA-SHA256")];
        assert!(is_finding(&evaluate("QS-CERT-001", &r)));
        r.certificate_chain = vec![cert(0, "ml_dsa", "ml_dsa", "id-ml-dsa-65")];
        assert_eq!(evaluate("QS-CERT-001", &r), Pass);
    }

    #[test]
    fn qs_cert_002() {
        assert!(is_finding(&evaluate("QS-CERT-002", &hybrid())));
        assert_eq!(evaluate("QS-CERT-002", &report("1.3", 4588, 0x0905)), Pass);
    }

    #[test]
    fn qs_cert_003() {
        let mut r = hybrid();
        r.certificate_chain = vec![cert(0, "hash_ml_dsa", "ml_dsa", "id-ml-dsa-65")];
        assert!(is_finding(&evaluate("QS-CERT-003", &r)));
        r.certificate_chain = vec![cert(0, "ml_dsa", "ml_dsa", "id-ml-dsa-65")];
        assert_eq!(evaluate("QS-CERT-003", &r), Pass);
    }

    #[test]
    fn qs_cert_004() {
        let mut r = hybrid();
        assert_eq!(evaluate("QS-CERT-004", &r), Pass);
        r.tls = None;
        r.certificate_validation.status = "invalid".into();
        r.certificate_validation.reason = Some("certificate expired".into());
        r.certificate_chain = vec![cert(0, "classical", "classical", "ECDSA-SHA256")];
        assert!(is_finding(&evaluate("QS-CERT-004", &r)));
        // A chain webpki cannot verify is not reported as invalid.
        r.certificate_chain = vec![cert(0, "classical", "slh_dsa", "id-slh-dsa-sha2-128s")];
        assert!(matches!(evaluate("QS-CERT-004", &r), NotEvaluated(_)));
    }

    #[test]
    fn every_catalogue_rule_has_logic() {
        for meta in super::super::catalogue() {
            assert!(
                !matches!(evaluate(&meta.id, &hybrid()), NotEvaluated(ref r) if r.starts_with("no logic")),
                "{}",
                meta.id
            );
        }
    }
}
