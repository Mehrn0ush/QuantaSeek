//! Per-group probing (`--probe`): one hand-built ClientHello per question.
//!
//! Every probe opens a TCP connection, sends a ClientHello and reads only the
//! server's first reply (ServerHello, HelloRetryRequest or alert); no
//! handshake is completed. Probes are capped by a budget and spaced in time.
//! Results are observations of what the server sent in reply to an offer
//! QuantaSeek controls.

pub mod wire;

use crate::constants::{self, GroupKind};
use crate::report::{
    group_report, DowngradeProbe, GroupProbe, HelloRetryProbe, PreferenceProbe, ProbeReport,
    ToleranceProbe,
};
use crate::scan::{try_connect, ScanOptions};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wire::{ClientHelloSpec, Reply};

/// Limits for one target.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// Maximum number of probes (TCP connections) per target.
    pub max_probes: u32,
    /// Minimum delay between the start of consecutive probes.
    pub spacing: Duration,
    /// Time allowed for the server's first reply.
    pub reply_timeout: Duration,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            max_probes: 40,
            spacing: Duration::from_millis(100),
            reply_timeout: Duration::from_secs(5),
        }
    }
}

/// Size the padded ClientHello is grown to, and the record size used for
/// the split variant, in the tolerance probes.
pub const PADDED_CLIENT_HELLO_BYTES: usize = 2048;
pub const SPLIT_RECORD_BYTES: usize = 512;

/// Outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Reply(Reply),
    Timeout,
    ConnectFailed(String),
    NotSent(&'static str),
}

struct Prober<'a> {
    scan: &'a ScanOptions,
    opts: &'a ProbeOptions,
    host: &'a str,
    port: u16,
    server_name: &'a str,
    sent: u32,
    exhausted: bool,
}

impl Prober<'_> {
    async fn send(&mut self, spec: ClientHelloSpec, max_fragment: usize) -> Outcome {
        if self.sent >= self.opts.max_probes {
            self.exhausted = true;
            return Outcome::NotSent("probe budget exhausted");
        }
        let Some(hello) = wire::client_hello(&ClientHelloSpec {
            server_name: Some(self.server_name.to_string()),
            ..spec
        }) else {
            return Outcome::NotSent("key share could not be generated");
        };
        if self.sent > 0 {
            tokio::time::sleep(self.opts.spacing).await;
        }
        self.sent += 1;
        let mut stream = match try_connect(self.scan, self.host, self.port).await {
            Ok(s) => s,
            Err(e) => return Outcome::ConnectFailed(e.message),
        };
        if let Err(e) = stream.write_all(&wire::records(&hello, max_fragment)).await {
            return Outcome::ConnectFailed(e.to_string());
        }
        let mut received = Vec::new();
        let mut buf = [0u8; 8192];
        let deadline = tokio::time::Instant::now() + self.opts.reply_timeout;
        loop {
            let read = tokio::time::timeout_at(deadline, stream.read(&mut buf)).await;
            match read {
                Err(_) => return Outcome::Timeout,
                Ok(Ok(0)) | Ok(Err(_)) => {
                    return Outcome::Reply(
                        wire::parse_reply(&received, true).unwrap_or(Reply::Closed),
                    )
                }
                Ok(Ok(n)) => {
                    received.extend_from_slice(&buf[..n]);
                    if let Some(reply) = wire::parse_reply(&received, false) {
                        return Outcome::Reply(reply);
                    }
                }
            }
        }
    }

    /// Offer `groups` (preference order) with key shares for `shares`.
    async fn offer(&mut self, groups: &[u16], shares: &[u16]) -> Outcome {
        self.send(
            ClientHelloSpec {
                supported_groups: groups.to_vec(),
                key_shares: shares.to_vec(),
                ..Default::default()
            },
            16384,
        )
        .await
    }
}

/// Alert description name (IANA TLS Alerts registry, RFC 8446 §6).
pub fn alert_name(description: u8) -> String {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => return format!("alert({description})"),
    }
    .to_string()
}

/// One-word classification plus details, for report fields.
fn describe(outcome: &Outcome) -> (String, Option<String>, Option<u16>, Option<String>) {
    // (result, alert, group in reply, detail)
    match outcome {
        Outcome::Reply(Reply::Hello(h)) if h.hello_retry_request => {
            ("hello_retry_request".into(), None, h.group, None)
        }
        Outcome::Reply(Reply::Hello(h)) if !wire::is_tls13(h.selected_version) => (
            "malformed".into(),
            None,
            h.group,
            Some("ServerHello did not select TLS 1.3".into()),
        ),
        Outcome::Reply(Reply::Hello(h)) => ("server_hello".into(), None, h.group, None),
        Outcome::Reply(Reply::Alert { description, .. }) => (
            "rejected".into(),
            Some(alert_name(*description)),
            None,
            None,
        ),
        Outcome::Reply(Reply::Closed) => ("closed".into(), None, None, None),
        Outcome::Reply(Reply::Malformed(m)) => ("malformed".into(), None, None, Some(m.clone())),
        Outcome::Timeout => ("timeout".into(), None, None, None),
        Outcome::ConnectFailed(m) => ("connect_failed".into(), None, None, Some(m.clone())),
        Outcome::NotSent(why) => ("not_probed".into(), None, None, Some((*why).into())),
    }
}

fn name(code: u16) -> String {
    constants::get_group_name(code)
}

/// Run every probe for `host:port`.
pub async fn probe(
    scan: &ScanOptions,
    opts: &ProbeOptions,
    host: &str,
    port: u16,
    server_name: &str,
) -> ProbeReport {
    let mut p = Prober {
        scan,
        opts,
        host,
        port,
        server_name,
        sent: 0,
        exhausted: false,
    };

    // 1. Group enumeration: one group, one key share per probe.
    let mut groups = Vec::new();
    let mut accepted: Vec<u16> = Vec::new();
    for g in constants::NAMED_GROUPS {
        if wire::client_key_share(g.code).is_none() {
            groups.push(GroupProbe {
                group: group_report(g.code),
                result: "not_probed".into(),
                alert: None,
                reply_group: None,
                detail: Some(wire::unprobeable_reason(g.code).into()),
            });
            continue;
        }
        let outcome = p.offer(&[g.code], &[g.code]).await;
        let (mut result, alert, reply_group, mut detail) = describe(&outcome);
        if result == "server_hello" {
            match (&outcome, reply_group) {
                (Outcome::Reply(Reply::Hello(h)), Some(rg)) if rg == g.code => {
                    if h.key_share_len == wire::server_share_len(g.code) {
                        result = "accepted".into();
                        accepted.push(g.code);
                    } else {
                        result = "malformed".into();
                        detail = Some(format!(
                            "server key share is {:?} bytes, expected {:?}",
                            h.key_share_len,
                            wire::server_share_len(g.code)
                        ));
                    }
                }
                _ => {
                    result = "malformed".into();
                    detail = Some("ServerHello selected a group that was not offered".into());
                }
            }
        }
        groups.push(GroupProbe {
            group: group_report(g.code),
            result,
            alert,
            reply_group: reply_group.map(name),
            detail,
        });
    }

    // 2. Preference: pairs of accepted groups, both orders, both with shares.
    let candidates: Vec<u16> = accepted.iter().copied().take(3).collect();
    let mut preference = Vec::new();
    for &a in &candidates {
        for &b in &candidates {
            if a == b {
                continue;
            }
            let outcome = p.offer(&[a, b], &[a, b]).await;
            let (result, alert, reply_group, detail) = describe(&outcome);
            preference.push(PreferenceProbe {
                offered: vec![name(a), name(b)],
                result,
                alert,
                selected: reply_group.map(name),
                detail,
            });
        }
    }

    // 3. HelloRetryRequest: accepted group listed, no key share sent.
    let mut hello_retry = Vec::new();
    for &g in &candidates {
        let outcome = p.offer(&[g], &[]).await;
        let (result, alert, reply_group, detail) = describe(&outcome);
        hello_retry.push(HelloRetryProbe {
            group: name(g),
            result,
            alert,
            requested_group: reply_group.map(name),
            detail,
        });
    }

    // 4. Downgrade: PQ and classical listed, only the classical share sent.
    let kind = |g: u16| constants::named_group(g).map(|n| n.kind);
    let pq = accepted
        .iter()
        .copied()
        .find(|g| kind(*g) != Some(GroupKind::Classical));
    let classical = accepted
        .iter()
        .copied()
        .find(|g| kind(*g) == Some(GroupKind::Classical));
    let downgrade = match (pq, classical) {
        (Some(pq), Some(classical)) => {
            let outcome = p.offer(&[pq, classical], &[classical]).await;
            let (result, alert, reply_group, detail) = describe(&outcome);
            let behaviour = match (result.as_str(), reply_group) {
                ("hello_retry_request", Some(g)) if g == pq => "retried_for_pq_group",
                ("server_hello", Some(g)) if g == classical => "accepted_classical_share",
                _ => "other",
            };
            Some(DowngradeProbe {
                pq_group: name(pq),
                classical_group: name(classical),
                behaviour: behaviour.into(),
                result,
                alert,
                reply_group: reply_group.map(name),
                detail,
            })
        }
        _ => None,
    };

    // 5. ClientHello tolerance: same offer as a baseline, padded, and split.
    let tolerance = match accepted
        .iter()
        .copied()
        .find(|g| kind(*g) == Some(GroupKind::Classical))
        .or(accepted.first().copied())
    {
        Some(g) => {
            let spec = ClientHelloSpec {
                supported_groups: vec![g],
                key_shares: vec![g],
                ..Default::default()
            };
            let ok = |o: &Outcome| matches!(o, Outcome::Reply(Reply::Hello(_)));
            let base = p.send(spec.clone(), 16384).await;
            let padded = p
                .send(
                    ClientHelloSpec {
                        pad_to: Some(PADDED_CLIENT_HELLO_BYTES),
                        ..spec.clone()
                    },
                    16384,
                )
                .await;
            let split = p.send(spec, SPLIT_RECORD_BYTES).await;
            let label = |o: &Outcome| {
                if ok(o) {
                    "ok".to_string()
                } else {
                    describe(o).0
                }
            };
            Some(ToleranceProbe {
                group: name(g),
                baseline: label(&base),
                padded: label(&padded),
                padded_bytes: PADDED_CLIENT_HELLO_BYTES as u32,
                split_records: label(&split),
                split_record_bytes: SPLIT_RECORD_BYTES as u32,
            })
        }
        None => None,
    };

    ProbeReport {
        provenance: "observed".into(),
        method: "hand-built TLS 1.3 ClientHello per probe; only the first server reply is read"
            .into(),
        probes_sent: p.sent,
        probe_budget: opts.max_probes,
        spacing_ms: opts.spacing.as_millis() as u64,
        budget_exhausted: p.exhausted,
        accepted_groups: accepted.iter().copied().map(name).collect(),
        groups,
        preference,
        hello_retry,
        downgrade,
        client_hello_tolerance: tolerance,
    }
}
