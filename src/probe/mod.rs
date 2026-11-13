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
    /// Minimum delay between the start of consecutive probes. Each delay is
    /// this plus a random jitter of up to half of it.
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
/// Split-segment variant: bytes in the first TCP write, and the pause
/// before the rest (with TCP_NODELAY, so the two writes leave as separate
/// segments on an unloaded path).
pub const SPLIT_SEGMENT_BYTES: usize = 64;
pub const SPLIT_SEGMENT_PAUSE: Duration = Duration::from_millis(50);
/// Probing stops after this many consecutive probes fail to connect
/// (refused, reset, timed out at TCP level).
pub const ABORT_AFTER_CONNECT_FAILURES: u32 = 3;
/// Classical groups used as the classical side of the preference,
/// downgrade and tolerance probes, in this order: x25519 and secp256r1 are
/// the shares real clients send.
pub const CLASSICAL_PREFERENCE: [u16; 2] = [
    constants::NAMED_GROUP_X25519,
    constants::NAMED_GROUP_SECP256R1,
];

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
    consecutive_connect_failures: u32,
    aborted: bool,
}

/// How the ClientHello bytes are written.
#[derive(Debug, Clone, Copy)]
enum Framing {
    /// Records of at most this many bytes, one write.
    Records(usize),
    /// One record, written in two TCP writes with a pause between.
    SplitSegment,
}

fn jittered(spacing: Duration) -> Duration {
    let mut b = [0u8; 2];
    let _ = aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), &mut b);
    let fraction = u16::from_be_bytes(b) as f64 / u16::MAX as f64; // 0..=1
    spacing + spacing.mul_f64(0.5 * fraction)
}

impl Prober<'_> {
    async fn send(&mut self, spec: ClientHelloSpec, max_fragment: usize) -> Outcome {
        self.send_framed(spec, Framing::Records(max_fragment)).await
    }

    async fn send_framed(&mut self, spec: ClientHelloSpec, framing: Framing) -> Outcome {
        if self.aborted {
            return Outcome::NotSent("probing aborted after repeated connection failures");
        }
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
            tokio::time::sleep(jittered(self.opts.spacing)).await;
        }
        self.sent += 1;
        let mut stream = match try_connect(self.scan, self.host, self.port).await {
            Ok(s) => {
                self.consecutive_connect_failures = 0;
                s
            }
            Err(e) => {
                self.consecutive_connect_failures += 1;
                if self.consecutive_connect_failures >= ABORT_AFTER_CONNECT_FAILURES {
                    self.aborted = true;
                }
                return Outcome::ConnectFailed(e.message);
            }
        };
        let written = match framing {
            Framing::Records(max) => stream.write_all(&wire::records(&hello, max)).await,
            Framing::SplitSegment => {
                let bytes = wire::records(&hello, 16384);
                let cut = SPLIT_SEGMENT_BYTES.min(bytes.len());
                match stream.write_all(&bytes[..cut]).await {
                    Ok(()) => {
                        let _ = stream.flush().await;
                        tokio::time::sleep(SPLIT_SEGMENT_PAUSE).await;
                        stream.write_all(&bytes[cut..]).await
                    }
                    Err(e) => Err(e),
                }
            }
        };
        if let Err(e) = written {
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
        consecutive_connect_failures: 0,
        aborted: false,
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

    // Candidates. Every accepted PQ/hybrid group is included. The classical
    // side is chosen the way real clients send shares: x25519 first, then
    // secp256r1; another accepted classical group is used only if neither is.
    let kind = |g: u16| constants::named_group(g).map(|n| n.kind);
    let pq_accepted: Vec<u16> = accepted
        .iter()
        .copied()
        .filter(|g| kind(*g).is_some_and(|k| k != GroupKind::Classical))
        .collect();
    let mut classical: Vec<u16> = CLASSICAL_PREFERENCE
        .iter()
        .copied()
        .filter(|g| accepted.contains(g))
        .collect();
    if classical.is_empty() {
        classical.extend(
            accepted
                .iter()
                .copied()
                .find(|g| kind(*g) == Some(GroupKind::Classical)),
        );
    }

    // The remaining probes run in priority order, so that when the budget
    // runs out it is the least informative ones that are skipped (they are
    // still reported, with result "not_probed").
    let mut downgrade = Vec::new();
    let mut hello_retry = Vec::new();
    let mut preference = Vec::new();

    // Priority 1: downgrade with the first classical candidate (x25519).
    if let Some(&c) = classical.first() {
        if !pq_accepted.is_empty() {
            downgrade.push(downgrade_case(&mut p, &pq_accepted, c).await);
        }
    }

    // Priority 2: ClientHello tolerance, offering the first classical
    // candidate (or the first accepted group).
    let tolerance = match classical.first().copied().or(accepted.first().copied()) {
        Some(g) => Some(tolerance_probe(&mut p, g).await),
        None => None,
    };

    // Priority 3: HelloRetryRequest for every accepted PQ group.
    for &g in &pq_accepted {
        hello_retry.push(hello_retry_probe(&mut p, g).await);
    }

    // Priority 4: preference, each PQ group against the first classical one.
    if let Some(&c) = classical.first() {
        for &q in &pq_accepted {
            for pair in [[q, c], [c, q]] {
                preference.push(preference_probe(&mut p, pair).await);
            }
        }
    }

    // Priority 5: downgrade with the second classical candidate (secp256r1).
    if let Some(&c) = classical.get(1) {
        if !pq_accepted.is_empty() {
            downgrade.push(downgrade_case(&mut p, &pq_accepted, c).await);
        }
    }

    // Priority 6: HelloRetryRequest for the classical candidates.
    for &g in &classical {
        hello_retry.push(hello_retry_probe(&mut p, g).await);
    }

    // Priority 7: remaining preference pairs: PQ vs the second classical,
    // PQ vs PQ, classical vs classical.
    let mut rest: Vec<[u16; 2]> = Vec::new();
    for &c in classical.iter().skip(1) {
        for &q in &pq_accepted {
            rest.extend([[q, c], [c, q]]);
        }
    }
    for (i, &a) in pq_accepted.iter().enumerate() {
        for &b in &pq_accepted[i + 1..] {
            rest.extend([[a, b], [b, a]]);
        }
    }
    for (i, &a) in classical.iter().enumerate() {
        for &b in &classical[i + 1..] {
            rest.extend([[a, b], [b, a]]);
        }
    }
    for pair in rest {
        preference.push(preference_probe(&mut p, pair).await);
    }

    ProbeReport {
        provenance: "observed".into(),
        method: "hand-built TLS 1.3 ClientHello per probe; only the first server reply is read"
            .into(),
        probes_sent: p.sent,
        probe_budget: opts.max_probes,
        spacing_ms: opts.spacing.as_millis() as u64,
        budget_exhausted: p.exhausted,
        aborted: p.aborted,
        accepted_groups: accepted.iter().copied().map(name).collect(),
        groups,
        preference,
        hello_retry,
        downgrade,
        client_hello_tolerance: tolerance,
    }
}

async fn preference_probe(p: &mut Prober<'_>, pair: [u16; 2]) -> PreferenceProbe {
    let outcome = p.offer(&pair, &pair).await;
    let (result, alert, reply_group, detail) = describe(&outcome);
    PreferenceProbe {
        offered: vec![name(pair[0]), name(pair[1])],
        result,
        alert,
        selected: reply_group.map(name),
        detail,
    }
}

async fn hello_retry_probe(p: &mut Prober<'_>, g: u16) -> HelloRetryProbe {
    let outcome = p.offer(&[g], &[]).await;
    let (result, alert, reply_group, detail) = describe(&outcome);
    HelloRetryProbe {
        group: name(g),
        result,
        alert,
        requested_group: reply_group.map(name),
        detail,
    }
}

/// Every accepted PQ group listed first, then `classical`; a key share for
/// `classical` only.
async fn downgrade_case(p: &mut Prober<'_>, pq: &[u16], classical: u16) -> DowngradeProbe {
    let mut offered = pq.to_vec();
    offered.push(classical);
    let outcome = p.offer(&offered, &[classical]).await;
    let (result, alert, reply_group, detail) = describe(&outcome);
    let behaviour = match (result.as_str(), reply_group) {
        ("hello_retry_request", Some(g)) if pq.contains(&g) => "retried_for_pq_group",
        ("server_hello", Some(g)) if g == classical => "accepted_classical_share",
        ("not_probed", _) => "not_probed",
        _ => "other",
    };
    DowngradeProbe {
        offered: offered.iter().copied().map(name).collect(),
        key_share: name(classical),
        behaviour: behaviour.into(),
        result,
        alert,
        reply_group: reply_group.map(name),
        detail,
    }
}

/// The same single-group offer sent normally, padded, split into records
/// and split across TCP segments.
async fn tolerance_probe(p: &mut Prober<'_>, g: u16) -> ToleranceProbe {
    let spec = ClientHelloSpec {
        supported_groups: vec![g],
        key_shares: vec![g],
        ..Default::default()
    };
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
    let split = p.send(spec.clone(), SPLIT_RECORD_BYTES).await;
    let segments = p.send_framed(spec, Framing::SplitSegment).await;
    let label = |o: &Outcome| match o {
        Outcome::Reply(Reply::Hello(_)) => "ok".to_string(),
        other => describe(other).0,
    };
    ToleranceProbe {
        group: name(g),
        baseline: label(&base),
        padded: label(&padded),
        padded_bytes: PADDED_CLIENT_HELLO_BYTES as u32,
        split_records: label(&split),
        split_record_bytes: SPLIT_RECORD_BYTES as u32,
        split_segments: label(&segments),
        first_segment_bytes: SPLIT_SEGMENT_BYTES as u32,
    }
}
