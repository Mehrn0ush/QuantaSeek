//! Scan report, output schema v0.
//!
//! Provenance rules (see `schema/scan-result.v0.json`):
//! - `tls`, `certificate_chain`, `http_redirect` and `evidence` hold values
//!   observed in the handshake (or in the opt-in redirect requests).
//! - Every field under `pqc` is `derived`: a registry lookup on an observed
//!   value, with the basis stated.
//! - `outcome.error.interpretation`, when present, is `inferred`.
//! - `not_implemented` lists what this version does not observe at all.
//!
//! Nothing in this report is a default, an estimate, or a constant standing
//! in for a measurement.

use crate::constants::{self, GroupKind, OidKind, Status};
use crate::handshake::{Observation, PartialObservation};
use crate::types::{HandshakeProfile, ScanError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// JSON Schema (2020-12) for [`ScanReport`], generated from these types.
pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ScanReport)).unwrap_or_default()
}

/// Version of this output format. Bumped on any breaking change.
pub const SCHEMA_VERSION: &str = "0";

/// Things this version of QuantaSeek does not observe. Reported in every
/// result so that an absent value is never mistaken for a negative one.
pub const NOT_IMPLEMENTED: &[&str] = &[
    "quic",
    "alpn",
    "ocsp_stapling",
    "session_resumption",
    "early_data",
    "certificate_transparency",
    "revocation",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanReport {
    /// Always "0" for this format.
    pub schema_version: String,
    pub tool: Tool,
    pub target: TargetInfo,
    pub profile: ProfileInfo,
    /// RFC 3339 UTC time the scan of this target started.
    pub started_at: String,
    /// Wall-clock time for this target, all connections included.
    pub duration_ms: u64,
    pub outcome: Outcome,
    /// Present when the handshake completed.
    pub tls: Option<TlsInfo>,
    /// Certificates as sent by the server, leaf first. Reported whenever the
    /// server presented them, including when validation failed; see
    /// `certificate_validation`.
    pub certificate_chain: Vec<CertificateReport>,
    pub certificate_validation: CertificateValidation,
    /// Present when the handshake completed or a certificate chain was seen.
    pub pqc: Option<PqcSummary>,
    /// Present only when redirect following was requested.
    pub http_redirect: Option<HttpRedirectInfo>,
    /// Per-group probing results; present only with `--probe`.
    pub probe: Option<ProbeReport>,
    /// Aspects this version does not observe.
    pub not_implemented: Vec<String>,
    /// Capabilities that exist but were not requested for this scan
    /// ("probe", "http_redirect").
    pub not_requested: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub version: String,
    /// TLS library and crypto provider used for the handshake.
    pub tls_stack: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetInfo {
    /// The target exactly as given.
    pub input: String,
    pub host: Option<String>,
    /// Port the handshake used (null if no connection was made).
    pub port: Option<u16>,
    /// Name sent as SNI and validated against the certificate.
    pub server_name: Option<String>,
    /// Peer address of the handshake connection.
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileInfo {
    pub name: String,
    /// Key-exchange groups our ClientHello offered, in preference order.
    pub offered_groups: Vec<String>,
    /// TLS versions our ClientHello offered.
    pub offered_tls_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// "completed" when the handshake finished, otherwise "failed".
    pub status: String,
    /// Why the scan did not complete. Absent when status is "completed".
    pub error: Option<ScanError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateValidation {
    /// "valid" (rustls/webpki accepted the chain for `target.server_name`),
    /// "invalid" (it rejected it; see `reason`), or "not_reached" (the
    /// handshake failed before the server presented certificates).
    pub status: String,
    /// Trust store used: "webpki-roots" or "custom".
    pub trust_store: String,
    /// rustls/webpki rejection reason when status is "invalid". Note that
    /// webpki 0.103 cannot verify SLH-DSA, composite ML-DSA or Ed448
    /// signatures, so such chains are "invalid" here even if correctly signed.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeName {
    pub code: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupReport {
    pub code: u16,
    /// IANA name, or `unknown(0x....)` if not in the registry table.
    pub name: String,
    /// "classical", "hybrid", "pure_pq", or "unregistered".
    pub kind: String,
    /// Post-quantum KEM component, if any.
    pub pq_kem: Option<String>,
    /// Registry status: "standard", "draft", "obsolete", or "unregistered".
    pub status: String,
    /// Document the registry entry cites.
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignatureSchemeReport {
    pub code: u16,
    pub name: String,
    /// Null when the scheme is not in the registry table.
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsInfo {
    /// "1.3" or "1.2".
    pub version: String,
    pub cipher_suite: CodeName,
    pub key_exchange: Option<GroupReport>,
    /// The server answered the first ClientHello with a HelloRetryRequest.
    pub hello_retry_request: bool,
    /// The server's handshake signature scheme (TLS 1.3 CertificateVerify,
    /// TLS 1.2 ServerKeyExchange). In TLS 1.2 an ECDSA codepoint names only
    /// the hash (RFC 5246 §7.4.1.4.1), e.g. ecdsa_secp384r1_sha384 can be a
    /// P-256 key signing with SHA-384; the key is in `certificate_chain[0]`.
    pub server_signature_scheme: Option<SignatureSchemeReport>,
    pub handshake_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmReport {
    pub oid: String,
    pub name: String,
    /// "classical", "ml_dsa", "hash_ml_dsa", "slh_dsa", "hash_slh_dsa",
    /// "ml_kem", "composite_ml_dsa", or "unrecognised".
    pub family: String,
    /// Key size in bits, where the algorithm has one and it was parsed.
    pub size_bits: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateReport {
    /// 0 = leaf, in the order the server sent them.
    pub position: usize,
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub public_key: AlgorithmReport,
    pub signature: AlgorithmReport,
    pub sha256: String,
}

/// A value derived from observed data by a stated rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    pub value: String,
    /// Always "derived".
    pub provenance: String,
    pub basis: String,
}

impl Derived {
    fn new(value: &str, basis: impl Into<String>) -> Self {
        Self {
            value: value.to_string(),
            provenance: "derived".to_string(),
            basis: basis.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PqcSummary {
    /// "hybrid", "pure_pq", "classical", or "unknown".
    pub key_exchange: Derived,
    /// "post_quantum" (every certificate PQ or composite), "mixed", "classical",
    /// or "unknown".
    pub certificate_chain: Derived,
    /// "post_quantum", "classical", or "unknown".
    pub handshake_signature: Derived,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRedirectInfo {
    /// At least one redirect was followed.
    pub detected: bool,
    /// HTTP status of the first response.
    pub status_code: Option<u16>,
    /// URLs requested, in order.
    pub redirect_chain: Vec<String>,
    pub final_destination: Option<String>,
    /// Leaf certificate of the final destination, when it is a different origin.
    /// Never substituted for the target's certificate.
    pub final_destination_certificate: Option<CertificateReport>,
    pub redirect_count: u32,
}

/// Results of per-group probing (`--probe`). Every result is an observation
/// of the server's first reply to a ClientHello QuantaSeek built; results
/// are "accepted"/"server_hello", "hello_retry_request", "rejected" (with
/// `alert`), "closed", "timeout", "malformed", "connect_failed", or
/// "not_probed" (with `detail`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    /// Always "observed".
    pub provenance: String,
    pub method: String,
    pub probes_sent: u32,
    pub probe_budget: u32,
    pub spacing_ms: u64,
    /// True if some probes were skipped because the budget ran out.
    pub budget_exhausted: bool,
    /// True if probing stopped after repeated TCP connection failures.
    pub aborted: bool,
    /// Groups the server accepted when offered alone with a key share.
    pub accepted_groups: Vec<String>,
    /// One entry per registered group.
    pub groups: Vec<GroupProbe>,
    /// Pairs of accepted groups offered in both orders, both with key shares.
    pub preference: Vec<PreferenceProbe>,
    /// Each accepted group listed in supported_groups with no key share.
    pub hello_retry: Vec<HelloRetryProbe>,
    /// An accepted PQ group and an accepted classical group listed, with a
    /// key share for the classical group only.
    pub downgrade: Option<DowngradeProbe>,
    /// The same offer sent normally, padded, and split across records.
    pub client_hello_tolerance: Option<ToleranceProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupProbe {
    pub group: GroupReport,
    /// "accepted" means a TLS 1.3 ServerHello selecting this group with a
    /// key share of the size the group defines.
    pub result: String,
    pub alert: Option<String>,
    /// Group named in the reply, if any.
    pub reply_group: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreferenceProbe {
    /// supported_groups, in the order offered.
    pub offered: Vec<String>,
    pub result: String,
    pub alert: Option<String>,
    /// Group the server selected.
    pub selected: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HelloRetryProbe {
    pub group: String,
    /// "hello_retry_request" is the RFC 8446 §4.1.4 behaviour.
    pub result: String,
    pub alert: Option<String>,
    /// Group the HelloRetryRequest asked for.
    pub requested_group: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DowngradeProbe {
    pub pq_group: String,
    pub classical_group: String,
    /// "retried_for_pq_group" (HelloRetryRequest for the PQ group),
    /// "accepted_classical_share" (ServerHello with the classical group), or
    /// "other".
    pub behaviour: String,
    pub result: String,
    pub alert: Option<String>,
    pub reply_group: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToleranceProbe {
    /// Group offered in all three variants.
    pub group: String,
    /// "ok" (ServerHello or HelloRetryRequest), otherwise the probe result.
    pub baseline: String,
    pub padded: String,
    pub padded_bytes: u32,
    pub split_records: String,
    pub split_record_bytes: u32,
    /// One record written as two TCP writes (the first `first_segment_bytes`
    /// long) with a pause between them.
    pub split_segments: String,
    pub first_segment_bytes: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Hex of each plaintext ServerHello / HelloRetryRequest message received.
    pub server_hellos_hex: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// IANA name for a cipher suite codepoint. rustls names TLS 1.3 suites
/// "TLS13_*"; the IANA registry calls them "TLS_*" (RFC 8446 §B.4).
fn cipher_suite_name(code: u16) -> String {
    let suite = rustls::CipherSuite::from(code);
    match suite.as_str() {
        Some(name) => name.replacen("TLS13_", "TLS_", 1),
        None => format!("unknown(0x{:04x})", code),
    }
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Standard => "standard",
        Status::Draft => "draft",
        Status::Obsolete => "obsolete",
    }
}

pub fn group_report(code: u16) -> GroupReport {
    match constants::named_group(code) {
        Some(g) => GroupReport {
            code,
            name: g.name.to_string(),
            kind: match g.kind {
                GroupKind::Classical => "classical",
                GroupKind::Hybrid => "hybrid",
                GroupKind::PurePq => "pure_pq",
            }
            .to_string(),
            pq_kem: g.pq_kem.map(str::to_string),
            status: status_name(g.status).to_string(),
            reference: Some(g.reference.to_string()),
        },
        None => GroupReport {
            code,
            name: constants::get_group_name(code),
            kind: "unregistered".to_string(),
            pq_kem: None,
            status: "unregistered".to_string(),
            reference: None,
        },
    }
}

fn signature_scheme_report(code: u16) -> SignatureSchemeReport {
    let info = constants::signature_scheme(code);
    SignatureSchemeReport {
        code,
        name: constants::get_signature_algorithm_name(code),
        post_quantum: info.map(|s| s.post_quantum),
    }
}

fn family_of(oid: &str) -> String {
    match constants::pqc_oid(oid).map(|o| o.kind) {
        Some(OidKind::MlDsa) => "ml_dsa",
        Some(OidKind::HashMlDsa) => "hash_ml_dsa",
        Some(OidKind::SlhDsa) => "slh_dsa",
        Some(OidKind::HashSlhDsa) => "hash_slh_dsa",
        Some(OidKind::MlKem) => "ml_kem",
        Some(OidKind::CompositeMlDsa) => "composite_ml_dsa",
        None if crate::cert::is_known_classical_oid(oid) => "classical",
        None => "unrecognised",
    }
    .to_string()
}

/// Parse one DER certificate into its report form.
pub fn certificate_report(position: usize, der: &[u8]) -> Result<CertificateReport, String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("{e:?}"))?;
    let tbs = &cert.tbs_certificate;
    let rfc3339 = |t: ASN1Time| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(t.timestamp(), 0)
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| t.to_string())
    };
    let (mut san_dns, mut san_ip) = (Vec::new(), Vec::new());
    if let Ok(Some(san)) = tbs.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(d) => san_dns.push(d.to_string()),
                GeneralName::IPAddress(bytes) => san_ip.push(match bytes.len() {
                    4 => std::net::IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap_or_default())
                        .to_string(),
                    16 => std::net::IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap_or_default())
                        .to_string(),
                    _ => hex(bytes),
                }),
                _ => {}
            }
        }
    }
    let spki_oid = tbs.subject_pki.algorithm.algorithm.to_id_string();
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
    Ok(CertificateReport {
        position,
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial_hex: hex(tbs.raw_serial()),
        not_before: rfc3339(tbs.validity.not_before),
        not_after: rfc3339(tbs.validity.not_after),
        san_dns,
        san_ip,
        public_key: AlgorithmReport {
            name: crate::cert::public_key_algorithm_name(&spki_oid),
            family: family_of(&spki_oid),
            size_bits: crate::cert::public_key_size_bits(&tbs.subject_pki),
            oid: spki_oid,
        },
        signature: AlgorithmReport {
            name: crate::cert::signature_algorithm_name(&sig_oid),
            family: family_of(&sig_oid),
            size_bits: None,
            oid: sig_oid,
        },
        sha256: hex(digest.as_ref()),
    })
}

fn is_pq_family(family: &str) -> bool {
    !matches!(family, "classical" | "unrecognised")
}

/// Derived PQC summary. Each value states the rule it follows.
fn pqc_summary(tls: Option<&TlsInfo>, chain: &[CertificateReport]) -> PqcSummary {
    let key_exchange = match tls.and_then(|t| t.key_exchange.as_ref()) {
        Some(g) if g.kind == "hybrid" || g.kind == "pure_pq" || g.kind == "classical" => {
            Derived::new(
                &g.kind,
                format!(
                    "negotiated group {} (0x{:04x}) is {} in the IANA TLS Supported Groups registry",
                    g.name, g.code, g.kind
                ),
            )
        }
        Some(g) => Derived::new(
            "unknown",
            format!(
                "negotiated group 0x{:04x} is not in QuantaSeek's registry table",
                g.code
            ),
        ),
        None if tls.is_none() => Derived::new("unknown", "the handshake did not complete"),
        None => Derived::new("unknown", "the TLS stack reported no negotiated group"),
    };

    // A certificate counts as post-quantum when its own signature algorithm
    // is PQ or composite. The root (self-signed, not used for validation by
    // the client) is included as sent.
    let certificate_chain = if chain.is_empty() {
        Derived::new("unknown", "no certificates were received")
    } else {
        let pq = chain
            .iter()
            .filter(|c| is_pq_family(&c.signature.family))
            .count();
        let value = if pq == chain.len() {
            "post_quantum"
        } else if pq == 0 {
            "classical"
        } else {
            "mixed"
        };
        Derived::new(
            value,
            format!(
                "{} of {} certificate signature algorithms are ML-DSA, SLH-DSA or composite ML-DSA OIDs",
                pq,
                chain.len()
            ),
        )
    };

    let handshake_signature = match tls.and_then(|t| t.server_signature_scheme.as_ref()) {
        Some(s) => match s.post_quantum {
            Some(true) => Derived::new(
                "post_quantum",
                format!("server signature scheme {} is post-quantum", s.name),
            ),
            Some(false) => Derived::new(
                "classical",
                format!("server signature scheme {} is classical", s.name),
            ),
            None => Derived::new(
                "unknown",
                format!(
                    "signature scheme 0x{:04x} is not in the registry table",
                    s.code
                ),
            ),
        },
        None if tls.is_none() => Derived::new("unknown", "the handshake did not complete"),
        None => Derived::new("unknown", "no server signature scheme was captured"),
    };

    PqcSummary {
        key_exchange,
        certificate_chain,
        handshake_signature,
    }
}

/// Inputs to a report that are not part of the handshake observation.
pub struct ReportContext {
    pub input: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub server_name: Option<String>,
    pub address: Option<String>,
    pub profile: HandshakeProfile,
    pub custom_trust_store: bool,
    pub redirects_requested: bool,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration: std::time::Duration,
}

impl ScanReport {
    /// Assemble a report. `observation` is `Some` only for a completed handshake.
    pub fn build(
        ctx: ReportContext,
        observation: Option<&Observation>,
        partial: Option<&PartialObservation>,
        error: Option<ScanError>,
        http_redirect: Option<HttpRedirectInfo>,
        probe: Option<ProbeReport>,
    ) -> Self {
        let mut not_requested = Vec::new();
        if probe.is_none() {
            not_requested.push("probe".to_string());
        }
        if http_redirect.is_none() && !ctx.redirects_requested {
            not_requested.push("http_redirect".to_string());
        }
        let tls = observation.map(|o| TlsInfo {
            version: o
                .tls_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            cipher_suite: o
                .cipher_suite
                .map(|code| CodeName {
                    code,
                    name: cipher_suite_name(code),
                })
                .unwrap_or(CodeName {
                    code: 0,
                    name: "unknown".to_string(),
                }),
            key_exchange: o.negotiated_group.map(group_report),
            hello_retry_request: o.hello_retry_request,
            server_signature_scheme: o.server_signature_scheme.map(signature_scheme_report),
            handshake_ms: o.duration.as_millis() as u64,
        });
        let presented = observation
            .map(|o| &o.peer_chain)
            .or(partial.map(|p| &p.peer_chain));
        let certificate_chain: Vec<CertificateReport> = presented
            .map(|chain| {
                chain
                    .iter()
                    .enumerate()
                    .filter_map(|(i, der)| match certificate_report(i, der.as_ref()) {
                        Ok(c) => Some(c),
                        Err(e) => {
                            tracing::warn!("certificate {} could not be parsed: {}", i, e);
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let pqc = (tls.is_some() || !certificate_chain.is_empty())
            .then(|| pqc_summary(tls.as_ref(), &certificate_chain));
        let trust_store = if ctx.custom_trust_store {
            "custom"
        } else {
            "webpki-roots"
        }
        .to_string();
        let certificate_rejected = error
            .as_ref()
            .is_some_and(|e| e.code == "certificate_rejected");
        let certificate_validation = match (observation.is_some(), certificate_rejected) {
            (true, _) => CertificateValidation {
                status: "valid".to_string(),
                trust_store,
                reason: None,
            },
            (false, true) => CertificateValidation {
                status: "invalid".to_string(),
                trust_store,
                reason: error.as_ref().map(|e| e.message.clone()),
            },
            (false, false) => CertificateValidation {
                status: "not_reached".to_string(),
                trust_store,
                reason: None,
            },
        };
        let offered_tls_versions = if ctx.profile.tls13_only() {
            vec!["1.3".to_string()]
        } else {
            vec!["1.3".to_string(), "1.2".to_string()]
        };

        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: Tool {
                name: "quantaseek".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                tls_stack: "rustls 0.23 / aws-lc-rs".to_string(),
            },
            target: TargetInfo {
                input: ctx.input,
                host: ctx.host,
                port: ctx.port,
                server_name: ctx.server_name,
                address: ctx.address,
            },
            profile: ProfileInfo {
                name: ctx.profile.name().to_string(),
                offered_groups: ctx.profile.offered_group_names(),
                offered_tls_versions,
            },
            started_at: ctx
                .started_at
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            duration_ms: ctx.duration.as_millis() as u64,
            outcome: Outcome {
                status: if observation.is_some() {
                    "completed"
                } else {
                    "failed"
                }
                .to_string(),
                error,
            },
            tls,
            certificate_chain,
            certificate_validation,
            pqc,
            http_redirect,
            probe,
            not_implemented: NOT_IMPLEMENTED.iter().map(|s| s.to_string()).collect(),
            not_requested,
            evidence: Evidence {
                server_hellos_hex: observation
                    .map(|o| &o.server_hellos)
                    .or(partial.map(|p| &p.server_hellos))
                    .map(|hellos| hellos.iter().map(|m| hex(m)).collect())
                    .unwrap_or_default(),
            },
        }
    }

    /// True if the handshake completed.
    pub fn completed(&self) -> bool {
        self.outcome.status == "completed"
    }

    /// Human-readable rendering of the same data.
    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "Target:   {}", self.target.input);
        if let Some(addr) = &self.target.address {
            let _ = writeln!(
                out,
                "Address:  {} (SNI {})",
                addr,
                self.target.server_name.as_deref().unwrap_or("-")
            );
        }
        let _ = writeln!(
            out,
            "Profile:  {} (offered {})",
            self.profile.name,
            self.profile.offered_groups.join(", ")
        );
        match (&self.tls, &self.outcome.error) {
            (Some(tls), _) => {
                let _ = writeln!(out, "Outcome:  completed");
                let _ = writeln!(out, "TLS:      {} {}", tls.version, tls.cipher_suite.name);
                match &tls.key_exchange {
                    Some(g) => {
                        let _ = writeln!(out, "Group:    {} ({}, {})", g.name, g.kind, g.status);
                    }
                    None => {
                        let _ = writeln!(out, "Group:    not reported by the TLS stack");
                    }
                }
                if tls.hello_retry_request {
                    let _ = writeln!(out, "HRR:      server sent a HelloRetryRequest");
                }
                if let Some(s) = &tls.server_signature_scheme {
                    let _ = writeln!(out, "Sig:      {}", s.name);
                }
            }
            (None, Some(e)) => {
                let _ = writeln!(out, "Outcome:  failed: {} ({:?})", e.code, e.category);
                let _ = writeln!(out, "          {}", e.message);
                if let Some(alert) = &e.alert {
                    let _ = writeln!(out, "Alert:    {}", alert);
                }
                if let Some(i) = &e.interpretation {
                    let _ = writeln!(out, "Inferred: {}", i.statement);
                }
            }
            (None, None) => {
                let _ = writeln!(out, "Outcome:  failed");
            }
        }
        for c in &self.certificate_chain {
            let _ = writeln!(
                out,
                "Cert[{}]:  {} | key {} | sig {}",
                c.position, c.subject, c.public_key.name, c.signature.name
            );
        }
        if let Some(p) = &self.pqc {
            let _ = writeln!(
                out,
                "PQC:      key exchange {}, certificates {}, handshake signature {} (derived)",
                p.key_exchange.value, p.certificate_chain.value, p.handshake_signature.value
            );
        }
        if let Some(r) = &self.http_redirect {
            let _ = writeln!(out, "Redirect: {}", r.redirect_chain.join(" -> "));
        }
        if let Some(p) = &self.probe {
            let _ = writeln!(
                out,
                "Probe:    {} probes; accepted groups: {}",
                p.probes_sent,
                if p.accepted_groups.is_empty() {
                    "none".to_string()
                } else {
                    p.accepted_groups.join(", ")
                }
            );
            if let Some(d) = &p.downgrade {
                let _ = writeln!(out, "          downgrade check: {}", d.behaviour);
            }
            if let Some(t) = &p.client_hello_tolerance {
                let _ = writeln!(
                    out,
                    "          ClientHello tolerance: baseline {}, padded {}, split records {}, split segments {}",
                    t.baseline, t.padded, t.split_records, t.split_segments
                );
            }
        }
        let _ = writeln!(out, "Not observed: {}", self.not_implemented.join(", "));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_names_follow_iana() {
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(
            cipher_suite_name(0xc02b),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn certificate_families_cover_every_pqc_oid_kind() {
        assert_eq!(family_of("2.16.840.1.101.3.4.3.18"), "ml_dsa");
        assert_eq!(family_of("2.16.840.1.101.3.4.3.33"), "hash_ml_dsa");
        assert_eq!(family_of("2.16.840.1.101.3.4.3.20"), "slh_dsa");
        assert_eq!(family_of("2.16.840.1.101.3.4.3.36"), "hash_slh_dsa");
        assert_eq!(family_of("2.16.840.1.101.3.4.4.2"), "ml_kem");
        assert_eq!(family_of("1.3.6.1.5.5.7.6.46"), "composite_ml_dsa");
        assert_eq!(family_of("1.2.840.10045.4.3.2"), "classical");
        // oqs-provider prototype composite OID: not RFC 10073, not recognised.
        assert_eq!(family_of("1.3.9999.7.7"), "unrecognised");
        assert!(is_pq_family("composite_ml_dsa") && !is_pq_family("unrecognised"));
    }

    #[test]
    fn group_report_marks_unregistered() {
        assert_eq!(group_report(4588).kind, "hybrid");
        assert_eq!(group_report(4588).status, "standard");
        assert_eq!(group_report(25497).status, "obsolete");
        assert_eq!(group_report(0x7777).kind, "unregistered");
    }
}
