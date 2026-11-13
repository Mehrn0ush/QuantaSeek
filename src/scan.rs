//! Scan orchestration: resolve, connect, handshake, report.

use crate::handshake::HandshakeEngine;
use crate::http_redirect::{follow_redirects, RedirectOptions};
use crate::report::{ReportContext, ScanReport};
use crate::types::{ErrorCode, HandshakeConfig, HandshakeProfile, Inference, ScanError};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Ports tried, in order, when the target names none.
pub const DEFAULT_PORTS: &[u16] = &[443];

/// A scan target: host plus optional port, parsed from user input.
///
/// Accepts `host`, `host:port`, `[v6addr]:port`, `[v6addr]` and bare IPv6
/// literals (more than one colon, no brackets: no port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
}

impl Target {
    pub fn parse(input: &str) -> std::result::Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty target".to_string());
        }
        let parse_port = |p: &str| {
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("invalid port '{p}' in target '{input}'"))
        };
        if let Some(rest) = input.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("unclosed '[' in target '{input}'"))?;
            let port = match after {
                "" => None,
                _ => Some(parse_port(after.strip_prefix(':').ok_or_else(|| {
                    format!("unexpected text after ']' in '{input}'")
                })?)?),
            };
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!(
                    "'[{host}]' in target '{input}' is not an IPv6 address"
                ));
            }
            return Ok(Self {
                host: host.to_string(),
                port,
            });
        }
        match input.matches(':').count() {
            0 => Ok(Self {
                host: input.to_string(),
                port: None,
            }),
            1 => {
                let (host, port) = input.split_once(':').unwrap_or((input, ""));
                if host.is_empty() {
                    return Err(format!("missing host in target '{input}'"));
                }
                Ok(Self {
                    host: host.to_string(),
                    port: Some(parse_port(port)?),
                })
            }
            // Bare IPv6 literal without brackets: no port.
            _ if input.parse::<std::net::Ipv6Addr>().is_ok() => Ok(Self {
                host: input.to_string(),
                port: None,
            }),
            _ => Err(format!(
                "target '{input}' has several ':' but is not an IPv6 address; \
                 use [address]:port"
            )),
        }
    }
}

/// Turn a handshake error into a classified outcome.
///
/// Classification is by error type, not message text: rustls errors say what
/// the server sent; I/O errors say what happened to the connection.
pub fn classify_handshake_error(
    error: &anyhow::Error,
    profile: &HandshakeProfile,
    port: u16,
) -> ScanError {
    let offered = profile.offered_group_names().join(", ");
    let details = Some(format!(
        "port={}, profile={}, offered_groups=[{}]",
        port,
        profile.name(),
        offered
    ));
    let message = format!("{:#}", error);

    if let Some(tls) = error.downcast_ref::<rustls::Error>() {
        return match tls {
            rustls::Error::AlertReceived(alert) => {
                let mut e = ScanError::from_code_with_message(
                    ErrorCode::HandshakeRejected,
                    message,
                    details,
                );
                e.alert = Some(format!("{:?}", alert));
                if matches!(
                    alert,
                    rustls::AlertDescription::HandshakeFailure
                        | rustls::AlertDescription::InsufficientSecurity
                        | rustls::AlertDescription::IllegalParameter
                ) {
                    e.interpretation = Some(Inference::new(format!(
                        "The server aborted after our ClientHello offering [{}]. A common \
                         cause is that it supports none of these key-exchange groups, but \
                         this alert is also used for other negotiation failures (cipher \
                         suites, signature algorithms, versions). Per-group probing, which \
                         would confirm the cause, is not implemented.",
                        offered
                    )));
                }
                e
            }
            rustls::Error::InvalidCertificate(_) | rustls::Error::InvalidCertRevocationList(_) => {
                ScanError::from_code_with_message(ErrorCode::CertificateRejected, message, details)
            }
            rustls::Error::PeerIncompatible(_)
            | rustls::Error::PeerMisbehaved(_)
            | rustls::Error::InappropriateHandshakeMessage { .. }
            | rustls::Error::InappropriateMessage { .. }
            | rustls::Error::InvalidMessage(_) => {
                ScanError::from_code_with_message(ErrorCode::ProtocolError, message, details)
            }
            _ => ScanError::from_code_with_message(ErrorCode::HandshakeFailed, message, details),
        };
    }

    if let Some(io) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        use std::io::ErrorKind::*;
        let code = match io.kind() {
            TimedOut | WouldBlock => ErrorCode::HandshakeTimeout,
            UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => {
                ErrorCode::ConnectionClosed
            }
            _ => ErrorCode::HandshakeFailed,
        };
        return ScanError::from_code_with_message(code, message, details);
    }

    if message.contains("Connection closed during handshake") {
        return ScanError::from_code_with_message(ErrorCode::ConnectionClosed, message, details);
    }
    ScanError::from_code_with_message(ErrorCode::HandshakeFailed, message, details)
}

/// Run-wide scan settings.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Ports tried in order when the target names none.
    pub ports: Vec<u16>,
    /// Server name for SNI and certificate validation. `None` uses the target host.
    pub sni: Option<String>,
    /// Follow HTTP redirects after the handshake and report them separately.
    pub follow_redirects: bool,
    /// Connect to this address instead of resolving the target host
    /// (the host is still used for SNI). Like curl's --connect-to.
    pub connect_to: Option<SocketAddr>,
    pub connect_timeout: Duration,
    pub handshake: HandshakeConfig,
    /// Run per-group probes after the handshake (opt-in).
    pub probe: Option<crate::probe::ProbeOptions>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            sni: None,
            follow_redirects: false,
            connect_to: None,
            connect_timeout: Duration::from_secs(5),
            handshake: HandshakeConfig::default(),
            probe: None,
        }
    }
}

/// Classify a TCP connect failure.
fn classify_connect_error(error: &std::io::Error, details: String) -> ScanError {
    use std::io::ErrorKind::*;
    let code = match error.kind() {
        ConnectionRefused => ErrorCode::ConnectionRefused,
        TimedOut => ErrorCode::ConnectionTimeout,
        ConnectionReset => ErrorCode::ConnectionReset,
        PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::ConnectionFailed,
    };
    ScanError::from_code_with_message(code, error.to_string(), Some(details))
}

/// Resolve and connect, honouring `connect_to` and the connect timeout.
pub async fn try_connect(
    opts: &ScanOptions,
    host: &str,
    port: u16,
) -> Result<TcpStream, Box<ScanError>> {
    let details = format!("host={}, port={}", host, port);
    let addrs: Vec<SocketAddr> = match opts.connect_to {
        Some(addr) => vec![addr],
        None => match tokio::net::lookup_host((host, port)).await {
            Ok(a) => a.collect(),
            Err(e) => {
                return Err(Box::new(ScanError::from_code_with_message(
                    ErrorCode::DnsFailed,
                    e.to_string(),
                    Some(details),
                )))
            }
        },
    };
    if addrs.is_empty() {
        return Err(Box::new(ScanError::from_code_with_message(
            ErrorCode::DnsFailed,
            format!("{} resolved to no addresses", host),
            Some(details),
        )));
    }
    let mut last = None;
    for addr in addrs {
        match tokio::time::timeout(opts.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                last = Some(classify_connect_error(
                    &e,
                    format!("{}, address={}", details, addr),
                ))
            }
            Err(_) => {
                last = Some(ScanError::from_code_with_message(
                    ErrorCode::ConnectionTimeout,
                    format!("no TCP connection within {:?}", opts.connect_timeout),
                    Some(format!("{}, address={}", details, addr)),
                ))
            }
        }
    }
    Err(Box::new(last.unwrap_or_else(|| {
        ScanError::from_code(ErrorCode::Unknown, Some(details))
    })))
}

/// Scan one target with one profile: one TCP connection and one handshake per
/// port tried, stopping at the first port that accepts TCP.
pub async fn scan_target(
    opts: &ScanOptions,
    target: &str,
    profile: &HandshakeProfile,
) -> ScanReport {
    let started_at = chrono::Utc::now();
    let clock = Instant::now();
    let custom_trust_store = opts.handshake.trust_anchors.is_some();
    let ctx = |host: Option<&str>, port, server_name: Option<&str>, address: Option<String>| {
        ReportContext {
            input: target.to_string(),
            host: host.map(str::to_string),
            port,
            server_name: server_name.map(str::to_string),
            address,
            profile: *profile,
            custom_trust_store,
            redirects_requested: opts.follow_redirects,
            started_at,
            duration: clock.elapsed(),
        }
    };

    let parsed = match Target::parse(target) {
        Ok(t) => t,
        Err(e) => {
            let error = ScanError::from_code_with_message(ErrorCode::InvalidTarget, e, None);
            return ScanReport::build(
                ctx(None, None, None, None),
                None,
                None,
                Some(error),
                None,
                None,
            );
        }
    };
    let host = parsed.host.as_str();
    let server_name = opts.sni.as_deref().unwrap_or(host);
    let ports = match parsed.port {
        Some(port) => vec![port],
        None => opts.ports.clone(),
    };

    let mut last_error = None;
    for port in ports {
        let stream = match try_connect(opts, host, port).await {
            Ok(stream) => stream,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        let address = stream.peer_addr().ok().map(|a| a.to_string());
        tracing::info!(
            "connected to {} ({})",
            target,
            address.as_deref().unwrap_or("?")
        );
        let engine = HandshakeEngine::with_config(*profile, opts.handshake.clone());
        let handshake = engine.perform_handshake(stream, server_name).await;
        let probe = match &opts.probe {
            Some(probe_opts) => {
                Some(crate::probe::probe(opts, probe_opts, host, port, server_name).await)
            }
            None => None,
        };
        return match handshake {
            Ok(observation) => {
                let redirect = if opts.follow_redirects {
                    let redirect_opts = RedirectOptions {
                        trust_anchors: opts.handshake.trust_anchors.clone(),
                        ..RedirectOptions::default()
                    };
                    let start = match parsed.port {
                        Some(p) => format!("{}:{}", url_host(host), p),
                        None => url_host(host),
                    };
                    match follow_redirects(&start, &redirect_opts).await {
                        Ok(info) => Some(info),
                        Err(e) => {
                            tracing::warn!("redirect following failed for {}: {}", target, e);
                            None
                        }
                    }
                } else {
                    None
                };
                ScanReport::build(
                    ctx(Some(host), Some(port), Some(server_name), address),
                    Some(&observation),
                    None,
                    None,
                    redirect,
                    probe,
                )
            }
            Err(failure) => ScanReport::build(
                ctx(Some(host), Some(port), Some(server_name), address),
                None,
                Some(&failure.partial),
                Some(classify_handshake_error(&failure.error, profile, port)),
                None,
                probe,
            ),
        };
    }

    let error = last_error
        .map(|e| *e)
        .unwrap_or_else(|| ScanError::from_code(ErrorCode::Unknown, None));
    ScanReport::build(
        ctx(Some(host), None, Some(server_name), None),
        None,
        None,
        Some(error),
        None,
        None,
    )
}

/// Host as it appears in a URL authority (IPv6 literals bracketed).
fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

/// Scan several targets sequentially.
pub async fn scan_targets(
    opts: &ScanOptions,
    targets: &[String],
    profile: HandshakeProfile,
) -> Vec<ScanReport> {
    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        reports.push(scan_target(opts, target, &profile).await);
    }
    reports
}
