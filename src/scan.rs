//! Scan orchestration: connect, handshake, analyse.
//!
//! Moved out of `main.rs` so that tests can drive scans against local
//! servers. Behaviour is unchanged by the move.

use crate::{
    detector::PqcDetector,
    http_redirect::{follow_redirects, RedirectOptions},
    security_scoring::SecurityScorer,
    types::{
        ErrorCode, FallbackInfo, HandshakeConfig, Inference, PerformanceWarning, ScanError,
        ScanResult, SecurityScore, SecurityWarning, WarningLevel,
    },
    HandshakeEngine, HandshakeProfile,
};
use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpStream;

/// Ports probed for reachability, in order.
pub const DEFAULT_PORTS: &[u16] = &[443, 8443, 4433, 9443, 4443];

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
            _ => Ok(Self {
                host: input.to_string(),
                port: None,
            }),
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
    let message = error.to_string();

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
            rustls::Error::InvalidCertificate(_) => {
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
    pub ports: Vec<u16>,
    /// Server name for SNI and certificate validation. `None` uses the target host.
    pub sni: Option<String>,
    /// Follow HTTP redirects after the handshake and report them separately.
    pub follow_redirects: bool,
    pub connect_timeout: Duration,
    pub handshake: HandshakeConfig,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            sni: None,
            follow_redirects: false,
            connect_timeout: Duration::from_secs(5),
            handshake: HandshakeConfig::default(),
        }
    }
}

pub async fn scan_target(
    opts: &ScanOptions,
    target: &str,
    profile: &HandshakeProfile,
) -> Result<ScanResult> {
    let mut result = ScanResult::new(target.to_string());
    result.set_profile(profile.name());

    let parsed = Target::parse(target).map_err(|e| anyhow::anyhow!(e))?;
    let host = parsed.host.as_str();
    let ports_to_try = match parsed.port {
        Some(port) => vec![port],
        None => opts.ports.clone(),
    };

    let mut tried_ports = Vec::new();
    let mut last_error = None;
    for port in &ports_to_try {
        tried_ports.push(*port);
        match try_connect(opts, host, *port).await {
            Ok(stream) => {
                tracing::info!("  Connected to {}:{}", host, port);
                match perform_scan_with_stream(opts, stream, target, host, *port, profile).await {
                    Ok(scan_result) => {
                        result = scan_result;
                        result.fallback_strategy_used = Some("tcp_tls_only".to_string());
                        result.fallback_success = Some(true);
                    }
                    Err(e) => {
                        let error = classify_handshake_error(&e, profile, *port);
                        result.security_warnings.push(SecurityWarning {
                            message: format!("Scan failed: {}", error.message),
                            level: WarningLevel::Critical,
                            category: "Handshake".to_string(),
                            recommendation: None,
                        });
                        result.error = Some(error);
                    }
                }
                return Ok(result);
            }
            Err(e) => last_error = Some(e),
        }
    }

    // No port accepted a TCP connection.
    let ports_tried = tried_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let (code, message) = match last_error {
        Some(error) => {
            let text = error.to_string();
            let code = if text.contains("refused") {
                ErrorCode::ConnectionRefused
            } else if text.contains("timeout") {
                ErrorCode::ConnectionTimeout
            } else if text.contains("dns") || text.contains("not found") {
                ErrorCode::DnsFailed
            } else if text.contains("reset") {
                ErrorCode::ConnectionReset
            } else if text.contains("permission") {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::ConnectionFailed
            };
            (code, text)
        }
        None => (ErrorCode::Unknown, "Unknown connection error".to_string()),
    };
    result.security_warnings.push(SecurityWarning {
        level: WarningLevel::Critical,
        category: "Connection".to_string(),
        message: format!(
            "Scan failed: {} - {} (tried ports: {})",
            code.default_message(),
            message,
            ports_tried
        ),
        recommendation: None,
    });
    result.error = Some(ScanError::from_code_with_message(
        code,
        message,
        Some(format!("ports_tried={}", ports_tried)),
    ));
    result.fallback_strategy_used = Some("ports_and_profile_chain".to_string());
    result.fallback_success = Some(false);
    Ok(result)
}

pub async fn try_connect(
    opts: &ScanOptions,
    hostname: &str,
    port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let timeout = opts.connect_timeout;

    match tokio::time::timeout(timeout, TcpStream::connect((hostname, port))).await {
        Ok(Ok(stream)) => {
            // Set TCP options for better performance
            stream.set_nodelay(true)?;
            Ok(stream)
        }
        Ok(Err(e)) => {
            // Provide more specific error messages
            let error_msg = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    format!("Connection refused on port {}", port)
                }
                std::io::ErrorKind::TimedOut => format!("Connection timeout on port {}", port),
                std::io::ErrorKind::NotFound => format!("Hostname '{}' not found", hostname),
                std::io::ErrorKind::PermissionDenied => {
                    format!("Permission denied connecting to port {}", port)
                }
                _ => format!("Connection failed: {}", e),
            };
            Err(error_msg.into())
        }
        Err(_) => Err(format!("Connection timeout on port {}", port).into()),
    }
}

/// One handshake on `host:port` with the profile's ClientHello, then analysis.
///
/// The TCP stream from the reachability probe is dropped; the handshake uses
/// a fresh connection to the same port.
pub async fn perform_scan_with_stream(
    opts: &ScanOptions,
    _stream: TcpStream,
    target: &str,
    host: &str,
    port: u16,
    profile: &HandshakeProfile,
) -> anyhow::Result<ScanResult> {
    let scan_start = std::time::Instant::now();
    let server_name = opts.sni.as_deref().unwrap_or(host);
    let engine = HandshakeEngine::with_config(*profile, opts.handshake.clone());
    let stream = try_connect(opts, host, port)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let handshake_result = engine.perform_handshake(stream, server_name).await?;

    let detector = PqcDetector::new();
    let analysis = detector.analyze_handshake(&handshake_result);

    // One profile, one handshake: there is no profile fallback chain.
    let fallback = FallbackInfo {
        enabled: false,
        used: false,
        attempts_count: 0,
        attempted_profiles: Vec::new(),
        fallback_penalty_ms: None,
        tls12_fallback: None,
    };

    let scorer = SecurityScorer::new();
    let mut scan_result = ScanResult {
        target: target.to_string(),
        tls_version: handshake_result.tls_version.clone(),
        cipher_suite: handshake_result.cipher_suite.clone(),
        key_exchange: handshake_result.key_exchange.clone(),
        certificate: handshake_result.certificate_info.clone(),
        certificate_visible: handshake_result.certificate_visible,
        handshake_complete: handshake_result.handshake_complete,
        handshake_duration_ms: handshake_result.handshake_duration_ms,
        pqc_detected: analysis.pqc_detected,
        pqc_extensions: handshake_result.pqc_extensions.clone(),
        extension_map: handshake_result.extension_map.clone(),
        tls_features: handshake_result.tls_features.clone(),
        analysis: analysis.clone(),
        client_profile_used: profile.name().to_string(),
        adaptive_fingerprinting: false,
        server_fingerprint: None,
        fallback: fallback.clone(),
        security_score: SecurityScore::default(), // will set below
        security_warnings: vec![],                // will set below
        performance_warnings: vec![],
        total_scan_duration_ms: None,
        raw_server_hello: handshake_result.raw_server_hello.clone(),
        http_redirect: None,
        connection_type: handshake_result.connection_type.clone(),
        cipher_suite_reason: handshake_result.cipher_suite_reason.clone(),
        fallback_strategy_used: None,
        fallback_success: None,
        quic_only_server_detected: None,
        error: None,
    };

    scan_result.security_score = scorer.calculate_security_score(&scan_result);
    scan_result.security_warnings = scorer.generate_security_warnings(&scan_result.security_score);

    // Detect HTTP redirects after handshake (for both TLS and QUIC)
    if scan_result.handshake_complete && opts.follow_redirects {
        let redirect_opts = RedirectOptions {
            trust_anchors: opts.handshake.trust_anchors.clone(),
            ..RedirectOptions::default()
        };
        // Reported in http_redirect only: the target's own certificate and
        // analysis are never replaced by the destination's.
        match follow_redirects(target, &redirect_opts).await {
            Ok(redirect_info) => scan_result.http_redirect = Some(redirect_info),
            Err(e) => tracing::debug!("HTTP redirect following failed for {}: {}", target, e),
        }
    }

    let total_scan_duration = scan_start.elapsed();
    scan_result.total_scan_duration_ms = Some(total_scan_duration.as_millis() as u64);

    Ok(scan_result)
}

pub async fn scan_multiple_targets(
    opts: &ScanOptions,
    targets: &[String],
    profile: HandshakeProfile,
) -> Result<Vec<ScanResult>> {
    let mut results = Vec::new();
    let mut successful_count = 0;
    let mut failed_count = 0;
    let start_time = std::time::Instant::now();

    for target in targets {
        tracing::info!("Scanning: {}", target);

        match scan_target(opts, target, &profile).await {
            // Enable TLS 1.2 fallback for batch scans
            Ok(mut result) => {
                // Add performance analysis and recommendations for batch results
                if result.handshake_complete {
                    successful_count += 1;

                    // Add performance warnings if needed
                    if let Some(duration) = result.handshake_duration_ms {
                        if duration > 1000 {
                            result.performance_warnings.push(PerformanceWarning {
                                level: WarningLevel::Warning,
                                category: "Handshake Performance".to_string(),
                                message: format!("Slow handshake detected: {}ms", duration),
                                impact: "Slow handshakes may impact user experience".to_string(),
                                recommendation: Some(
                                    "Consider optimizing TLS configuration".to_string(),
                                ),
                            });
                        }
                    }

                    // Add TLS 1.3 limitations warning if applicable
                    if result.tls_version == "1.3" && !result.certificate_visible {
                        result.security_warnings.push(SecurityWarning {
                            level: WarningLevel::Info,
                            category: "TLS 1.3 Limitations".to_string(),
                            message: "Certificate information is encrypted in TLS 1.3".to_string(),
                            recommendation: Some(
                                "Consider TLS 1.2 for certificate analysis".to_string(),
                            ),
                        });
                    }

                    // Add PQC signature limitations warning
                    if result.tls_version == "1.3"
                        && result.analysis.pqc_signature_algorithms.is_empty()
                    {
                        result.security_warnings.push(SecurityWarning {
                            level: WarningLevel::Info,
                            category: "PQC Signature Detection".to_string(),
                            message:
                                "PQC signature algorithms not visible due to TLS 1.3 encryption"
                                    .to_string(),
                            recommendation: Some(
                                "Use Certificate Transparency logs for signature analysis"
                                    .to_string(),
                            ),
                        });
                    }
                } else {
                    failed_count += 1;
                }
                results.push(result);
                tracing::info!("✅ Completed: {}", target);
            }
            Err(e) => {
                failed_count += 1;
                tracing::info!("❌ Failed: {} - {}", target, e);

                // Create a failed result for consistency
                let mut failed_result = ScanResult::new(target.clone());
                // FIXED: Set profile for failed scans so they don't show "Unknown"
                failed_result.set_profile(profile.name());
                failed_result.handshake_complete = false;
                failed_result.security_warnings = vec![SecurityWarning {
                    message: format!("Scan failed: {}", e),
                    level: WarningLevel::Critical,
                    category: "Connection".to_string(),
                    recommendation: None,
                }];
                failed_result.error = Some(ScanError::from_code_with_message(
                    ErrorCode::ScanFailed,
                    e.to_string(),
                    None,
                ));
                results.push(failed_result);
            }
        }
    }

    let total_duration = start_time.elapsed();

    // Print summary
    tracing::info!("\n📊 Scan Summary:");
    tracing::info!("  Total targets: {}", targets.len());
    tracing::info!(
        "  Successful: {} ({:.1}%)",
        successful_count,
        (successful_count as f64 / targets.len() as f64) * 100.0
    );
    tracing::info!(
        "  Failed: {} ({:.1}%)",
        failed_count,
        (failed_count as f64 / targets.len() as f64) * 100.0
    );
    tracing::info!("  Total duration: {:.2}s", total_duration.as_secs_f64());

    if successful_count > 0 {
        let avg_duration: f64 = results
            .iter()
            .filter_map(|r| r.handshake_duration_ms)
            .map(|d| d as f64)
            .sum::<f64>()
            / successful_count as f64;
        tracing::info!("  Average handshake time: {:.1}ms", avg_duration);

        let total_scan_time = total_duration.as_secs_f64();
        let scans_per_second = successful_count as f64 / total_scan_time;
        tracing::info!("  Throughput: {:.2} scans/second", scans_per_second);

        let pqc_detected = results.iter().filter(|r| r.pqc_detected).count();
        let hybrid_detected = results
            .iter()
            .filter(|r| r.analysis.hybrid_detected)
            .count();
        let pqc_signatures_used = results
            .iter()
            .filter(|r| r.analysis.pqc_signature_used == Some(true))
            .count();

        tracing::info!(
            "  PQC detected: {} ({:.1}%)",
            pqc_detected,
            (pqc_detected as f64 / successful_count as f64) * 100.0
        );
        tracing::info!(
            "  Hybrid mode: {} ({:.1}%)",
            hybrid_detected,
            (hybrid_detected as f64 / successful_count as f64) * 100.0
        );
        tracing::info!(
            "  PQC signatures used: {} ({:.1}%)",
            pqc_signatures_used,
            (pqc_signatures_used as f64 / successful_count as f64) * 100.0
        );

        let certificates_visible = results.iter().filter(|r| r.certificate_visible).count();
        let certificates_analyzed = results.iter().filter(|r| r.certificate.is_some()).count();

        tracing::info!(
            "  Certificates visible: {} ({:.1}%)",
            certificates_visible,
            (certificates_visible as f64 / successful_count as f64) * 100.0
        );
        tracing::info!(
            "  Certificates analyzed: {} ({:.1}%)",
            certificates_analyzed,
            (certificates_analyzed as f64 / successful_count as f64) * 100.0
        );

        let mut tls_versions = std::collections::HashMap::new();
        for result in &results {
            if result.handshake_complete {
                *tls_versions.entry(result.tls_version.clone()).or_insert(0) += 1;
            }
        }

        if !tls_versions.is_empty() {
            tracing::info!("  TLS version distribution:");
            for (version, count) in tls_versions {
                tracing::info!(
                    "    {}: {} servers ({:.1}%)",
                    version,
                    count,
                    (count as f64 / successful_count as f64) * 100.0
                );
            }
        }

        let mut profile_usage = std::collections::HashMap::new();
        for result in &results {
            if result.handshake_complete {
                *profile_usage
                    .entry(result.client_profile_used.clone())
                    .or_insert(0) += 1;
            }
        }

        if !profile_usage.is_empty() {
            tracing::info!("  Client profiles used:");
            for (profile, count) in profile_usage {
                tracing::info!("    {}: {} servers", profile, count);
            }
        }

        let mut algorithms = std::collections::HashMap::new();
        for result in &results {
            if result.handshake_complete {
                for kex in &result.analysis.pqc_key_exchange {
                    *algorithms.entry(kex.clone()).or_insert(0) += 1;
                }
                for kex in &result.key_exchange {
                    if !result.analysis.pqc_key_exchange.contains(kex) {
                        *algorithms.entry(kex.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        if !algorithms.is_empty() {
            tracing::info!("  Key exchange algorithms:");
            for (algo, count) in algorithms {
                tracing::info!("    {}: {} servers", algo, count);
            }
        }

        let mut signature_algorithms = std::collections::HashMap::new();
        for result in &results {
            if result.handshake_complete {
                for sig in &result.analysis.pqc_signature_algorithms {
                    *signature_algorithms.entry(sig.clone()).or_insert(0) += 1;
                }
            }
        }

        if !signature_algorithms.is_empty() {
            tracing::info!("  PQC signature algorithms:");
            for (sig, count) in signature_algorithms {
                tracing::info!("    {}: {} servers", sig, count);
            }
        }
    }

    Ok(results)
}
