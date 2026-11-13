//! Scan orchestration: connect, handshake, analyse.
//!
//! Moved out of `main.rs` so that tests can drive scans against local
//! servers. Behaviour is unchanged by the move.

use crate::{
    detector::PqcDetector,
    http_redirect::{follow_redirects, RedirectOptions},
    security_scoring::SecurityScorer,
    types::{
        ClientProfile, ErrorCode, FallbackInfo, HandshakeConfig, PerformanceWarning, ScanError,
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
    profile: &ClientProfile,
) -> Result<ScanResult> {
    let mut result = ScanResult::new(target.to_string());
    result.set_profile(profile.consistent_display_name());

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
                        result.security_warnings.push(SecurityWarning {
                            message: format!("Scan failed: {}", e),
                            level: WarningLevel::Critical,
                            category: "Handshake".to_string(),
                            recommendation: None,
                        });
                        result.error = Some(ScanError::from_code_with_message(
                            ErrorCode::HandshakeFailed,
                            e.to_string(),
                            Some(format!("port={}", port)),
                        ));
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

/// IMPROVED: Profile-based fallback strategy implementation
/// Each profile has a specific fallback chain:
/// - Fallback: MaxPQC → Hybrid → Classical (TLS 1.2)
/// - Hybrid: Hybrid → Classical (TLS 1.2)
/// - Classic: Classical only (TLS 1.2)
/// - MaxPQC: PQC-only → Hybrid → Classical (TLS 1.2)
pub async fn perform_scan_with_stream(
    opts: &ScanOptions,
    _stream: TcpStream,
    target: &str,
    host: &str,
    port: u16,
    profile: &ClientProfile,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let scan_start = std::time::Instant::now();
    let server_name = opts.sni.as_deref().unwrap_or(host);

    // Define fallback chain for each profile
    let fallback_chain = match profile {
        ClientProfile::Fallback => vec![
            HandshakeProfile::PqcOnly,   // Try MaxPQC first
            HandshakeProfile::HybridPqc, // Then Hybrid
            HandshakeProfile::Standard,  // Finally Classical (TLS 1.2)
        ],
        ClientProfile::Hybrid => vec![
            HandshakeProfile::HybridPqc, // Try Hybrid first
            HandshakeProfile::Standard,  // Then Classical (TLS 1.2)
        ],
        ClientProfile::Classic => vec![
            HandshakeProfile::Standard, // Only Classical (TLS 1.2)
        ],
        ClientProfile::MaxPqc => vec![
            HandshakeProfile::PqcOnly,   // Try PQC-only first
            HandshakeProfile::HybridPqc, // Then Hybrid
            HandshakeProfile::Standard,  // Finally Classical (TLS 1.2)
        ],
    };

    let mut attempted_profiles = Vec::new();
    let mut last_error = None;
    let mut handshake_result = None;

    // FIXED: Try each profile in the fallback chain with proper TLS 1.2 handling
    for (attempt_idx, fallback_profile) in fallback_chain.iter().enumerate() {
        attempted_profiles.push(format!("{:?}", fallback_profile));

        // FIXED: For Standard profile, use perform_handshake to capture raw_server_hello
        // Standard profile = TLS 1.2 only, but we still need raw_server_hello for analysis
        let handshake_attempt = if *fallback_profile == HandshakeProfile::Standard {
            // Standard profile = TLS 1.2 only
            let handshake = HandshakeEngine::with_config(*fallback_profile, opts.handshake.clone());

            // FIXED: Use perform_handshake instead of perform_tcp_tls_handshake to capture raw_server_hello
            // This ensures raw_server_hello is populated even for Classic profile
            match try_connect(opts, host, port).await {
                Ok(stream) => handshake.perform_handshake(stream, server_name).await,
                Err(e) => {
                    last_error = Some(e.to_string());
                    if attempt_idx < fallback_chain.len() - 1 {
                        continue; // Try next profile
                    } else {
                        return Err(format!("Connection failed: {}", e).into());
                    }
                }
            }
        } else {
            // For PQC profiles, use normal TLS 1.3 handshake
            let handshake = HandshakeEngine::with_config(*fallback_profile, opts.handshake.clone());

            // Try to perform handshake with this profile
            // Always create a new connection for each attempt to avoid ownership issues
            match try_connect(opts, host, port).await {
                Ok(new_stream) => handshake.perform_handshake(new_stream, server_name).await,
                Err(e) => {
                    last_error = Some(e.to_string());
                    if attempt_idx < fallback_chain.len() - 1 {
                        continue; // Try next profile
                    } else {
                        return Err(format!(
                            "Connection failed for all profiles. Last error: {}",
                            e
                        )
                        .into());
                    }
                }
            }
        };

        match handshake_attempt {
            Ok(result) => {
                // Handshake succeeded with this profile
                handshake_result = Some(result);
                break; // Success - no need to try next profile
            }
            Err(e) => {
                // Handshake failed - try next profile in chain
                last_error = Some(e.to_string());
                if attempt_idx < fallback_chain.len() - 1 {
                    // There are more profiles to try
                    continue;
                } else {
                    // This was the last profile - all attempts failed
                    return Err(format!("All handshake attempts failed. Last error: {}", e).into());
                }
            }
        }
    }

    // If we get here, handshake succeeded (or we'll return error above)
    let handshake_result = handshake_result.ok_or_else(|| {
        format!(
            "Handshake failed for all profiles. Last error: {:?}",
            last_error
        )
    })?;

    let detector = PqcDetector::new();
    let analysis = detector.analyze_handshake(&handshake_result);

    // FIXED: Separate profile fallback from TLS 1.2 fallback
    // Profile fallback: trying different client profiles (MaxPQC → Hybrid → Classical)
    let profile_fallback_used = attempted_profiles.len() > 1;
    let profile_fallback_enabled = *profile != ClientProfile::Classic; // Fallback is enabled for non-Classic profiles

    // FIXED: attempts_count should only count actual fallback attempts (excluding initial)
    let profile_fallback_attempts_count = if attempted_profiles.len() > 1 {
        (attempted_profiles.len() - 1) as u32
    } else {
        0
    };

    // Only populate attempted_profiles if fallback was actually used
    let attempted_profiles_list = if profile_fallback_used {
        attempted_profiles
            .iter()
            .map(|p| match p.as_str() {
                "PqcOnly" => "MaxPQC".to_string(),
                "HybridPqc" => "Hybrid".to_string(),
                "Standard" => "Classical".to_string(),
                "CloudflarePqc" => "Fallback".to_string(),
                _ => p.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    let fallback = FallbackInfo {
        enabled: profile_fallback_enabled,
        used: profile_fallback_used,
        attempts_count: profile_fallback_attempts_count,
        attempted_profiles: attempted_profiles_list,
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
        client_profile_used: profile.consistent_display_name().to_string(),
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
    profile: ClientProfile,
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
                failed_result.set_profile(profile.consistent_display_name());
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
