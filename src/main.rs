use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use quanta_seek::{
    detector::PqcDetector,
    http_redirect::detect_http_redirects,
    output::output_results,
    security_scoring::SecurityScorer,
    types::{
        ClientProfile, FallbackInfo, HandshakeResult, OutputFormat, PerformanceWarning, ScanResult,
        SecurityScore, SecurityWarning, WarningLevel,
    },
    HandshakeEngine, HandshakeProfile,
};
use std::str::FromStr;
use std::time::Instant;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    // In rustls 0.23, ensure crypto provider is set at process startup
    // This is required for prefer-post-quantum feature to work
    use rustls::crypto::aws_lc_rs::default_provider;
    let _ = default_provider().install_default();
    let matches = Command::new("QuantaSeek")
        .version("0.1.0")
        .about("PQC-aware TLS scanner")
        .arg(
            Arg::new("targets")
                .help("Target hostnames (e.g., example.com:443, google.com)")
                .required(true)
                .num_args(1..)
                .value_delimiter(','),
        )
        .arg(
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Handshake profile to use")
                .value_parser(HandshakeProfile::from_str)
                .default_value("cloudflare-pqc"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Output format")
                .value_parser(["json", "text"])
                .default_value("json"),
        )
        .arg(
            Arg::new("tls12")
                .long("tls12")
                .help("Enable TLS 1.2 fallback for certificate analysis")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ignore-mismatch")
                .long("ignore-mismatch")
                .help("Ignore hostname mismatch for experimental servers")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Suppress banner, progress lines, and summary; only print result (JSON/text)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable debug and progress messages (QUIC fallback, HTTP redirect, etc.)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Clap validates required arguments, so this should never fail
    // But we handle it gracefully for better error messages
    let targets: Vec<String> = matches
        .get_many::<String>("targets")
        .ok_or_else(|| anyhow!("No targets specified"))?
        .cloned()
        .collect();

    // Parse profile - FIXED: Use FromStr to fail fast on invalid profiles
    let handshake_profile = matches
        .get_one::<HandshakeProfile>("profile")
        .ok_or_else(|| anyhow::anyhow!("Invalid profile specified"))?;

    // Convert HandshakeProfile to ClientProfile for backward compatibility
    let profile = match handshake_profile {
        HandshakeProfile::Standard => ClientProfile::Classic,
        HandshakeProfile::CloudflarePqc => ClientProfile::Fallback,
        HandshakeProfile::HybridPqc => ClientProfile::Hybrid,
        HandshakeProfile::PqcOnly => ClientProfile::MaxPqc,
    };

    // Format has a default value, so this should never fail
    let format_str = matches
        .get_one::<String>("format")
        .ok_or_else(|| anyhow!("Format not specified"))?;
    let tls12_enabled = matches.get_flag("tls12");
    let ignore_mismatch = matches.get_flag("ignore-mismatch");
    let quiet = matches.get_flag("quiet");
    let verbose_flag = matches.get_flag("verbose");
    if verbose_flag {
        std::env::set_var("QUANTASEEK_DEBUG", "1");
    }

    // Parse output format
    let format = match format_str.as_str() {
        "json" => OutputFormat::Json,
        "text" => OutputFormat::Text,
        _ => OutputFormat::Json, // Default fallback
    };

    if !quiet {
        println!("🔍 QuantaSeek PQC TLS Scanner");
        println!("Targets: {}", targets.join(", "));
        println!("Profile: {}", profile.display_name());
        println!("Format: {:?}", format);
        if tls12_enabled && profile != ClientProfile::Classic {
            println!("TLS 1.2 Fallback: Enabled (available if TLS 1.3 fails)");
        }
        println!("═══════════════════════════");
    }

    // Start timing the complete scan
    let scan_start = Instant::now();

    if targets.len() == 1 {
        // Single target mode
        let target = &targets[0];
        let result = scan_target(target, &profile, tls12_enabled, ignore_mismatch, quiet).await?;
        output_results(&result, format);
    } else {
        // Batch mode
        let results = scan_multiple_targets(&targets, profile, &format, quiet).await?;

        // Calculate total scan duration
        let total_scan_duration = scan_start.elapsed();

        // Output batch results
        output_batch_results(&results, &format, total_scan_duration);
    }

    Ok(())
}

async fn scan_target(
    target: &str,
    profile: &ClientProfile,
    tls12_enabled: bool,
    _ignore_mismatch: bool,
    quiet: bool,
) -> Result<ScanResult> {
    let mut result = ScanResult::new(target.to_string());
    // FIXED: Set profile immediately so failed scans don't show "Unknown"
    result.set_profile(&profile.consistent_display_name());

    // Try multiple DNS resolution strategies
    let mut connection_success = false;
    let mut last_error = None;
    let mut tried_ports = Vec::new();

    // IMPROVED: Enhanced connection strategy with better port detection
    let is_experimental = detect_quic_server(target).await;

    // Try QUIC first for experimental servers
    if is_experimental {
        if !quiet {
            println!("  Attempting QUIC handshake for experimental server...");
        }
        let quic_scan_start = Instant::now();
        let handshake = HandshakeEngine::new_optimized(profile.to_handshake_profile());
        match handshake.perform_quic_handshake(target, 443).await {
            Ok(quic_result) => {
                if !quiet {
                    println!("  QUIC handshake successful!");
                }
                // Convert HandshakeResult -> ScanResult
                let mut scan_result = ScanResult::new(target.to_string());
                scan_result.update_from_handshake(quic_result);
                // raw_server_hello is already copied in update_from_handshake

                let mut certificate_replaced = false;

                // Detect HTTP redirects after handshake
                if scan_result.handshake_complete {
                    match detect_http_redirects(target, 10).await {
                        Ok(redirect_info) => {
                            if redirect_info.detected {
                                if quanta_seek::verbose() {
                                    eprintln!("  [DEBUG] HTTP redirect detected for {} (QUIC): status={:?}, chain={:?}", 
                                        target, redirect_info.status_code, redirect_info.redirect_chain);
                                }
                                scan_result.http_redirect = Some(redirect_info.clone());
                                // Use final destination certificate if different
                                if let Some(ref final_cert) =
                                    redirect_info.final_destination_certificate
                                {
                                    let should_replace = scan_result
                                        .certificate
                                        .as_ref()
                                        .map(|initial_cert| {
                                            initial_cert.subject != final_cert.subject
                                                || initial_cert.issuer != final_cert.issuer
                                        })
                                        .unwrap_or(true);
                                    if should_replace {
                                        scan_result.certificate = Some(final_cert.clone());
                                        certificate_replaced = true;
                                        // Re-analyze with new certificate
                                        let detector = PqcDetector::new();
                                        let handshake_result = HandshakeResult {
                                            target: target.to_string(),
                                            tls_version: scan_result.tls_version.clone(),
                                            cipher_suite: scan_result.cipher_suite.clone(),
                                            key_exchange: scan_result.key_exchange.clone(),
                                            pqc_extensions: scan_result.pqc_extensions.clone(),
                                            certificate_info: scan_result.certificate.clone(),
                                            raw_server_hello: scan_result.raw_server_hello.clone(),
                                            raw_certificate: Vec::new(),
                                            alert_info: None,
                                            certificate_visible: scan_result.certificate_visible,
                                            handshake_complete: scan_result.handshake_complete,
                                            pqc_signature_algorithms: Vec::new(),
                                            pqc_signature_used: None,
                                            tls_features: scan_result.tls_features.clone(),
                                            handshake_duration_ms: scan_result
                                                .handshake_duration_ms,
                                            client_profile_used: HandshakeProfile::Standard,
                                            extension_map: scan_result.extension_map.clone(),
                                            connection_type: scan_result.connection_type.clone(),
                                            cipher_suite_reason: scan_result
                                                .cipher_suite_reason
                                                .clone(),
                                        };
                                        let updated_analysis =
                                            detector.analyze_handshake(&handshake_result);
                                        scan_result.analysis = updated_analysis;
                                        // Recalculate security score with new certificate
                                        let scorer = SecurityScorer::new();
                                        scan_result.security_score =
                                            scorer.calculate_security_score(&scan_result);
                                        scan_result.security_warnings = scorer
                                            .generate_security_warnings(
                                                &scan_result.security_score,
                                            );
                                    }
                                }
                            } else {
                                if quanta_seek::verbose() {
                                    eprintln!(
                                        "  [DEBUG] No HTTP redirect detected for {} (QUIC)",
                                        target
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            if quanta_seek::verbose() {
                                eprintln!(
                                    "  [DEBUG] HTTP redirect detection failed for {} (QUIC): {}",
                                    target, e
                                );
                            }
                        }
                    }
                } else {
                    if quanta_seek::verbose() {
                        eprintln!("  [DEBUG] Skipping HTTP redirect detection (QUIC): handshake not complete for {}", target);
                    }
                }

                // Calculate security score (recalculate if certificate was replaced)
                let scorer = SecurityScorer::new();
                scan_result.security_score = scorer.calculate_security_score(&scan_result);
                scan_result.security_warnings =
                    scorer.generate_security_warnings(&scan_result.security_score);
                // FIXED: Set total_scan_duration_ms for QUIC
                let total_scan_duration = quic_scan_start.elapsed();
                scan_result.total_scan_duration_ms = Some(total_scan_duration.as_millis() as u64);
                return Ok(scan_result);
            }
            Err(e) => {
                if !quiet {
                    println!("  QUIC handshake failed: {}, falling back to TLS", e);
                }
                // Continue with TLS fallback
            }
        }
    }

    let ports_to_try = if is_experimental {
        try_alternative_ports(target).await
    } else {
        vec![443, 8443, 4433, 9443, 4443]
    };

    for port in ports_to_try.iter() {
        tried_ports.push(*port);
        match try_connect(target, *port).await {
            Ok(stream) => {
                connection_success = true;
                if !quiet {
                    println!("  Connected to {}:{}", target, port);
                }

                // FIXED: Use the actual provided profile instead of overriding
                let actual_profile = *profile;

                match perform_scan_with_stream(stream, target, &actual_profile, tls12_enabled).await
                {
                    Ok(scan_result) => result = scan_result,
                    Err(e) => {
                        result.security_warnings.push(SecurityWarning {
                            message: format!("Scan failed: {}", e),
                            level: WarningLevel::Critical,
                            category: "Handshake".to_string(),
                            recommendation: Some(
                                "Check if the server supports the requested TLS configuration."
                                    .to_string(),
                            ),
                        });
                        last_error = Some(e);
                    }
                }
                break;
            }
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        }
    }

    // Strategy 2: Try additional ports for experimental servers
    if !connection_success && is_experimental {
        let additional_ports = [853, 8530, 8531, 8532, 8533, 8534, 8535, 10443];
        for port in additional_ports.iter() {
            tried_ports.push(*port);
            match try_connect(target, *port).await {
                Ok(stream) => {
                    connection_success = true;
                    if !quiet {
                        println!("  Connected to {}:{} (PQC port)", target, port);
                    }
                    match perform_scan_with_stream(stream, target, profile, tls12_enabled).await {
                        Ok(scan_result) => result = scan_result,
                        Err(e) => {
                            result.security_warnings.push(SecurityWarning {
                                level: WarningLevel::Critical,
                                category: "Handshake".to_string(),
                                message: format!("Handshake failed on PQC port {}: {}", port, e),
                                recommendation: Some(
                                    "Server may not support PQC on this port".to_string(),
                                ),
                            });
                        }
                    }
                    break;
                }
                Err(e) => {
                    last_error = Some(format!("PQC Port {}: {}", port, e).into());
                }
            }
        }
    }

    // If all connection attempts failed
    if !connection_success {
        let ports_tried = tried_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // IMPROVED: More detailed error analysis
        let error_msg = if let Some(ref error) = last_error {
            let error_str = error.to_string();
            if error_str.contains("refused") {
                "Connection refused - server may be offline or not listening on TLS ports"
            } else if error_str.contains("timeout") {
                "Connection timeout - server may be slow or overloaded"
            } else if error_str.contains("dns") || error_str.contains("not found") {
                "DNS resolution failed - check hostname spelling"
            } else if error_str.contains("reset") {
                "Connection reset - server may not support the requested TLS configuration"
            } else if error_str.contains("permission") {
                "Permission denied - may need elevated privileges"
            } else {
                // For unknown errors, use a generic message
                "Connection failed - unknown error"
            }
        } else {
            "Unknown connection error"
        };

        // IMPROVED: Better error reporting with detailed QUIC detection
        let is_quic_likely = detect_quic_server(target).await;
        let quic_support_detected = test_quic_support(target).await;

        let (error_details, recommendation) = if quic_support_detected {
            ("QUIC support detected but TLS connection failed", 
             "This server supports QUIC but not TLS. Try using curl with --http3 or a QUIC-enabled client. For PQC testing, consider using a different server or protocol.")
        } else if is_quic_likely {
            ("Server appears to be QUIC-only or experimental", 
             "This server appears to be QUIC-only or experimental. Try using curl with --http3 or check if the server supports TLS connections. For PQC testing, consider using a different server or protocol.")
        } else {
            ("Standard TLS connection failed", 
             "Try with different profiles (standard, cloudflare-pqc) or check if server supports PQC/TLS 1.3. For experimental servers, try ports 853, 4433.")
        };

        result.security_warnings.push(SecurityWarning {
            level: WarningLevel::Critical,
            category: "Connection".to_string(),
            message: format!(
                "Scan failed: {} - {} (tried ports: {})",
                error_details, error_msg, ports_tried
            ),
            recommendation: Some(recommendation.to_string()),
        });
    }

    Ok(result)
}

async fn try_connect(hostname: &str, port: u16) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", hostname, port);

    // Try with shorter timeout for faster scanning
    match tokio::time::timeout(
        std::time::Duration::from_secs(5), // Reduced from 10 to 5 seconds
        TcpStream::connect(&addr),
    )
    .await
    {
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

/// IMPROVED: Detect if server might be QUIC-only
async fn detect_quic_server(hostname: &str) -> bool {
    // Check for common QUIC indicators in hostname
    let quic_indicators = ["quic", "http3", "h3", "udp", "s2n-quic"];
    let hostname_lower = hostname.to_lowercase();

    for indicator in &quic_indicators {
        if hostname_lower.contains(indicator) {
            return true;
        }
    }

    // Check for experimental PQC domains that might be QUIC-only
    let experimental_quic_domains = ["oqstest.net", "quantumtls.com", "pqkd.aws", "duckdns.org"];

    for domain in &experimental_quic_domains {
        if hostname_lower.contains(domain) {
            return true;
        }
    }

    false
}

/// IMPROVED: Direct QUIC detection by attempting UDP connections
async fn test_quic_support(hostname: &str) -> bool {
    let quic_ports = [443, 853, 4433, 8443];

    for port in &quic_ports {
        // Try to establish a UDP connection (basic QUIC detection)
        if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            let addr = format!("{}:{}", hostname, port);
            if let Ok(_) = socket.connect(&addr).await {
                // If we can connect via UDP, the server might support QUIC
                return true;
            }
        }
    }

    false
}

/// IMPROVED: Try alternative ports for experimental servers
async fn try_alternative_ports(_hostname: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    // Standard TLS ports
    ports.extend_from_slice(&[443, 8443, 4433, 9443, 4443]);

    // PQC-specific ports
    ports.extend_from_slice(&[853, 8530, 8531, 8532, 8533, 8534, 8535]);

    // Experimental ports
    ports.extend_from_slice(&[4443, 8443, 9443, 10443]);

    // Remove duplicates while preserving order
    let mut unique_ports = Vec::new();
    for port in ports {
        if !unique_ports.contains(&port) {
            unique_ports.push(port);
        }
    }

    unique_ports
}

/// IMPROVED: Profile-based fallback strategy implementation
/// Each profile has a specific fallback chain:
/// - Fallback: MaxPQC → Hybrid → Classical (TLS 1.2)
/// - Hybrid: Hybrid → Classical (TLS 1.2)
/// - Classic: Classical only (TLS 1.2)
/// - MaxPQC: PQC-only → Hybrid → Classical (TLS 1.2)
async fn perform_scan_with_stream(
    _stream: TcpStream,
    target: &str,
    profile: &ClientProfile,
    tls12_enabled: bool,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let scan_start = std::time::Instant::now();

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
    let mut final_profile = profile.to_handshake_profile();

    // FIXED: Try each profile in the fallback chain with proper TLS 1.2 handling
    for (attempt_idx, fallback_profile) in fallback_chain.iter().enumerate() {
        attempted_profiles.push(format!("{:?}", fallback_profile));

        // FIXED: For Standard profile, use perform_handshake to capture raw_server_hello
        // Standard profile = TLS 1.2 only, but we still need raw_server_hello for analysis
        let handshake_attempt = if *fallback_profile == HandshakeProfile::Standard {
            // Standard profile = TLS 1.2 only
            let mut handshake = HandshakeEngine::new(*fallback_profile);
            handshake = handshake.with_tls12_fallback();

            // FIXED: Use perform_handshake instead of perform_tcp_tls_handshake to capture raw_server_hello
            // This ensures raw_server_hello is populated even for Classic profile
            match try_connect(target, 443).await {
                Ok(stream) => handshake.perform_handshake(stream, target).await,
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
            let mut handshake = HandshakeEngine::new(*fallback_profile);

            // Enable TLS 1.2 fallback for certificate extraction if requested
            let should_enable_tls12 = tls12_enabled
                || detect_quic_server(target).await
                || target.contains("demo")
                || target.contains("test")
                || target.contains("experimental");

            if should_enable_tls12 {
                handshake = handshake.with_tls12_fallback();
            }

            // Try to perform handshake with this profile
            // Always create a new connection for each attempt to avoid ownership issues
            match try_connect(target, 443).await {
                Ok(new_stream) => handshake.perform_handshake(new_stream, target).await,
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
                final_profile = *fallback_profile;
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

    // TLS 1.2 fallback information (separate from profile fallback)
    let tls12_fallback_used = handshake_result.tls_version == "1.2";
    // Check if TLS 1.2 was attempted for certificate extraction (even if TLS 1.3 was used)
    // This is tracked separately from protocol-level TLS 1.2 usage
    let tls12_fallback_attempted_for_cert = tls12_enabled
        && handshake_result.tls_version == "1.3"
        && handshake_result.certificate_visible;
    let tls12_fallback_info = if tls12_enabled {
        Some(quanta_seek::types::Tls12FallbackInfo {
            enabled: true,
            used: tls12_fallback_used,
            attempted_for_certificate: tls12_fallback_attempted_for_cert,
        })
    } else {
        None
    };

    // Calculate fallback penalty (time difference between attempts)
    let fallback_penalty_ms =
        if profile_fallback_used && handshake_result.handshake_duration_ms.is_some() {
            // Estimate: each fallback attempt adds ~100ms overhead
            Some(profile_fallback_attempts_count as u64 * 100)
        } else {
            None
        };

    let fallback = FallbackInfo {
        enabled: profile_fallback_enabled,
        used: profile_fallback_used,
        attempts_count: profile_fallback_attempts_count,
        attempted_profiles: attempted_profiles_list,
        fallback_penalty_ms,
        tls12_fallback: tls12_fallback_info,
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
    };

    scan_result.security_score = scorer.calculate_security_score(&scan_result);
    scan_result.security_warnings = scorer.generate_security_warnings(&scan_result.security_score);

    // Detect HTTP redirects after handshake (for both TLS and QUIC)
    if scan_result.handshake_complete {
        match detect_http_redirects(target, 10).await {
            Ok(redirect_info) => {
                if redirect_info.detected {
                    if quanta_seek::verbose() {
                        eprintln!(
                            "  [DEBUG] HTTP redirect detected for {}: status={:?}, chain={:?}",
                            target, redirect_info.status_code, redirect_info.redirect_chain
                        );
                    }
                    scan_result.http_redirect = Some(redirect_info.clone());
                    // Use final destination certificate if different
                    if let Some(ref final_cert) = redirect_info.final_destination_certificate {
                        let should_replace =
                            scan_result
                                .certificate
                                .as_ref()
                                .map_or(true, |initial_cert| {
                                    initial_cert.subject != final_cert.subject
                                        || initial_cert.issuer != final_cert.issuer
                                });
                        if should_replace {
                            scan_result.certificate = Some(final_cert.clone());
                            // Re-analyze with new certificate
                            let detector = PqcDetector::new();
                            let handshake_result = HandshakeResult {
                                target: target.to_string(),
                                tls_version: scan_result.tls_version.clone(),
                                cipher_suite: scan_result.cipher_suite.clone(),
                                key_exchange: scan_result.key_exchange.clone(),
                                pqc_extensions: scan_result.pqc_extensions.clone(),
                                certificate_info: scan_result.certificate.clone(),
                                raw_server_hello: scan_result.raw_server_hello.clone(),
                                raw_certificate: Vec::new(),
                                alert_info: None,
                                certificate_visible: scan_result.certificate_visible,
                                handshake_complete: scan_result.handshake_complete,
                                pqc_signature_algorithms: Vec::new(),
                                pqc_signature_used: None,
                                tls_features: scan_result.tls_features.clone(),
                                handshake_duration_ms: scan_result.handshake_duration_ms,
                                client_profile_used: HandshakeProfile::Standard,
                                extension_map: scan_result.extension_map.clone(),
                                connection_type: scan_result.connection_type.clone(),
                                cipher_suite_reason: scan_result.cipher_suite_reason.clone(),
                            };
                            let updated_analysis = detector.analyze_handshake(&handshake_result);
                            scan_result.analysis = updated_analysis;
                            // Recalculate security score with new certificate
                            scan_result.security_score =
                                scorer.calculate_security_score(&scan_result);
                            scan_result.security_warnings =
                                scorer.generate_security_warnings(&scan_result.security_score);
                        }
                    }
                } else {
                    if quanta_seek::verbose() {
                        eprintln!("  [DEBUG] No HTTP redirect detected for {}", target);
                    }
                }
            }
            Err(e) => {
                if quanta_seek::verbose() {
                    eprintln!(
                        "  [DEBUG] HTTP redirect detection failed for {}: {}",
                        target, e
                    );
                }
            }
        }
    } else {
        if quanta_seek::verbose() {
            eprintln!(
                "  [DEBUG] Skipping HTTP redirect detection: handshake not complete for {}",
                target
            );
        }
    }

    let total_scan_duration = scan_start.elapsed();
    scan_result.total_scan_duration_ms = Some(total_scan_duration.as_millis() as u64);

    Ok(scan_result)
}

async fn scan_multiple_targets(
    targets: &[String],
    profile: ClientProfile,
    _format: &OutputFormat,
    quiet: bool,
) -> Result<Vec<ScanResult>> {
    let mut results = Vec::new();
    let mut successful_count = 0;
    let mut failed_count = 0;
    let start_time = std::time::Instant::now();

    for target in targets {
        if !quiet {
            println!("Scanning: {}", target);
        }

        match scan_target(target, &profile, true, false, quiet).await {
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
                if !quiet {
                    println!("✅ Completed: {}", target);
                }
            }
            Err(e) => {
                failed_count += 1;
                if !quiet {
                    println!("❌ Failed: {} - {}", target, e);
                }
                // Create a failed result for consistency
                let mut failed_result = ScanResult::new(target.clone());
                // FIXED: Set profile for failed scans so they don't show "Unknown"
                failed_result.set_profile(&profile.consistent_display_name());
                failed_result.handshake_complete = false;
                failed_result.security_warnings = vec![SecurityWarning {
                    message: format!("Scan failed: {}", e),
                    level: WarningLevel::Critical,
                    category: "Connection".to_string(),
                    recommendation: None,
                }];
                results.push(failed_result);
            }
        }
    }

    let total_duration = start_time.elapsed();

    if !quiet {
        // Print summary
        println!("\n📊 Scan Summary:");
        println!("  Total targets: {}", targets.len());
        println!(
            "  Successful: {} ({:.1}%)",
            successful_count,
            (successful_count as f64 / targets.len() as f64) * 100.0
        );
        println!(
            "  Failed: {} ({:.1}%)",
            failed_count,
            (failed_count as f64 / targets.len() as f64) * 100.0
        );
        println!("  Total duration: {:.2}s", total_duration.as_secs_f64());

        if successful_count > 0 {
            let avg_duration: f64 = results
                .iter()
                .filter_map(|r| r.handshake_duration_ms)
                .map(|d| d as f64)
                .sum::<f64>()
                / successful_count as f64;
            println!("  Average handshake time: {:.1}ms", avg_duration);

            let total_scan_time = total_duration.as_secs_f64();
            let scans_per_second = successful_count as f64 / total_scan_time;
            println!("  Throughput: {:.2} scans/second", scans_per_second);

            let pqc_detected = results.iter().filter(|r| r.pqc_detected).count();
            let hybrid_detected = results
                .iter()
                .filter(|r| r.analysis.hybrid_detected)
                .count();
            let pqc_signatures_used = results
                .iter()
                .filter(|r| r.analysis.pqc_signature_used == Some(true))
                .count();

            println!(
                "  PQC detected: {} ({:.1}%)",
                pqc_detected,
                (pqc_detected as f64 / successful_count as f64) * 100.0
            );
            println!(
                "  Hybrid mode: {} ({:.1}%)",
                hybrid_detected,
                (hybrid_detected as f64 / successful_count as f64) * 100.0
            );
            println!(
                "  PQC signatures used: {} ({:.1}%)",
                pqc_signatures_used,
                (pqc_signatures_used as f64 / successful_count as f64) * 100.0
            );

            let certificates_visible = results.iter().filter(|r| r.certificate_visible).count();
            let certificates_analyzed = results.iter().filter(|r| r.certificate.is_some()).count();

            println!(
                "  Certificates visible: {} ({:.1}%)",
                certificates_visible,
                (certificates_visible as f64 / successful_count as f64) * 100.0
            );
            println!(
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
                println!("  TLS version distribution:");
                for (version, count) in tls_versions {
                    println!(
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
                println!("  Client profiles used:");
                for (profile, count) in profile_usage {
                    println!("    {}: {} servers", profile, count);
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
                println!("  Key exchange algorithms:");
                for (algo, count) in algorithms {
                    println!("    {}: {} servers", algo, count);
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
                println!("  PQC signature algorithms:");
                for (sig, count) in signature_algorithms {
                    println!("    {}: {} servers", sig, count);
                }
            }
        }
    }

    Ok(results)
}

fn output_batch_results(
    results: &[ScanResult],
    format: &OutputFormat,
    total_duration: std::time::Duration,
) {
    match format {
        OutputFormat::Json => {
            let batch_output = serde_json::json!({
                "batch_scan": {
                    "total_targets": results.len(),
                    "successful_scans": results.iter().filter(|r| r.handshake_complete).count(),
                    "failed_scans": results.iter().filter(|r| !r.handshake_complete).count(),
                    "total_duration_ms": total_duration.as_millis(),
                    "results": results
                }
            });
            match serde_json::to_string_pretty(&batch_output) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Failed to serialize batch results: {}", e);
                    // Fallback to compact JSON
                    if let Ok(json) = serde_json::to_string(&batch_output) {
                        println!("{}", json);
                    } else {
                        eprintln!("Failed to serialize batch results in compact format");
                    }
                }
            }
        }
        OutputFormat::Text => {
            println!("\n=== BATCH SCAN SUMMARY ===");
            println!("Total targets: {}", results.len());
            println!(
                "Successful scans: {}",
                results.iter().filter(|r| r.handshake_complete).count()
            );
            println!(
                "Failed scans: {}",
                results.iter().filter(|r| !r.handshake_complete).count()
            );
            println!("Total duration: {}ms", total_duration.as_millis());
            println!("\n=== INDIVIDUAL RESULTS ===");

            for result in results {
                println!("\n--- {} ---", result.target);
                if result.handshake_complete {
                    println!("Status: ✅ Success");
                    println!("TLS Version: {}", result.tls_version);
                    println!("PQC Detected: {}", result.pqc_detected);
                    println!("Security Score: {}/100", result.security_score.overall);
                } else {
                    println!("Status: ❌ Failed");
                    if let Some(warnings) = result.security_warnings.first() {
                        println!("Error: {}", warnings.message);
                    }
                }
            }
        }
        OutputFormat::Csv => {
            println!("CSV batch output is not implemented in this version.");
        }
    }
}

// Note: parse_target function is not used in the current implementation
