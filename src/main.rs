use clap::{Command, Arg};
use tokio::net::TcpStream;
use anyhow::Result;
use QuantaSeek::{HandshakeEngine, HandshakeProfile, output_results, OutputFormat, ScanResult, SecurityScorer};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("QuantaSeek")
        .version("0.1.0")
        .about("PQC-aware TLS scanner")
        .arg(
            Arg::new("target")
                .help("Target hostname:port (e.g., example.com:443)")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Handshake profile to use")
                .value_parser(["standard", "cloudflare-pqc", "hybrid-pqc", "pqc-only"])
                .default_value("cloudflare-pqc")
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Output format")
                .value_parser(["json", "text"])
                .default_value("json")
        )
        .get_matches();

    let target = matches.get_one::<String>("target").unwrap();
    let profile_str = matches.get_one::<String>("profile").unwrap();
    let format_str = matches.get_one::<String>("format").unwrap();

    // Parse profile
    let profile = match profile_str.as_str() {
        "standard" => HandshakeProfile::Standard,
        "cloudflare-pqc" => HandshakeProfile::CloudflarePqc,
        "hybrid-pqc" => HandshakeProfile::HybridPqc,
        "pqc-only" => HandshakeProfile::PqcOnly,
        _ => HandshakeProfile::CloudflarePqc, // Default fallback
    };

    // Parse output format
    let format = match format_str.as_str() {
        "json" => OutputFormat::Json,
        "text" => OutputFormat::Text,
        _ => OutputFormat::Json, // Default fallback
    };

    println!("🔍 QuantaSeek PQC TLS Scanner");
    println!("Target: {}", target);
    println!("Profile: {:?}", profile);
    println!("Format: {:?}", format);
    println!("═══════════════════════════");

    // Start timing the complete scan
    let scan_start = Instant::now();

    // Parse hostname and port
    let (hostname, port) = parse_target(target)?;
    
    // Connect to target
    let stream = TcpStream::connect(format!("{}:{}", hostname, port)).await?;
    
    // Perform handshake
    let engine = HandshakeEngine::new(profile);
    let handshake_result = engine.perform_handshake(stream, &hostname).await?;
    
    // Calculate total scan duration
    let total_scan_duration = scan_start.elapsed();
    
    // Create scan result and output
    let mut scan_result = ScanResult::new(target.to_string());
    scan_result.update_from_handshake(handshake_result);
    scan_result.total_scan_duration_ms = Some(total_scan_duration.as_millis() as u64);
    
    // Calculate security score
    let security_scorer = SecurityScorer::new();
    scan_result.security_score = security_scorer.calculate_security_score(&scan_result);
    
    // Generate warnings and recommendations
    scan_result.security_warnings = security_scorer.generate_security_warnings(&scan_result);
    scan_result.performance_warnings = security_scorer.generate_performance_warnings(&scan_result);
    
    output_results(&scan_result, format);
    
    Ok(())
}

fn parse_target(target: &str) -> Result<(String, u16)> {
    if let Some(colon_pos) = target.rfind(':') {
        let hostname = target[..colon_pos].to_string();
        let port = target[colon_pos + 1..].parse::<u16>()?;
        Ok((hostname, port))
    } else {
        // Default to port 443 if not specified
        Ok((target.to_string(), 443))
    }
}
