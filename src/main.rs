use anyhow::Result;
use clap::Parser;
use quanta_seek::scan::{scan_multiple_targets, scan_target, ScanOptions};
use quanta_seek::{
    output::output_results,
    types::{ClientProfile, HandshakeConfig, OutputFormat, ScanResult},
    HandshakeProfile,
};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// QuantaSeek: report the TLS key exchange and certificate algorithms an
/// endpoint actually negotiates, with a focus on post-quantum readiness.
#[derive(Debug, Parser)]
#[command(name = "quantaseek", version, about, long_about = None)]
struct Cli {
    /// Target hostnames, space- or comma-separated (e.g. example.com google.com)
    #[arg(required = true, num_args = 1.., value_delimiter = ',')]
    targets: Vec<String>,

    /// Handshake profile label: standard, cloudflare-pqc, hybrid-pqc, pqc-only.
    /// Currently every profile sends the same ClientHello (see README, Limitations).
    #[arg(short, long, default_value = "cloudflare-pqc", value_parser = HandshakeProfile::from_str)]
    profile: HandshakeProfile,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = FormatArg::Json)]
    format: FormatArg,

    /// Enable TLS 1.2 fallback for certificate analysis
    #[arg(long)]
    tls12: bool,

    /// TCP connect timeout in seconds
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    connect_timeout: u64,

    /// TLS handshake read/write timeout in milliseconds
    #[arg(long, default_value_t = 5000, value_name = "MS")]
    handshake_timeout: u64,

    /// Only print errors on stderr; results still go to stdout
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Increase log detail on stderr (-v debug, -vv trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Json,
    Text,
}

fn init_logging(quiet: bool, verbose: u8) {
    let level = match (quiet, verbose) {
        (true, _) => tracing::Level::ERROR,
        (false, 0) => tracing::Level::INFO,
        (false, 1) => tracing::Level::DEBUG,
        (false, _) => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .without_time()
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.quiet, cli.verbose);

    // rustls 0.23 needs a process-wide crypto provider; aws-lc-rs provides
    // the ML-KEM hybrid groups.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let handshake = HandshakeConfig {
        timeout_ms: cli.handshake_timeout,
        ..HandshakeConfig::default()
    };
    let opts = ScanOptions {
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        handshake,
        ..ScanOptions::default()
    };

    let profile = match cli.profile {
        HandshakeProfile::Standard => ClientProfile::Classic,
        HandshakeProfile::CloudflarePqc => ClientProfile::Fallback,
        HandshakeProfile::HybridPqc => ClientProfile::Hybrid,
        HandshakeProfile::PqcOnly => ClientProfile::MaxPqc,
    };
    let format = match cli.format {
        FormatArg::Json => OutputFormat::Json,
        FormatArg::Text => OutputFormat::Text,
    };
    let targets = cli.targets;
    let tls12_enabled = cli.tls12;

    tracing::info!("QuantaSeek {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Targets: {}", targets.join(", "));
    tracing::info!("Profile: {}", profile.display_name());
    if tls12_enabled && profile != ClientProfile::Classic {
        tracing::info!("TLS 1.2 fallback enabled for certificate analysis");
    }

    let scan_start = Instant::now();

    if targets.len() == 1 {
        let result = scan_target(&opts, &targets[0], &profile, tls12_enabled).await?;
        output_results(&result, format);
    } else {
        let results = scan_multiple_targets(&opts, &targets, profile).await?;
        output_batch_results(&results, &format, scan_start.elapsed());
    }

    Ok(())
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
                    tracing::error!("Failed to serialize batch results: {}", e);
                    // Fallback to compact JSON
                    if let Ok(json) = serde_json::to_string(&batch_output) {
                        println!("{}", json);
                    } else {
                        tracing::error!("Failed to serialize batch results in compact format");
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
            tracing::error!("CSV output is not implemented");
        }
    }
}

// Note: parse_target function is not used in the current implementation
