use anyhow::Result;
use clap::Parser;
use quanta_seek::scan::{scan_target, ScanOptions};
use quanta_seek::{
    types::{HandshakeConfig, OutputFormat},
    HandshakeProfile,
};
use std::io::Write;
use std::time::Duration;

/// QuantaSeek: report the TLS key exchange and certificate algorithms an
/// endpoint actually negotiates, with a focus on post-quantum readiness.
#[derive(Debug, Parser)]
#[command(name = "quantaseek", version, about, long_about = None)]
struct Cli {
    /// Targets: host, host:port, [ipv6]:port; space- or comma-separated
    #[arg(required_unless_present = "print_schema", num_args = 1.., value_delimiter = ',')]
    targets: Vec<String>,

    /// Print the JSON Schema of the output and exit
    #[arg(long)]
    print_schema: bool,

    /// Key-exchange groups the ClientHello offers
    #[arg(short, long, value_enum, default_value_t = HandshakeProfile::Default)]
    profile: HandshakeProfile,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = FormatArg::Json)]
    format: FormatArg,

    /// Server name to send in SNI and validate the certificate against
    /// (default: the target host)
    #[arg(long, value_name = "NAME")]
    sni: Option<String>,

    /// After the handshake, follow HTTP redirects and report the chain and the
    /// final destination's certificate separately (off by default)
    #[arg(long)]
    follow_redirects: bool,

    /// After the handshake, probe each key-exchange group, preference,
    /// HelloRetryRequest, downgrade and ClientHello-size behaviour with
    /// hand-built ClientHellos (one TCP connection per probe)
    #[arg(long)]
    probe: bool,

    /// Maximum probes per target with --probe
    #[arg(long, default_value_t = 40, value_name = "N")]
    probe_budget: u32,

    /// Minimum delay between probes in milliseconds (at least 100)
    #[arg(long, default_value_t = 100, value_name = "MS", value_parser = clap::value_parser!(u64).range(100..))]
    probe_spacing: u64,

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
    if cli.print_schema {
        println!(
            "{}",
            serde_json::to_string_pretty(&quanta_seek::report::json_schema())?
        );
        return Ok(());
    }
    init_logging(cli.quiet, cli.verbose);

    // rustls 0.23 needs a process-wide crypto provider; aws-lc-rs provides
    // the ML-KEM hybrid groups.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let handshake = HandshakeConfig {
        timeout_ms: cli.handshake_timeout,
        ..HandshakeConfig::default()
    };
    let opts = ScanOptions {
        sni: cli.sni.clone(),
        follow_redirects: cli.follow_redirects,
        probe: cli.probe.then(|| quanta_seek::probe::ProbeOptions {
            max_probes: cli.probe_budget,
            spacing: Duration::from_millis(cli.probe_spacing),
            ..Default::default()
        }),
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        handshake,
        ..ScanOptions::default()
    };

    let profile = cli.profile;
    let format = match cli.format {
        FormatArg::Json => OutputFormat::Json,
        FormatArg::Text => OutputFormat::Text,
    };
    let targets = cli.targets;

    tracing::info!("QuantaSeek {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Targets: {}", targets.join(", "));
    tracing::info!(
        "Profile: {} (offers {})",
        profile.name(),
        profile.offered_group_names().join(", ")
    );

    // One result per target, written as soon as it is ready.
    let stdout = std::io::stdout();
    for target in &targets {
        let report = scan_target(&opts, target, &profile).await;
        let mut out = stdout.lock();
        match format {
            OutputFormat::Json => {
                serde_json::to_writer(&mut out, &report)?;
                writeln!(out)?;
            }
            OutputFormat::Text => {
                writeln!(out, "{}", report.render_text())?;
            }
        }
        out.flush()?;
    }

    Ok(())
}
