# QuantaSeek PQC TLS Scanner 🔍

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PQC](https://img.shields.io/badge/PQC-NIST%20Level%203-green.svg)](https://www.nist.gov/pqc)
[![TLS](https://img.shields.io/badge/TLS-1.3%20Ready-brightgreen.svg)](https://tools.ietf.org/html/rfc8446)

**QuantaSeek** is a production-ready Post-Quantum Cryptography (PQC) aware TLS scanner that performs real TLS handshakes using `rustls`, analyzes TLS/PQC features, and produces structured, explainable security and performance reports.

## ✨ Key Highlights

- ✅ **Real TLS Handshakes**: Uses `rustls` for actual TLS 1.3/1.2 connections
- ✅ **100% Accurate Certificate Analysis**: RFC 6125 compliant hostname validation, no mock data
- ✅ **PQC Detection**: Supports ML-KEM (Kyber), Dilithium, Falcon, SPHINCS+
- ✅ **QUIC Support**: Certificate extraction via TLS 1.2 fallback with robust retry logic
- ✅ **Transparent Scoring**: Explainable security scores with detailed formulas
- ✅ **Production Ready**: High accuracy for certificate validation, comprehensive error handling

## 🌟 Key Features

### 🔐 **PQC Algorithm Detection**
- **KEMs:** ML-KEM-512 (L1), ML-KEM-768 (L3), ML-KEM-1024 (L5) — Kyber aliases supported
- **Hybrid Mode:** Classical + PQC combinations (e.g., X25519 + ML-KEM-768)
- **PQC Signatures (analysis):** Dilithium2/3/5, Falcon512/1024, SPHINCS+ (via certificate OID analysis)
- **Raw TLS Parsing:** Extracts cipher suites and key exchange algorithms directly from ServerHello messages

### 📊 **Transparent Security Scoring**
- **Multi-Component Analysis:** TLS (30%), Certificate (25%), PQC (45%) for PQC-enabled handshakes
- **Classical Mode:** TLS (50%), Certificate (50%) for classical-only connections
- **Explainability:** Exact formulas and sub-scores included in JSON output
- **NIST Mapping:** FIPS 203 levels (L1/L3/L5) reflected in scores
- **Validation:** RFC 6125 hostname match and key/signature consistency checks

### ⚡ **Performance & Reliability**
- **Measured Handshakes:** Duration, overhead categories (PQC, certificate, network)
- **Batch Scans:** Summary stats and per-target analysis
- **TLS 1.2 Fallback:** Automatic certificate extraction for QUIC connections
- **QUIC Support:** Robust TCP/TLS fallback with retry logic and multiple port attempts
- **No Mock Data:** 100% real certificate data, validated and verified
- **Error Handling:** Comprehensive error reporting with detailed diagnostics

### 🎯 **Client Profiles**
- **Classic**: Standard TLS 1.3 with classical algorithms only
- **Fallback**: Cloudflare PQC-enabled server profile with fallback support
- **Hybrid**: Hybrid PQC with classical fallback
- **MaxPQC**: PQC-only configuration (experimental)

### 📄 Features, Capabilities, and Limitations (full document)

A complete description of all features, capabilities, and limitations of this Rust project is available in **[FEATURES_AND_LIMITATIONS.md](FEATURES_AND_LIMITATIONS.md)** (in English). It covers:

- **Features**: Real TLS handshakes, PQC detection (KEM and certificate-based), client profiles and fallback, certificate analysis (RFC 6125), security scoring, QUIC support, HTTP redirect detection, performance timing, output formats, and CLI options.
- **Capabilities**: Single and batch scans, dual stack (TCP + QUIC), fallback chains, structured output, and library API.
- **Limitations**: QUIC certificate extraction (TLS 1.2 fallback only; QUIC-only servers may have no cert/key_exchange), TLS 1.3 encrypted fields (CertificateVerify), PQC detection gaps (empty raw_server_hello, parsing issues), HTTP redirect and network behaviour, code quality (unwrap/panic, logging), no config file, and test coverage.
- **TLS 1.3 vs QUIC reporting**: PQC **key exchange** is reported for both TLS 1.3 and QUIC where available; PQC **signature** usage is authoritative for TLS 1.3 TCP (via CapturingVerifier) and best-effort for QUIC (certificate OID or "Not Implemented" when no cert).

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ (tested with Rust 1.75+)
- Network connectivity for target servers

Dependencies are pinned to address known advisories (e.g. `bytes`, `time`). Run `cargo audit` after `cargo update` to verify no vulnerabilities.

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/QuantaSeek.git
cd QuantaSeek

# Build release version
cargo build --release

# The binary will be at: ./target/release/quantaseek
```

### Basic Usage

```bash
# Scan a single target with default profile (Cloudflare PQC)
./target/release/quantaseek example.com

# Scan with Classic profile
./target/release/quantaseek example.com --profile standard

# Scan with MaxPQC profile
./target/release/quantaseek quantumtls.com --profile pqc-only

# Scan multiple targets
./target/release/quantaseek example.com google.com cloudflare.com

# Enable TLS 1.2 fallback for certificate analysis
./target/release/quantaseek example.com --tls12

# Output in text format
./target/release/quantaseek example.com --format text
```

## 📖 Usage Examples

### Example 1: Classic TLS Scan

```bash
./target/release/quantaseek example.com --profile standard
```

**Output:**
```json
{
  "target": "example.com",
  "client_profile_used": "Classic",
  "tls_version": "1.3",
  "cipher_suite": "TLS13_AES_256_GCM_SHA384",
  "key_exchange": ["X25519"],
  "handshake_duration_ms": 3330,
  "handshake_complete": true,
  "certificate_visible": true,
  "certificate": {
    "subject": "*.example.com",
    "issuer": "DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "public_key_algorithm": "ECDSA",
    "signature_algorithm": "ECDSA-SHA384",
    "signature_algorithm_oid": "1.2.840.10045.4.3.3",
    "key_size": 256,
    "valid_from": "Wed, 15 Jan 2025 00:00:00 +0000",
    "valid_to": "Thu, 15 Jan 2026 23:59:59 +0000",
    "san": "*.example.com, example.com"
  },
  "security_score": {
    "overall": 96,
    "tls": 97,
    "certificate": 95,
    "pqc": 0
  }
}
```

### Example 2: QUIC Server with PQC Profile

```bash
./target/release/quantaseek quantumtls.com --profile pqc-only
```

**Output:**
```json
{
  "target": "quantumtls.com",
  "client_profile_used": "MaxPQC",
  "tls_version": "1.3",
  "cipher_suite": "TLS13_AES_128_GCM_SHA256",
  "key_exchange": ["X25519"],
  "handshake_duration_ms": 16961,
  "handshake_complete": true,
  "certificate_visible": true,
  "raw_server_hello": [2, 0, 0, 118, ...],
  "protocol_support": {
    "tls": true,
    "quic": "unknown",
    "http3": "unknown"
  }
}
```

**Note:** QUIC servers automatically trigger TCP/TLS fallback for certificate extraction and PQC detection.

## 📋 Command Line Options

```
USAGE:
    quantaseek [OPTIONS] <targets>...

ARGS:
    <targets>...    Target hostnames (e.g., example.com:443, google.com)

OPTIONS:
    -p, --profile <profile>
            Handshake profile to use [default: cloudflare-pqc]
            [possible values: standard, cloudflare-pqc, hybrid-pqc, pqc-only]

    -f, --format <format>
            Output format [default: json]
            [possible values: json, text]

        --tls12
            Enable TLS 1.2 fallback for certificate analysis

        --ignore-mismatch
            Ignore hostname mismatch for experimental servers

    -q, --quiet
            Suppress banner, progress lines, and summary; only print result (JSON/text).
            Use in production or scripts to avoid cluttering stdout.

    -v, --verbose
            Enable debug and progress messages (QUIC fallback, HTTP redirect, etc.).
            Equivalent to setting QUANTASEEK_DEBUG=1.

    -h, --help
            Print help information

    -V, --version
            Print version information
```

### Production use and logging

By default the scanner prints a banner, per-target progress (`Scanning: ...`, `✅ Completed`), and a summary. Debug messages (HTTP redirect, QUIC fallback) are **off** unless requested.

- **Production / scripts:** use `-q` / `--quiet` so only the result (e.g. JSON) is printed; no banner or summary. Example: `./target/release/quantaseek -q example.com google.com > out.jsonl`
- **Debug:** use `-v` / `--verbose`, or set `QUANTASEEK_DEBUG=1`, to enable `[DEBUG]` and `[QUIC Fallback]` messages on stderr. This avoids flooding the terminal in production.

## 📊 Output Format

### JSON Output Structure

```json
{
  "target": "example.com",
  "client_profile_used": "Classic",
  "tls_version": "1.3",
  "cipher_suite": "TLS13_AES_256_GCM_SHA384",
  "key_exchange": ["X25519"],
  "handshake_complete": true,
  "handshake_duration_ms": 3330,
  "total_scan_duration_ms": 3576,
  "certificate_visible": true,
  "certificate": { ... },
  "raw_server_hello": [ ... ],
  "analysis": {
    "pqc_detected": false,
    "hybrid_detected": false,
    "security_level": "Classical Only",
    "security_features": ["TLS 1.3", "X25519"],
    "server_endpoint_fingerprint": "x25519-aes256gcm"
  },
  "security_score": {
    "overall": 96,
    "tls": 97,
    "certificate": 95,
    "pqc": 0,
    "formula": {
      "overall_method": "Overall = 0.50×TLS(97) + 0.50×Certificate(95) = 96",
      "tls_method": "TLS = Version(100)×0.40 + Cipher(100)×0.30 + KeyExchange(90)×0.30 = 97",
      "certificate_method": "Certificate = (Validation(100) + KeyStrength(90)) / 2 = 95"
    }
  },
  "performance_analysis": {
    "handshake_timing": {
      "duration_ms": 3330,
      "category": "very_slow",
      "benchmark": {
        "excellent": "< 200ms",
        "good": "200-400ms",
        "acceptable": "400-800ms",
        "slow": "800-1500ms",
        "very_slow": "> 1500ms"
      }
    },
    "overhead_analysis": {
      "certificate_overhead_ms": 80,
      "network_overhead_ms": 0,
      "pqc_overhead_ms": 0,
      "overhead_vs_baseline_percent": 2120.0
    }
  },
  "security_warnings": [ ... ],
  "recommendations": [ ... ]
}
```

## 🔍 Technical Details

### TLS Handshake Process

1. **Connection Establishment**: TCP connection to target server (default port 443)
2. **TLS Handshake**: Real TLS 1.3 handshake using `rustls` with selected profile
3. **Raw Record Capture**: Captures raw TLS records including ServerHello for analysis
4. **Certificate Extraction**: Extracts and validates X.509 certificates
5. **PQC Detection**: Analyzes key exchange algorithms and extensions for PQC support
6. **Security Scoring**: Calculates multi-component security scores with explainable formulas

### QUIC Support

For QUIC-enabled servers:
- Automatic detection of QUIC-capable servers
- TCP/TLS fallback with robust retry logic (minimum 3 attempts)
- Multiple port attempts (443, actual_port, 8443)
- Extended timeout (minimum 8 seconds) for rate-limited servers
- Detailed logging for fallback attempts
- Certificate extraction via TLS 1.2 fallback when needed

### Certificate Analysis

- **RFC 6125 Compliance**: Strict hostname validation
- **Algorithm Consistency**: Validates public key and signature algorithm consistency
- **OID Extraction**: Extracts signature algorithm OIDs for PQC detection
- **SAN Parsing**: Parses Subject Alternative Names for multi-domain certificates
- **Validity Checking**: Validates certificate expiration dates
- **No Mock Data**: 100% real certificate data from actual handshakes

### PQC Detection Methods

1. **Key Exchange Analysis**: Detects PQC KEM groups in key_share extension
2. **Certificate OID Analysis**: Identifies PQC signature algorithms via certificate OIDs
3. **Raw TLS Parsing**: Extracts cipher suites and groups directly from ServerHello
4. **Extension Analysis**: Analyzes supported_groups and key_share extensions

## 🧪 Testing & Validation

### Test Results

Based on comprehensive testing with 60+ servers:

- **Success Rate**: 83.3% (50/60 successful scans)
- **Cipher Suite Extraction**: 75% success rate
- **PQC Detection**: 25% of servers show PQC support
- **Profile Consistency**: 100% correct profile names in successful scans
- **Certificate Accuracy**: 100% real certificate data, no mock data

### Known Limitations

1. **TLS 1.3 Encryption**: CertificateVerify signature algorithms are encrypted in TLS 1.3, reported as "Unknown"
2. **QUIC certificate extraction**: Certificate and key exchange for QUIC are obtained via TCP/TLS 1.2 fallback only; direct extraction from the QUIC connection is not implemented. QUIC-only servers may show no certificate or key_exchange
3. **QUIC-Only Servers**: Some QUIC-only servers do not offer TCP/TLS on the same host/port; certificate and PQC detection will be unavailable for those targets
4. **Rate Limiting**: Some servers may rate-limit connections, causing occasional failures
5. **Network Errors**: Network connectivity issues may cause scan failures (reported with proper error messages)
6. **Empty raw_server_hello**: Classic profile or some fallback paths do not capture raw ServerHello, so raw parsing–based PQC detection is unavailable for those scans

**Full details:** For a complete list of features, capabilities, and limitations (in English), see **[FEATURES_AND_LIMITATIONS.md](FEATURES_AND_LIMITATIONS.md)**.

## 🛠️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/your-username/QuantaSeek.git
cd QuantaSeek

# Build debug version
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run --release -- example.com
```

### Project Structure

```
QuantaSeek/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── types.rs          # Data structures and types
│   ├── handshake.rs      # TLS/QUIC handshake engine
│   ├── detector.rs       # PQC detection logic
│   ├── tls_parser.rs     # Raw TLS message parsing
│   ├── constants.rs      # TLS/PQC constants
│   ├── security_scoring.rs  # Security score calculation
│   └── output.rs         # Output formatting
├── Cargo.toml           # Rust dependencies
├── README.md            # This file
└── LICENSE              # MIT License
```

### Dependencies

- **rustls** (0.23+): TLS implementation with PQC support
- **tokio-rustls** (0.26+): Async TLS streams
- **quinn** (0.11): QUIC protocol support
- **webpki-roots**: Root certificate store
- **x509-parser**: X.509 certificate parsing
- **clap**: Command-line argument parsing
- **serde/serde_json**: JSON serialization

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **rustls**: Modern TLS library with PQC support
- **NIST**: Post-Quantum Cryptography standardization
- **IETF**: TLS 1.3 and QUIC protocol specifications

## 📧 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Reporting Issues

If you encounter any issues or have suggestions, please open an issue on GitHub.

## 📚 References

- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 6125 - PKIX Certificate and CRL Profile](https://tools.ietf.org/html/rfc6125)
- [NIST PQC Standardization](https://www.nist.gov/pqc)
- [rustls Documentation](https://docs.rs/rustls/)

---

**Made with ❤️ for Post-Quantum Cryptography research**
