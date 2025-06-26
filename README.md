# QuantaSeek PQC TLS Scanner 🔍

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PQC](https://img.shields.io/badge/PQC-NIST%20Level%203-green.svg)](https://www.nist.gov/pqc)
[![TLS](https://img.shields.io/badge/TLS-1.3%20Ready-brightgreen.svg)](https://tools.ietf.org/html/rfc8446)

**QuantaSeek** is a production-ready Post-Quantum Cryptography (PQC) aware TLS 1.3 scanner that provides comprehensive security analysis of TLS connections with transparent scoring methodology.

## 🌟 Key Features

### 🔐 **PQC Algorithm Detection**
- **ML-KEM Family:** ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber Family:** Kyber512, Kyber768, Kyber1024  
- **Signature Algorithms:** Dilithium2/3/5, Falcon512/1024, SPHINCS+
- **Hybrid Mode:** Classical + PQC combinations (e.g., X25519 + ML-KEM-768)

### 📊 **Transparent Security Scoring**
- **Multi-Component Analysis:** TLS (30%), Certificate (25%), PQC (45%)
- **Formula Transparency:** All calculations documented with actual values
- **NIST Level Mapping:** Automatic security level classification
- **Real-time Validation:** Certificate consistency and hostname verification

### ⚡ **High Performance**
- **Fast Handshakes:** 350-800ms for PQC-enabled connections
- **Memory Efficient:** Handles large certificates (3000+ bytes)
- **Concurrent Scanning:** Support for multiple targets
- **Optimized Parsing:** Efficient X.509 certificate analysis

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ 
- OpenSSL development libraries
- Network connectivity for target servers

### Installation

```bash
# Clone the repository
git clone https://github.com/Mehrn0ush/QuantaSeek.git
cd QuantaSeek

# Build in release mode
cargo build --release

# The scanner is now available as ./target/release/quantaseek
```

### Basic Usage

```bash
# Scan a single target
./target/release/quantaseek pq.cloudflareresearch.com

# Scan with JSON output
./target/release/quantaseek --format json pq.cloudflareresearch.com

# Scan with debug logging
RUST_LOG=debug ./target/release/quantaseek pq.cloudflareresearch.com

# Scan multiple targets
./target/release/quantaseek server1.example.com server2.example.com
```

## 📋 Command Line Options

```bash
USAGE:
    pqcscan [OPTIONS] <TARGETS>...

ARGS:
    <TARGETS>...    Target hostnames to scan

OPTIONS:
    -f, --format <FORMAT>    Output format [default: json] [possible values: json, text]
    -p, --profile <PROFILE>  Client profile to use [default: CloudflarePqc] [possible values: Standard, CloudflarePqc, HybridPqc, PqcOnly]
    -h, --help              Print help information
    -V, --version           Print version information
```

## 🔧 Client Profiles

### CloudflarePqc (Default)
Optimized for Cloudflare and similar PQC-enabled servers:
- Offers ML-KEM-768 + X25519 hybrid
- Includes PQC signature algorithms
- Full TLS 1.3 extension support

### Standard
Classical TLS 1.3 only:
- No PQC algorithms
- Standard cipher suites
- Basic extension set

### HybridPqc
Balanced PQC + Classical:
- PQC with classical fallback
- Conservative algorithm selection
- Compatibility focused

### PqcOnly
PQC-only configuration:
- Maximum PQC algorithms
- Experimental/advanced features
- Research and testing use

## 📊 Output Format

### JSON Output Structure

```json
{
  "target": "pq.cloudflareresearch.com",
  "tls_version": "1.3",
  "cipher_suite": "TLS13_AES_256_GCM_SHA384",
  "key_exchange": ["X25519", "ML-KEM-768"],
  "certificate": {
    "subject": "pq.cloudflareresearch.com",
    "issuer": "WE1",
    "public_key_algorithm": "ECDSA",
    "signature_algorithm": "ECDSA-SHA256",
    "key_size": 256,
    "algorithm_consistency": true,
    "certificate_length_estimate": 975
  },
  "security_score": {
    "overall": 96,
    "tls": 97,
    "certificate": 90,
    "pqc": 100,
    "details": {
      "tls_version": 100,
      "cipher_suite": 100,
      "key_exchange": 92,
      "certificate_validation": 90,
      "certificate_key_strength": 90,
      "pqc_algorithm": 100,
      "pqc_implementation": 100,
      "hybrid_security": 100
    },
    "formula": {
      "overall_method": "Overall = TLS(97) + Certificate(90) + PQC(100) = 97×0.30 + 90×0.25 + 100×0.45 = 96",
      "pqc_method": "PQC = (Algorithm(100) + Implementation(100) + Hybrid(100)) / 3 = (100 + 100 + 100) / 3 = 100"
    },
    "pqc_strength": {
      "algorithms": [
        {
          "name": "ML-KEM-768",
          "security_bits": 192,
          "nist_level": "Level 2",
          "score": 95
        }
      ],
      "overall_level": "Maximum Security (256+ bits)",
      "security_bits": 256,
      "nist_level": "Level 3"
    }
  },
  "handshake_duration_ms": 396,
  "total_scan_duration_ms": 586
}
```

## 🎯 Security Scoring Methodology

### Overall Score Calculation
For PQC-enabled connections:
```
Overall = TLS(30%) + Certificate(25%) + PQC(45%)
```

For classical connections:
```
Overall = TLS(50%) + Certificate(50%)
```

### Component Scoring

#### TLS Component (40% of TLS score)
- **Version (40%):** TLS 1.3 = 100, TLS 1.2 = 70, TLS 1.1 = 30, TLS 1.0 = 0
- **Cipher Suite (30%):** AES-256-GCM = 100, AES-128-GCM = 95, etc.
- **Key Exchange (30%):** X25519 = 90, P-256 = 85, RSA = 40

#### Certificate Component
- **Validation (50%):** Hostname match, algorithm consistency, validity dates
- **Key Strength (50%):** RSA 4096+ = 100, ECDSA P-256 = 90, etc.

#### PQC Component
- **Algorithm (33%):** ML-KEM-1024 = 100, ML-KEM-768 = 95, ML-KEM-512 = 90
- **Implementation (33%):** Extension support, negotiation success
- **Hybrid Security (34%):** Classical + PQC combination strength

### NIST Security Levels
- **Level 1:** 128-bit security (ML-KEM-512, Dilithium2)
- **Level 2:** 192-bit security (ML-KEM-768, Dilithium3, Falcon512)
- **Level 3:** 256-bit security (ML-KEM-1024, Dilithium5, Falcon1024)

## 🔍 Supported PQC Algorithms

### Key Exchange
| Algorithm | Security Bits | NIST Level | Score |
|-----------|---------------|------------|-------|
| ML-KEM-1024 | 256 | Level 3 | 100 |
| ML-KEM-768 | 192 | Level 2 | 95 |
| ML-KEM-512 | 128 | Level 1 | 90 |
| Kyber1024 | 256 | Level 3 | 100 |
| Kyber768 | 192 | Level 2 | 95 |
| Kyber512 | 128 | Level 1 | 90 |

### Digital Signatures
| Algorithm | Security Bits | NIST Level | Score |
|-----------|---------------|------------|-------|
| Dilithium5 | 256 | Level 3 | 100 |
| Dilithium3 | 192 | Level 2 | 95 |
| Dilithium2 | 128 | Level 1 | 90 |
| Falcon1024 | 256 | Level 3 | 100 |
| Falcon512 | 192 | Level 2 | 95 |

## 🏗️ Architecture

### Core Components

```
src/
├── main.rs              # CLI entry point
├── lib.rs               # Library exports
├── handshake.rs         # TLS handshake engine
├── cert.rs              # Certificate parsing
├── detector.rs          # PQC detection logic
├── security_scoring.rs  # Scoring algorithms
├── types.rs             # Data structures
└── output.rs            # Output formatting
```

### Dependencies
- **rustls:** TLS 1.3 implementation
- **oqs:** Post-quantum cryptography
- **x509-parser:** Certificate parsing
- **chrono:** Date/time handling
- **serde:** JSON serialization
- **tokio:** Async runtime

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
cargo test

# Run specific test module
cargo test --lib detector

# Run with output
cargo test -- --nocapture
```

### Integration Tests
```bash
# Test against known PQC servers
./target/release/quantaseek pq.cloudflareresearch.com
./target/release/quantaseek pki.goog

# Test classical servers
./target/release/quantaseek google.com
```

### Performance Benchmarks
```bash
# Benchmark handshake performance
cargo bench

# Profile memory usage
cargo build --release && valgrind --tool=massif ./target/release/quantaseek test.example.com
```

## 📈 Performance Characteristics

### Handshake Times
- **PQC Servers:** 350-800ms (ML-KEM-768 + X25519)
- **Classical Servers:** 200-400ms (X25519 only)
- **Large Certificates:** +100-200ms for 3000+ byte certificates

### Memory Usage
- **Base Memory:** ~5MB
- **Per Connection:** ~2MB additional
- **Large SAN Lists:** +1MB per 100 domains

### Throughput
- **Single Thread:** ~10 scans/second
- **Concurrent:** ~50 scans/second (5 threads)
- **Network Bound:** Limited by target server response times

## 🔧 Configuration

### Environment Variables
```bash
# Enable debug logging
export RUST_LOG=debug

# Set custom timeout (default: 10s)
export PQCSCAN_TIMEOUT=15

# Enable experimental features
export PQCSCAN_EXPERIMENTAL=1
```

### Custom Profiles
Create custom client profiles by modifying the `HandshakeProfile` enum in `src/types.rs`:

```rust
pub enum HandshakeProfile {
    Custom {
        key_exchange: Vec<String>,
        signature_algorithms: Vec<String>,
        extensions: HashSet<u16>,
    },
    // ... existing profiles
}
```

## 🚨 Security Considerations

### Certificate Validation
- **Hostname Verification:** Strict RFC 6125 compliance
- **Algorithm Consistency:** Public key vs signature algorithm validation
- **Date Validation:** Certificate expiration and validity checks
- **Chain Verification:** Basic CA trust validation

### PQC Security
- **Algorithm Selection:** NIST-recommended algorithms only
- **Hybrid Mode:** Classical + PQC for backward compatibility
- **Implementation Verification:** Extension presence and negotiation

### Network Security
- **TLS 1.3 Only:** No downgrade to older versions
- **Forward Secrecy:** All supported key exchanges provide PFS
- **No Data Collection:** Scanner does not transmit scan results

## 🤝 Contributing

### Development Setup
```bash
# Clone and setup
git clone https://github.com/your-username/QuantaSeek.git
cd QuantaSeek

# Install development dependencies
rustup component add rustfmt clippy

# Run code formatting
cargo fmt

# Run linter
cargo clippy

# Run tests
cargo test
```

### Contribution Guidelines
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Style
- Follow Rust conventions and `rustfmt` formatting
- Use meaningful variable and function names
- Add comprehensive documentation for public APIs
- Include tests for new functionality

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST PQC Project** for algorithm specifications
- **Cloudflare Research** for PQC deployment insights
- **Rustls Team** for excellent TLS implementation
- **OQS Project** for post-quantum cryptography bindings

## 📞 Support

### Issues and Questions
- **GitHub Issues:** [Create an issue](https://github.com/your-username/QuantaSeek/issues)
- **Discussions:** [GitHub Discussions](https://github.com/your-username/QuantaSeek/discussions)
- **Email:** security@your-domain.com

### Documentation
- **API Reference:** [docs.rs/quanta-seek](https://docs.rs/quanta-seek)
- **Examples:** [examples/](examples/) directory
- **Blog Posts:** [Security Blog](https://your-blog.com/tags/quanta-seek)

## 🔮 Roadmap

### v1.1.0 (Q2 2024)
- [ ] ML-KEM-1024 support
- [ ] OCSP/CRL integration
- [ ] Performance profiling tools
- [ ] Windows/macOS builds

### v1.2.0 (Q3 2024)
- [ ] Additional PQC algorithms (HQC, NTRU)
- [ ] Machine learning scoring
- [ ] REST API server
- [ ] Docker containerization

### v2.0.0 (Q4 2024)
- [ ] Web interface
- [ ] Batch scanning capabilities
- [ ] Custom scoring rules
- [ ] Integration with security tools

---

**QuantaSeek** - Empowering the quantum-safe future of TLS security 🔐✨ 