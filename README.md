# QuantaSeek - PQC-Aware TLS Scanner

A client-side scanning utility that establishes TLS connections to detect Post-Quantum Cryptography (PQC) support based on observed handshake parameters.

## 🎯 Purpose

QuantaSeek implements a command-line scanning tool that:
- Initiates TLS handshakes with remote hosts
- Sends crafted `ClientHello` messages supporting PQC (or hybrid) extensions
- Parses `ServerHello`, certificate, and extensions at the record level
- Extracts evidence of PQC support in key exchange or certificate signatures
- Reports results in structured, machine-readable JSON output

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd QuantaSeek

# Build the project
cargo build --release

# The binary will be available as 'pqcscan'
```

### Basic Usage

```bash
# Basic scan
./target/release/pqcscan example.com

# Scan with custom port
./target/release/pqcscan example.com:8443

# Force PQC-only handshake
./target/release/pqcscan example.com --profile=pqc

# Scan with extended timeout
./target/release/pqcscan example.com --timeout=10

# Human-readable output
./target/release/pqcscan example.com --output=stdout
```

## 📋 Command Line Options

| Parameter   | Type                                | Description                                             |
| ----------- | ----------------------------------- | ------------------------------------------------------- |
| `target`    | `hostname[:port]`                   | Required. Defaults to port `443` if omitted             |
| `--timeout` | integer (seconds)                   | Optional. Default: 5 seconds                            |
| `--profile` | enum: `pqc` \| `legacy` \| `hybrid` | Optional. Determines what kind of `ClientHello` to send |
| `--output`  | `json` \| `stdout`                  | Optional. Default is JSON output                        |

### Handshake Profiles

- **`legacy`**: Sends traditional TLS 1.3 ClientHello with classical algorithms only
- **`pqc`**: Sends ClientHello with Post-Quantum algorithms only
- **`hybrid`**: Sends ClientHello supporting both classical and PQC algorithms (default)

## 📤 Output Format

### JSON Output (Default)

```json
{
  "target": "example.com:443",
  "tls_version": "1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "key_exchange": ["x25519", "kyber1024"],
  "pqc_extensions": {
    "kem": true,
    "kem_group": true
  },
  "certificate": {
    "subject": "CN=example.com",
    "public_key_algorithm": "rsa",
    "signature_algorithm": "dilithium5",
    "key_size": 3072
  },
  "pqc_detected": true,
  "fallback": {
    "attempted": true,
    "succeeded": true
  },
  "analysis": {
    "pqc_key_exchange": ["kyber1024"],
    "pqc_signature_algorithms": ["dilithium5"],
    "pqc_public_key_algorithms": [],
    "hybrid_detected": true,
    "classical_fallback_available": true,
    "security_level": "High (~256-bit)"
  }
}
```

### Human-Readable Output

```
🔍 PQC TLS Scanner Results
═══════════════════════════
Target: example.com:443
TLS Version: 1.3
Cipher Suite: TLS_AES_256_GCM_SHA384

🔐 Key Exchange:
  x25519 🔒 (Classical)
  kyber1024 🚀 (PQC)

📜 Certificate:
  Subject: CN=example.com
  Public Key: rsa (2048 bits)
  Signature: dilithium5

🧪 PQC Extensions:
  KEM Support: ✅
  KEM Group Support: ✅

📊 PQC Analysis:
  PQC Detected: ✅ YES
  Security Level: High (~256-bit)
  Hybrid Mode: ✅ Detected
  Classical Fallback: ✅ Available
  PQC Key Exchange: kyber1024
  PQC Signatures: dilithium5

📋 Summary:
  🚀 This server supports Post-Quantum Cryptography!
  🛡️  High security level detected
  🔗 Hybrid mode provides classical fallback
```

## 🔍 Supported PQC Algorithms

### Key Exchange Mechanisms (KEMs)
- **Kyber family**: kyber512, kyber768, kyber1024
- **NTRU family**: ntru, ntru_hps, ntru_hrss
- **SABER family**: saber, lightsaber, firesaber
- **FrodoKEM family**: frodo, frodokem, frodo640, frodo976
- **Other lattice-based**: bike, hqc
- **Code-based**: mceliece, classic_mceliece

### Digital Signatures
- **Dilithium family**: dilithium2, dilithium3, dilithium5
- **Falcon family**: falcon512, falcon1024
- **SPHINCS+ family**: sphincs, sphincsplus
- **Hash-based**: xmss, lms
- **Multivariate**: rainbow, picnic

## 🏗️ Architecture

```
src/
├── main.rs              // CLI entrypoint and argument parsing
├── handshake.rs         // TLS handshake construction and execution
├── parser.rs            // Raw TLS record parsing
├── cert.rs              // X.509/DER certificate decoding
├── detector.rs          // PQC algorithm detection logic
├── output.rs            // JSON and human-readable output formatting
```

### Key Components

1. **HandshakeEngine**: Constructs and sends TLS ClientHello messages with different algorithm profiles
2. **TlsParser**: Parses raw TLS records (ServerHello, Certificate) without high-level TLS libraries
3. **CertificateParser**: Implements ASN.1/DER parsing for X.509 certificates
4. **PqcDetector**: Contains logic for identifying PQC algorithms and estimating security levels
5. **OutputFormatter**: Generates structured JSON and human-readable reports

## ⚡ Performance

- Target scan latency: < 3 seconds per host
- Memory efficient: minimal buffering, streaming parser
- Concurrent scans: supports async/await for multiple targets
- Lightweight: no heavyweight TLS library dependencies

## 🔒 Security Considerations

- **Client-side only**: No server-side privileges required
- **Read-only**: Only establishes connections, doesn't modify server state
- **Standard sockets**: Uses normal user TCP connections
- **No certificate validation**: Focuses on algorithm detection, not trust verification

## 📊 Exit Codes

- `0`: Successful scan completed
- `1`: Target unreachable or connection failed
- `2`: Invalid command line arguments
- `3`: TLS handshake parsing error

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Test with real servers (requires network)
cargo test --test live_servers -- --ignored
```

## 🚧 Current Limitations

1. **Certificate Chain**: Only parses the leaf certificate
2. **Extensions**: Limited to hypothetical PQC extension IDs
3. **TLS Versions**: Primarily targets TLS 1.3
4. **IPv6**: Currently supports IPv4 only

## 🔮 Future Enhancements

- [ ] Support for real PQC extension OIDs as they're standardized
- [ ] Complete certificate chain analysis
- [ ] TLS 1.2 with PQC cipher suites
- [ ] IPv6 support
- [ ] Batch scanning multiple targets
- [ ] Integration with threat intelligence feeds

## 🛠️ Development

### Building from Source

```bash
git clone <repository-url>
cd QuantaSeek
cargo build --release
```

### Dependencies

- **tokio**: Async runtime for networking
- **clap**: Command-line argument parsing
- **serde**: JSON serialization
- **anyhow**: Error handling
- **hex**: Hexadecimal encoding
- **chrono**: Timestamp generation

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- NIST Post-Quantum Cryptography Standardization
- OpenQuantumSafe project
- Rust TLS and cryptography community

---

**Note**: This tool is for security research and assessment purposes. PQC algorithm support detection is based on current draft specifications and may change as standards evolve. 