# QuantaSeek: Features, Capabilities, and Limitations

This document describes the features, capabilities, and limitations of the QuantaSeek PQC TLS scanner. It is the authoritative supplement to the [README](README.md).

---

## Features

### Real TLS handshakes

- Uses **rustls** for actual TLS 1.3 and TLS 1.2 connections (no simulation).
- Connection establishment, handshake, and record capture are performed against real servers.
- Raw TLS records (including ServerHello) are captured where supported for analysis.

### PQC detection

- **KEM-based:** Detection of ML-KEM-512 (NIST L1), ML-KEM-768 (L3), ML-KEM-1024 (L5); Kyber aliases are supported. Hybrid key exchange (e.g. X25519 + ML-KEM-768) is detected.
- **Certificate-based:** PQC signature algorithms (Dilithium2/3/5, Falcon512/1024, SPHINCS+) are identified via certificate OID analysis where the certificate is available.
- **Raw TLS parsing:** Cipher suites and key exchange algorithms are extracted directly from ServerHello when raw records are available (see Limitations).

### Client profiles and fallback

- **Classic (standard):** TLS 1.3 with classical algorithms only.
- **Fallback (cloudflare-pqc):** PQC-enabled profile with fallback support (default).
- **Hybrid (hybrid-pqc):** Hybrid PQC with classical fallback.
- **MaxPQC (pqc-only):** PQC-only configuration (experimental).
- Profile selection is via the `--profile` CLI option.

### Certificate analysis

- **RFC 6125:** Hostname verification is performed according to RFC 6125.
- **Algorithm consistency:** Public key algorithm and signature algorithm are checked for consistency.
- **OID extraction:** Signature algorithm OIDs are extracted for PQC signature detection.
- **SAN and validity:** Subject Alternative Names and validity dates are parsed and reported.
- All certificate data is from real handshakes; no mock data is used.

### Security scoring

- **PQC-enabled handshakes:** Overall = TLS (30%) + Certificate (25%) + PQC (45%).
- **Classical-only:** Overall = TLS (50%) + Certificate (50%).
- **Explainability:** JSON output includes formula strings and sub-scores (e.g. TLS, certificate, PQC components).
- **NIST levels:** FIPS 203 security levels (L1/L3/L5) are reflected in the scoring where applicable.

### QUIC support

- QUIC-capable servers are detected; the scanner may perform TCP/TLS fallback to obtain certificates and TLS details.
- Fallback uses retry logic (minimum 3 attempts), multiple ports (443, actual port, 8443), and extended timeouts (minimum 8 seconds) for rate-limited servers.
- Certificate extraction for QUIC is done via TLS 1.2 fallback only (see Limitations).

### HTTP redirect detection

- The scanner can detect HTTP redirects (e.g. HTTP → HTTPS) when connecting to targets; this is used to inform connection behaviour and can be reported in verbose output.

### Performance timing

- Handshake duration and total scan duration are reported in milliseconds.
- Output may include performance analysis: handshake timing category (e.g. excellent, good, slow) and overhead breakdown (certificate, network, PQC) where applicable.

### Output formats and CLI options

- **Formats:** JSON (default) and text via `--format json` or `--format text`.
- **Options:** `--profile`, `--tls12`, `--ignore-mismatch`, `--quiet` / `-q`, `--verbose` / `-v`, plus standard `--help` and `--version`.
- **Quiet mode:** Suppresses banner, progress lines, and summary; only the result (JSON or text) is printed, suitable for scripts and automation.
- **Verbose / debug:** `-v` or `QUANTASEEK_DEBUG=1` enables debug and progress messages (e.g. QUIC fallback, HTTP redirect) on stderr.

---

## Capabilities

- **Single and batch scans:** One or multiple target hostnames can be supplied; each target is scanned and reported (with optional batch summary).
- **Dual stack (TCP + QUIC):** The tool uses TCP/TLS for primary handshakes and, when relevant, triggers TCP/TLS fallback for QUIC-capable servers to obtain certificate and key exchange information.
- **Fallback chains:** Retries and multiple port attempts form a fallback chain to improve success rate against varied server configurations.
- **Structured output:** JSON output is structured and suitable for parsing; text output is human-readable.
- **Library API:** The core logic is exposed as a library (see `src/lib.rs`) for use by other Rust crates; the CLI in `main.rs` is one consumer of this API.

---

## Limitations

### QUIC certificate extraction

- Certificate and key exchange information for QUIC servers is obtained **only via TCP/TLS 1.2 fallback**. Direct extraction from the QUIC connection is not implemented.
- **QUIC-only servers** that do not offer TCP/TLS on the same host/port may yield no certificate or key exchange data; in such cases the report will reflect missing or best-effort data.

### TLS 1.3 encrypted fields

- In TLS 1.3, the CertificateVerify message (and thus the negotiated signature algorithm used in the handshake) is encrypted. The scanner cannot report the actual handshake signature algorithm for TLS 1.3; it may be reported as "Unknown". PQC signature usage in the handshake is inferred where possible from certificate OIDs and other context.

### PQC detection gaps

- **Empty or missing raw ServerHello:** When the Classic profile or certain fallback paths are used, raw ServerHello may not be captured. In those cases, PQC detection that relies on raw TLS parsing is unavailable; key exchange may still be reported from the TLS stack where the stack exposes it.
- **Parsing issues:** Malformed or non-standard ServerHello or extensions can lead to incomplete or incorrect parsing; results are best-effort.

### HTTP redirect and network behaviour

- HTTP redirect detection depends on network conditions and server responses; behaviour may vary. Rate limiting, timeouts, and connectivity issues can cause scan failures or incomplete data.
- The tool does not implement a full browser-like redirect following policy; redirect handling is limited to what is documented and implemented in the handshake/redirect logic.

### Code quality and operational constraints

- **Panics and unwraps:** Some code paths may use `unwrap()` or similar; invalid or unexpected input can cause panics. Error handling is improved over time but not guaranteed panic-free in all code paths.
- **Logging:** Logging is controlled by CLI flags and environment (e.g. `QUANTASEEK_DEBUG`, `RUST_LOG`). Default behaviour is to avoid flooding stdout/stderr in production; use `--quiet` for script-friendly output.
- **Configuration:** There is no configuration file; behaviour is controlled via CLI options and environment variables only.
- **Test coverage:** Unit and integration test coverage exist but are not exhaustive; some code paths and edge cases may be undertested.

---

## TLS 1.3 vs QUIC reporting

| Aspect | TLS 1.3 (TCP) | QUIC |
|--------|----------------|------|
| **PQC key exchange** | Reported when available from the handshake / key_share. | Reported when available; typically from TCP/TLS fallback, so only if the server offers TCP/TLS and fallback succeeds. |
| **PQC signature** | **Authoritative** where the stack exposes it (e.g. via a CapturingVerifier or equivalent). | **Best-effort** via certificate OID analysis when a certificate is obtained (e.g. via TLS 1.2 fallback). If no certificate is obtained, signature may be reported as "Not Implemented" or omitted. |

In short: PQC **key exchange** is reported for both TLS 1.3 and QUIC where the scanner has data; PQC **signature** is authoritative for TLS 1.3 TCP when captured, and best-effort for QUIC (certificate OID or "Not Implemented" when no cert is available).

---

*This document is part of the QuantaSeek project. For installation, usage, and examples, see [README.md](README.md).*
