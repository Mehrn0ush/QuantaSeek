# QuantaSeek

QuantaSeek is a command-line TLS scanner, written in Rust, that connects to an
endpoint, completes a real TLS handshake with [rustls](https://github.com/rustls/rustls),
and reports which key exchange group and certificate algorithms were
negotiated. Its focus is post-quantum cryptography (PQC): whether an endpoint
negotiates a hybrid ML-KEM group such as `X25519MLKEM768`, and whether its
certificate uses ML-DSA, SLH-DSA or composite ML-DSA.

**Status: pre-1.0 research prototype.** The output format is not stable and
several reported fields are estimates rather than measurements (see
[Limitations](#limitations)). Do not use it as the sole basis for an audit
finding yet. [ROADMAP.md](ROADMAP.md) describes the plan to get there.

## What it observes

For each target, QuantaSeek makes one full handshake through rustls (aws-lc-rs
provider) and reports:

| Field | Source | Observed or inferred |
|---|---|---|
| `tls_version`, `cipher_suite` | rustls / raw ServerHello | Observed |
| `key_exchange` (e.g. `X25519MLKEM768`) | `key_share` in the raw ServerHello, or the group rustls reports as negotiated | Observed |
| `pqc_detected`, `analysis.hybrid_detected` | Negotiated group looked up in the IANA registry | Derived from an observed value |
| `certificate.*` (leaf only) | Peer certificate parsed with x509-parser | Observed, but see the redirect limitation |
| `analysis.pqc_signature_used` (TLS 1.3) | Signature scheme in the server's CertificateVerify, captured from the rustls verifier | Observed |

Codepoints and OIDs come from one table in [`src/constants.rs`](src/constants.rs),
where each entry cites its source (IANA TLS registries, NIST CSOR, RFC 10024,
RFC 9881, RFC 9909, RFC 9935, RFC 10073). It was last checked against those
sources on 2026-11-13.

### What it can and cannot negotiate

QuantaSeek can only report a group that rustls itself offers. With rustls
0.23.46 and the `prefer-post-quantum` feature, the ClientHello offers, in order:
`X25519MLKEM768`, `x25519`, `secp256r1`, `secp384r1`. As a result:

- A server that supports `X25519MLKEM768` is reported as PQC-capable.
- A server that supports **only** `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`,
  pure `MLKEM768`/`MLKEM1024`, or another PQC group negotiates a classical
  group (or fails). It is reported as classical. This is a false negative.
- QuantaSeek does not enumerate the groups a server supports, its preference
  order, or its HelloRetryRequest and downgrade behaviour.

## Build

Requires Rust 1.88 or later and a C compiler (for aws-lc-sys).

```bash
git clone https://github.com/Mehrn0ush/QuantaSeek.git
cd QuantaSeek
cargo build --release
```

## Usage

```bash
# One target; JSON result on stdout, progress on stderr
./target/release/quantaseek example.com

# Only the JSON result (stderr limited to errors)
./target/release/quantaseek -q example.com | jq '.key_exchange, .pqc_detected'

# Several targets, human-readable summary
./target/release/quantaseek -f text example.com cloudflare.com

# Debug logging on stderr
./target/release/quantaseek -v example.com
```

Options (`quantaseek --help`):

| Option | Meaning |
|---|---|
| `-f, --format json\|text` | Output format (default `json`) |
| `-p, --profile <name>` | Profile label recorded in the output. It does not change the ClientHello (see Limitations). |
| `--tls12` | When no certificate was obtained, retry with a separate handshake to fetch one |
| `--connect-timeout <SECS>` | TCP connect timeout (default 5) |
| `--handshake-timeout <MS>` | TLS read/write timeout (default 5000) |
| `-q, --quiet` / `-v, --verbose` | Log level on stderr (`-vv` for trace) |
| `-V, --version` | Version from `Cargo.toml` |

Results go to stdout; all logging goes to stderr.

## Limitations

These were confirmed on 2026-11-13 by running the scanner or reading the code.
They are not fixed yet, and each one is scheduled in [ROADMAP.md](ROADMAP.md).

**Detection**
- Profiles (`standard`, `hybrid-pqc`, `pqc-only`, `cloudflare-pqc`) all send
  the same ClientHello. Run on 2026-11-13, `-p standard` still negotiated
  `X25519MLKEM768` against google.com. The profile "fallback chain" therefore
  repeats an identical handshake.
- Only the leaf certificate is analysed. Intermediates and the root are not
  inspected for PQC or composite algorithms.
- A server whose chain does not validate against the webpki-roots bundle fails
  the handshake. It is reported as a connection failure, not as a certificate
  finding.

**Targeting**
- `host:port` targets do not work. `example.com:443` fails with
  `connection_failed`, and the handshake is always made to port 443, whatever
  port the reachability probe used.
- A target is treated as "experimental/QUIC" because of substrings in its
  hostname (for example `quic`, `oqstest.net`, `duckdns.org`). Hostnames
  containing `test`, `demo` or `experimental` also change fallback behaviour.

**QUIC**
- No QUIC handshake is performed. The scanner has no QUIC dependency. Results
  tagged `"connection_type": "quic"` come from a TCP/TLS handshake to the same
  host, and their `tls_version` is hard-coded to `1.3`.

**Certificates and redirects**
- After the handshake, QuantaSeek follows HTTP redirects with a separate HTTPS
  client. If the final destination's certificate differs, it **replaces** the
  target's certificate in the report. Run on 2026-11-13, scanning `google.com`
  reported the certificate of `www.google.com`.
- Certificate Transparency lookup is a stub that always returns nothing.

**Reported values that are not measurements**
- `performance_analysis.overhead_analysis`, `analysis.hybrid_details.efficiency`
  and `fallback_analysis` (for example `time_penalty_ms: 200` and
  `trigger_reason: "PQC handshake failed..."`) are fixed estimates, not
  measured values.
- `extension_usage` lists extensions with assumed lengths, not parsed ones.
- `extension_map` and `tls_features` hard-code session ticket, OCSP, PSK and
  early-data status as absent.
  "Session tickets not enabled" recommendations follow from that, not from the
  server.
- `security_score` is a fixed weighted formula (TLS 30 / certificate 25 / PQC
  45). It is not tied to any published policy. Some of its PQC sub-scores label
  `X25519MLKEM768` as "Level 1 / 128 bits", which is wrong: ML-KEM-768 is NIST
  Category 3.

## Accuracy policy

The project's rule, applied from Phase 1 onwards:

- Every codepoint and OID cites its source.
- A value that was inferred rather than observed must be labelled as inferred.
- When the scanner cannot observe something, it reports "unknown" or "not
  implemented" instead of a default.

Where current output breaks this rule, the breach is listed above. Fixing those
cases is the first milestone in the roadmap.

## Responsible use

Scan only systems you own or are authorised to test. Each scan opens several
TCP connections and makes HTTPS requests (redirect detection). There is no rate
limiting yet, so do not run it against third-party hosts at volume.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets          # no network access needed
cargo test -- --ignored           # network-dependent tests
cargo audit
cargo deny check
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of these on
Linux and macOS, and checks the MSRV (1.88).

## License

No license has been chosen yet, so no rights are granted beyond viewing the
source. See [ROADMAP.md](ROADMAP.md) for the options under consideration.
