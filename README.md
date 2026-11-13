# QuantaSeek

QuantaSeek is a command-line TLS scanner, written in Rust. It connects to an
endpoint, completes a real TLS handshake with
[rustls](https://github.com/rustls/rustls), and reports what was negotiated:
TLS version, cipher suite, key-exchange group, the server's signature scheme,
and the certificate chain. Its focus is post-quantum cryptography (PQC):
whether an endpoint negotiates a hybrid or pure ML-KEM group, and whether its
certificates and handshake signatures are ML-DSA, SLH-DSA or composite
ML-DSA.

**Status: pre-1.0.** The output format is versioned (schema `0`) but can
still change. Every value in the output is labelled as observed, derived or
inferred, or is listed as not implemented (see [Output](#output)). What the
scanner cannot see is listed under [Limitations](#limitations).
[ROADMAP.md](ROADMAP.md) describes what comes next.

## Build

Requires Rust 1.88 or later and a C compiler (for aws-lc-sys).

```bash
git clone https://github.com/Mehrn0ush/QuantaSeek.git
cd QuantaSeek
cargo build --release
```

## Usage

```bash
# One target; one JSON object on stdout, progress on stderr
./target/release/quantaseek example.com

# Only the result (stderr limited to errors)
./target/release/quantaseek -q example.com | jq '.tls.key_exchange.name, .pqc.key_exchange.value'

# Explicit port, IPv6, or scanning by IP while validating a DNS name
./target/release/quantaseek example.com:8443 '[2001:db8::1]:443'
./target/release/quantaseek --sni www.example.com 192.0.2.10

# Does the server accept a ClientHello that offers only pure ML-KEM?
./target/release/quantaseek -p mlkem example.com

# Human-readable output for several targets
./target/release/quantaseek -f text example.com cloudflare.com
```

| Option | Meaning |
|---|---|
| `-p, --profile <name>` | Which key-exchange groups the ClientHello offers (table below). Default `default` |
| `-f, --format json\|text` | JSON Lines (one object per target) or text. Default `json` |
| `--sni <name>` | Name sent in SNI and validated against the certificate. Default: the target host |
| `--follow-redirects` | After the handshake, follow HTTP redirects and report them separately (off by default) |
| `--probe` | Also probe groups, preference, HelloRetryRequest, downgrade and ClientHello-size tolerance (off by default) |
| `--probe-budget <N>` | Maximum probes per target (default 40) |
| `--probe-spacing <MS>` | Minimum milliseconds between probes, at least 100 (default 100, plus up to 50% jitter) |
| `--connect-timeout <SECS>` | TCP connect timeout (default 5) |
| `--handshake-timeout <MS>` | TLS read/write timeout (default 5000) |
| `--print-schema` | Print the output's JSON Schema and exit |
| `-q, --quiet` / `-v, --verbose` | Log level on stderr (`-vv` for trace) |

Results go to stdout and logs to stderr. A target with no port is scanned on
443 only.

### Probing (`--probe`)

The default scan is one handshake. `--probe` adds up to `--probe-budget` more
TCP connections, each sending a hand-built TLS 1.3 ClientHello and reading
only the server's first reply. The probes cover:
- every group alone, with its key share
- pairs of accepted groups, in both orders
- each accepted group listed with no key share (HelloRetryRequest)
- PQ and classical groups listed with only a classical share (downgrade)
- the same offer sent normally, padded to 2048 bytes, split into 512-byte
  records, and split across TCP segments (tolerance)

Probing stops early after 3 consecutive connection failures. Results are in
`probe`, with provenance `observed`.

```bash
./target/release/quantaseek -q --probe example.com | jq '.probe.accepted_groups, .probe.downgrade.behaviour'
```

### Profiles

Each profile changes the ClientHello. Profiles use only groups that the linked
rustls 0.23.46 / aws-lc-rs 1.19.0 implement. rustls sends a key share for the
first group, so a server that wants a different offered group answers with a
HelloRetryRequest (reported as `tls.hello_retry_request`).

| Profile | Groups offered, in order | TLS versions |
|---|---|---|
| `default` | X25519MLKEM768, x25519, secp256r1, secp384r1 | 1.3, 1.2 |
| `classical` | x25519, secp256r1, secp384r1 | 1.3, 1.2 |
| `hybrid` | X25519MLKEM768, SecP256r1MLKEM768 | 1.3 |
| `mlkem` | MLKEM1024, MLKEM768 | 1.3 |
| `all` | X25519MLKEM768, SecP256r1MLKEM768, MLKEM1024, MLKEM768, x25519, secp256r1, secp384r1 | 1.3, 1.2 |

One profile means one handshake. To compare a server's behaviour across
profiles, run the scanner once per profile.

## Output

Each target produces one JSON object (schema version `"0"`). The full schema is
[`schema/scan-result.v0.json`](schema/scan-result.v0.json), and
`quantaseek --print-schema` prints the same schema. Tests check that the
committed file matches the code.

How each part of the output is sourced:

| Part | Provenance |
|---|---|
| `tls` (version, cipher suite, key exchange, HelloRetryRequest, server signature scheme) | **Observed** in the handshake |
| `certificate_chain` | **Observed**: every certificate the server sent, leaf first, including chains that fail validation. Algorithms are named from cited OID tables |
| `evidence.server_hellos_hex` | **Observed**: the raw ServerHello (and HelloRetryRequest) messages |
| `http_redirect` | **Observed**, only with `--follow-redirects`. Never replaces the target's certificate |
| `pqc.*` | **Derived**: each has a `value`, `provenance: "derived"`, and the `basis` (the registry rule applied to an observed value) |
| `outcome.error.interpretation` | **Inferred**: the likely cause of a failure, labelled `provenance: "inferred"` |
| `probe` | **Observed**, only with `--probe`: the server's first reply to each hand-built ClientHello |
| `certificate_validation` | **Observed**: whether rustls/webpki accepted the chain (`valid`, `invalid` with `reason`, or `not_reached`) |
| `not_implemented` / `not_requested` | What this version does not observe at all, and what exists but was not requested. An absent value is never a "no" |

A failed scan carries `outcome.error`, with a stable `code` and a `category`
(examples: [`tests/golden/`](tests/golden/)):

| Category | Codes | Meaning |
|---|---|---|
| `server_result` | `handshake_rejected` (with the TLS `alert`), `certificate_rejected`, `protocol_error`, `connection_closed` | The server answered. The answer is a finding about the server, not a scan failure |
| `network` | `dns_failed`, `connection_refused`, `connection_timeout`, `handshake_timeout`, `connection_reset`, `connection_failed` | No usable answer |
| `scanner` | `invalid_target`, `handshake_failed`, `unknown` | Input error, or a failure the scanner did not classify |

For example, `-p mlkem` against a server without ML-KEM usually gives
`handshake_rejected` with alert `HandshakeFailure`, plus an inferred
interpretation. The scanner cannot confirm from one handshake that the cause
was the groups rather than another negotiation failure.

Codepoints and OIDs come from [`src/constants.rs`](src/constants.rs), where
each entry cites its source (IANA TLS registries, NIST CSOR, RFC 10024, RFC
9881, RFC 9909, RFC 9935, RFC 10073). The table was last checked on 2026-11-13.

## Limitations

These describe the tool after milestone M3, as of 2026-11-13.

**What the handshake can test**
- The full handshake (rustls) can only offer the groups in the profile
  table. A server that supports only SecP384r1MLKEM1024 or MLKEM512 fails the
  handshake. `--probe` still finds such groups, but the certificate and
  handshake signature are then not observed for them.
- The prober covers the ten groups it can generate keys for (x25519,
  secp256r1/384r1/521r1, MLKEM512/768/1024, X25519MLKEM768,
  SecP256r1MLKEM768, SecP384r1MLKEM1024). x448, FFDHE, curveSM2MLKEM768,
  MLKEM1024X448, the ML-KEM-512 hybrids and the obsolete Kyber drafts are
  listed as `not_probed`, with the reason.
- Probes offer TLS 1.3 only. A TLS 1.2-only server rejects every probe.
- Without `--probe`, a `handshake_rejected` under a restrictive profile is
  reported with an *inferred* cause. With `--probe`, the per-group results
  show whether the server accepts any of the offered groups.
- QUIC is not implemented. Every result is TCP/TLS.
- ALPN is not offered. OCSP stapling, session resumption, early data,
  Certificate Transparency and revocation are not observed (all listed in
  `not_implemented`).

**Certificates**
- The chain is validated by rustls/webpki against the webpki-roots bundle.
  webpki 0.103 verifies ECDSA, Ed25519, RSA and ML-DSA-44/65/87 signatures,
  but not SLH-DSA, composite ML-DSA or Ed448. Such chains get
  `certificate_validation.status: "invalid"`, even when correctly signed. The
  chain is still reported as sent.
- `pqc.certificate_chain` counts a certificate as post-quantum when its own
  signature algorithm is ML-DSA, SLH-DSA or composite ML-DSA. Whether the
  leaf's key is post-quantum shows in `pqc.handshake_signature`.
- Composite ML-DSA and HashML-DSA are recognised by OID only. No testbed
  fixture exists for them, because no maintained implementation produces
  RFC 10073 composites.

**Operation**
- Targets are scanned one after another. There is no concurrency and no
  target-file or CIDR input yet (ROADMAP M5). Within one target, probes are
  spaced and capped (see `--probe`).
- The exit code is 0 whenever output was produced, even if a target failed.
  Check `outcome.status`.

## Responsible use

Scan only systems you own or are authorised to test. A default scan opens one
TCP connection and performs one handshake per target. `--probe` adds up to 40
connections, at least 100 ms apart. `--follow-redirects` adds HTTPS requests. There is no rate limiting yet, so do not run it against
third-party hosts at volume.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets          # loopback only, no internet access
cargo audit
cargo deny check
```

The integration tests (`tests/`) run in-process rustls servers on 127.0.0.1
with throwaway CAs and chosen key-exchange groups. They cover ports, SNI,
profiles, outcome classification, redirects and the output schema. To refresh
the golden files after an intended output change, run
`UPDATE_GOLDEN=1 cargo test --test schema`. After changing the report types,
regenerate the schema with
`quantaseek --print-schema > schema/scan-result.v0.json`.

### Testbed

[`testbed/`](testbed/README.md) runs 17 TLS servers in Docker, each with a
known configuration: OpenSSL 3.5.9 and Go 1.27, with ML-KEM hybrid and pure
groups, HelloRetryRequest, TLS 1.2, ML-DSA and SLH-DSA chains, and expired,
mismatched and self-signed certificates, a hybrid+classical server, and a
ClientHello-size middlebox. `testbed/confirm.sh` checks every
server with `openssl s_client`, independently of QuantaSeek, and
`tests/testbed.rs` asserts the same values against the scanner:

```bash
docker compose -f testbed/compose.yml up -d --build --wait
sh testbed/confirm.sh
cargo test --features testbed --test testbed
```

The prober's expected results are the per-group acceptance matrix that
`confirm.sh` builds with `openssl s_client`.

### Fuzzing

```bash
cd fuzz && cargo +nightly fuzz run server_hello -- -max_total_time=300
```

The targets are `server_hello` (record splitter, ServerHello and
HelloRetryRequest extraction), `server_reply` (the prober's reply parser),
`certificate_report` (X.509 wrapper) and `target_parse`.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs fmt, clippy,
tests on Linux and macOS, an MSRV (1.88) check, audit and deny. It also has
an offline-test job, a testbed job, and a nightly fuzz workflow. None of
these workflows has run on GitHub yet.

## License

No license has been chosen yet, so no rights are granted beyond viewing the
source. See [ROADMAP.md](ROADMAP.md) for the options under consideration.
