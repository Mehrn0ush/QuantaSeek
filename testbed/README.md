# QuantaSeek testbed

TLS servers whose configuration is known independently of QuantaSeek. They
exist so that detection can be proven correct against ground truth, rather
than assumed correct from what the scanner printed.

```bash
docker compose -f testbed/compose.yml up -d --build --wait
sh testbed/confirm.sh                                 # ground truth via openssl s_client
cargo test --features testbed --test testbed          # QuantaSeek against it
cargo test --features testbed --test testbed -- --ignored   # M3's definition of done (fails today)
docker compose -f testbed/compose.yml down
```

## Images

- `alpine:3.23@sha256:469c9ea4…` with `openssl=3.5.9-r0`
- `golang:1.27-alpine3.23@sha256:7a93747a…` (build stage only)

Both digests are multi-arch indexes covering linux/amd64 and linux/arm64. One
image (`quantaseek-testbed:local`) serves every service. Its entrypoint
generates the server's keys and certificates at start-up, copies only
`ca.pem`, `chain.pem` and `config.txt` to `testbed/run/<service>/`
(git-ignored), and then runs the server. Private keys never leave the
container, and none are committed. Every port is bound to 127.0.0.1.

## What the implementations support

These lists come from the pinned build itself, not from memory:
- `openssl list -tls-groups -tls1_3`: secp256r1, secp384r1, secp521r1,
  x25519, x448, brainpool*tls13, ffdhe*, MLKEM512, MLKEM768, MLKEM1024,
  SecP256r1MLKEM768, X25519MLKEM768, SecP384r1MLKEM1024.
- `openssl list -tls-signature-algorithms`: includes mldsa44, mldsa65 and
  mldsa87, but no SLH-DSA. SLH-DSA can sign certificates
  (`openssl list -signature-algorithms` lists id-slh-dsa-*), but cannot sign a
  TLS handshake.
- Go 1.27 `crypto/tls` CurveIDs include X25519MLKEM768, SecP256r1MLKEM768,
  SecP384r1MLKEM1024 and MLKEM1024 (pkg.go.dev/crypto/tls, go1.27.4).

## Servers and their ground truth

`confirm.sh` also builds a per-group acceptance matrix: each server is offered
each of the ten groups the prober can generate, one at a time. The prober's
`accepted_groups` must equal that set for every server (67 checks in total).

The second column of the table is the configuration, from compose.yml and the
entrypoint. The third column is the independent confirmation: `confirm.sh`
running `openssl s_client` from the same image, inside the container.

| Service (port) | Configuration | Confirmed by `confirm.sh` | QuantaSeek today |
|---|---|---|---|
| x25519mlkem768 (44301) | s_server `-groups X25519MLKEM768 -tls1_3`, ECDSA P-256 chain | negotiates X25519MLKEM768; a client offering only x25519 gets alert 40 | sees it (`default`) |
| secp256r1mlkem768 (44302) | `-groups SecP256r1MLKEM768` | negotiates SecP256r1MLKEM768; an X25519MLKEM768-first offer gets two ServerHellos (HRR) | sees it (`hybrid`, with HRR); `default` is rejected |
| secp384r1mlkem1024 (44303) | `-groups SecP384r1MLKEM1024` | negotiates SecP384r1MLKEM1024; an offer of all seven rustls groups gets alert 40 | full handshake rejected (rustls cannot offer the group); `--probe` reports it accepted |
| mlkem1024 (44304) | `-groups MLKEM1024` | negotiates MLKEM1024; MLKEM768:x25519 gets alert 40 | sees it (`mlkem`) |
| mlkem512 (44305) | `-groups MLKEM512` | negotiates MLKEM512; an offer of all seven rustls groups gets alert 40 | full handshake rejected; `--probe` reports it accepted |
| classical (44306) | `-groups x25519:secp256r1`, TLS 1.2 and 1.3 | Peer Temp Key X25519 (also with the `default` offer); PQ-only offers get alert 40 | sees it |
| hrr-secp384r1 (44307) | `-groups secp384r1 -tls1_3` | two ServerHellos when the first share is not secp384r1; Peer Temp Key secp384r1 | sees it, reports `hello_retry_request: true` |
| hybrid-and-classical (44309) | `-groups X25519MLKEM768:x25519 -tls1_3` | accepted set {x25519, X25519MLKEM768}; with both shares OpenSSL follows the client's order; PQ listed without a share plus an x25519 share → x25519, one ServerHello (no HRR) | sees it; `--probe` downgrade `accepted_classical_share` |
| tls12-classical (44308) | `-groups x25519:secp256r1 -tls1_2` | TLSv1.2, Peer Temp Key X25519; with rustls's sigalg order the signature is ecdsa_secp384r1_sha384 (SHA-384 digest); a TLS 1.3 client gets a protocol_version alert | sees it (`classical`) |
| cert-mldsa65 (44311) | ML-DSA-65 root → ML-DSA-65 leaf | Peer signature type mldsa65; verify OK; `storeutl` shows ML-DSA-65 key and signature | sees it |
| cert-mldsa65-intermediate (44312) | ECDSA root → ML-DSA-65 intermediate → ECDSA leaf | verify OK; chain position 1 is the ML-DSA-65 intermediate; leaf signed with ML-DSA-65 | sees it (`certificate_chain: mixed`) |
| cert-slhdsa-ca (44313) | SLH-DSA-SHA2-128s root → ECDSA leaf | OpenSSL verifies the chain; leaf signature SLH-DSA-SHA2-128s `certificate_rejected` (webpki 0.103 cannot verify SLH-DSA); chain reported with family `slh_dsa` |
| cert-expired (44314) | leaf valid 2025-01-01 to 2025-02-01 | verify code 10 (certificate has expired) `certificate_rejected`; chain reported as sent |
| cert-mismatch (44315) | leaf SAN `DNS:other.invalid` only | verify code 62 (hostname mismatch) `certificate_rejected`; chain reported as sent |
| cert-self-signed (44316) | self-signed leaf; the exported CA did not issue it | verify code 18–21 `certificate_rejected`; chain reported as sent |
| middlebox-1024 (44331) | Go proxy closing any connection whose first record exceeds 1024 bytes, in front of s_server `-groups x25519` | by construction (`go/main.go`); s_client with x25519 completes, with X25519MLKEM768 (larger first record) gets no ServerHello | `--probe`: X25519MLKEM768 `closed`, padded `closed`, split records and split segments `ok` |
| go-x25519mlkem768 (44321) | Go 1.27 `crypto/tls`, `CurvePreferences = [X25519MLKEM768]`, TLS 1.3 | negotiates X25519MLKEM768; x25519:secp256r1 gets alert 40 | sees it |

## Not built, and why

- **X25519Kyber768Draft00 (0x6399).** It is absent from OpenSSL 3.5.9's group
  list, and the oqs-provider algorithm table (main branch, checked
  2026-11-13) lists no pre-standard Kyber groups. No maintained
  implementation serves it, so it is left out rather than approximated.
- **Composite ML-DSA (RFC 10073).** OpenSSL 3.5.9 has no composite
  signatures. oqs-provider's composites (`p256_mldsa44`, …) use prototype
  OIDs under 1.3.9999.7, not the RFC 10073 arc 1.3.6.1.5.5.7.6.37–54, so a
  fixture built from them would test a different algorithm under the same
  name.
- **HashML-DSA leaf.** OpenSSL 3.5.9 cannot produce one (no id-hash-ml-dsa
  signature algorithm), and RFC 9881 §8.3 forbids it in certificates.
- **QUIC server.** Not added: the direct QUIC Initial prober is not built yet
  (see ROADMAP M3).
- **rustls `tlsserver-mio`.** rustls servers already run in-process in
  `tests/support`, so a container would duplicate them.
