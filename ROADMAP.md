# QuantaSeek Roadmap

*Written 2026-11-13, at the end of Phase 0 (audit) and Phase 1 (foundation),
on branch `phase1-foundation`. Updated the same day after milestone M1
(Truthful output) on branch `m1-truthful-output` (§1.6, §5 M1), and after
milestone M2 (Deterministic testbed) on branch `m2-testbed` (§1.7, §5 M2).*

This document has nine parts:

1. Where the project stands: what works, what doesn't, which claims were false.
2. The standards landscape the product must track.
3. Competitors, and where QuantaSeek can be distinctly better.
4. The target product and who buys it.
5. The technical roadmap as sequenced milestones with runnable acceptance criteria.
6. Production readiness.
7. Commercial options, with a recommendation.
8. Decisions needed from the owner.
9. Appendix: verification log and sources.

Labels used throughout: **[ran]** means verified by running something,
**[read]** means concluded from reading code, and **[secondary]** means it
comes from a secondary source not checked against the primary document.

---

## 1. Honest assessment

### 1.1 What QuantaSeek is today

QuantaSeek is a single Rust crate (library plus a `quantaseek` binary) of about
11k lines. It completes one TLS handshake per target through rustls 0.23
(aws-lc-rs provider) and reports the negotiated version, cipher suite and key
exchange group, plus fields parsed from the leaf certificate. Around that core
sits a large amount of derived output: scores, "hybrid efficiency", "KEM
negotiation", "extension usage" and performance analysis. Much of that derived
output is estimated, assumed or invented (§1.3).

**What genuinely works [ran]:**
- **Negotiated group.** It reads the group from `ServerHello.key_share`. Against
  google.com, cloudflare.com, example.com, pq.cloudflareresearch.com and
  microsoft.com it reported `X25519MLKEM768`, consistent with those sites.
- **Leaf certificate fields.** Subject, issuer, SAN, validity, key algorithm and
  size. Validity is checked against webpki-roots by rustls.
- **TLS 1.3 CertificateVerify scheme.** It is captured from the rustls verifier
  callback, which is a sound way to detect ML-DSA handshake signatures once a
  server presents one.

### 1.2 State at the start of the audit (before Phase 1)

| Check | Result |
|---|---|
| `cargo build` | OK, 4 warnings [ran] |
| `cargo test` | 31 passed. One test hit example.com over the network [ran] |
| `cargo clippy --all-targets` | About 30 warnings [ran] |
| `cargo fmt --check` | Diff [ran] |
| `cargo audit` | **32 vulnerabilities, 5 warnings** [ran]. Includes RUSTSEC-2026-0349, a rustls advisory in which an unauthenticated ServerHello can downgrade later connections to classical: directly relevant to a PQC scanner. |
| `cargo deny check` | Failed: no config, 283 license rejections, 3 advisories [ran] |
| CI, LICENSE, tests/ | None |

### 1.3 Claims that were false

The README and FEATURES_AND_LIMITATIONS.md made these claims. The table gives
the reality.

| Claim | Reality |
|---|---|
| "Production-ready", "100% accurate certificate analysis", "no mock data" | Several reported values were defaults or constants presented as data (below). |
| Four client profiles: Classic, Hybrid, MaxPQC, Fallback | Every profile sends the identical rustls default ClientHello [read]. `-p classic` still negotiated `X25519MLKEM768` with google.com [ran]. The profile "fallback chain" repeats the same handshake. **Fixed in M1** (93b8a38): profiles configure real group lists. |
| "Classic = TLS 1.2 only" | It still offers TLS 1.3 and X25519MLKEM768 [read, ran]. |
| QUIC support with certificate extraction | No QUIC handshake ever happens. `perform_quic_with_cert_extraction` is a stub returning `None`; quinn was a dependency but unused (removing it changed nothing) [read, ran]. "QUIC" results are TCP/TLS handshakes labelled `connection_type: "quic"` with `tls_version` hard-coded to `"1.3"`. A target counts as "QUIC" because of hostname substrings. **Removed in M1** (601a7b6); QUIC is listed as not implemented. |
| Detects Dilithium/Falcon/SPHINCS+ certificates | It matched draft or invented OIDs and codepoints (§1.4). It would not have recognised a real FIPS 204 ML-DSA certificate signed with RFC 10073 composite OIDs. |
| PQC KEM/KEM_GROUP extensions (0xFE00/0xFE01, 0xFE50/0xFE51) | These extensions do not exist in any registry. They were never sent; tests asserted they were "offered" via a helper that nothing called. |
| `kem_negotiation.client_offered` | A per-profile list (Kyber768, ML-KEM-512, ML-KEM-1024, …) that the ClientHello never contained. Fixed in Phase 1. |
| `hybrid_details.efficiency`, `fallback_analysis` | Constants: 150 ms overhead, 1024 bytes, 25% CPU, 2048 bytes memory, `time_penalty_ms: 200`, `trigger_reason: "PQC handshake failed, falling back to classical"`. They are emitted even when nothing failed [read]. **Removed in M1** (c76b46c). |
| Performance "overhead analysis", "percentile" | Lookup tables keyed on algorithm name and certificate size, not measurements [read]. **Removed in M1** (c76b46c). |
| Session tickets / OCSP / PSK / early data | Hard-coded `false`, which produces "Session tickets not enabled" recommendations [read, ran]. **Removed in M1**; listed in `not_implemented` instead (c76b46c). |
| Certificate for the scanned host | After the handshake, HTTP redirects are followed and the final destination's certificate **replaces** the target's. Scanning `google.com` reports `www.google.com`'s certificate [ran]. **Fixed in M1** (8cd3cf1): redirects are opt-in and reported separately. |
| `host:port` targets | `example.com:443` fails with `connection_failed`. The handshake is always to port 443, whatever port the probe used [ran, read]. **Fixed in M1** (65a5e07). |
| Certificate Transparency lookup | A stub that returns `None` [read]. |
| RSA key size | The hand-rolled DER parser assumed short-form lengths, so it failed on every real RSA key and silently defaulted to 2048 [read]. Fixed in Phase 1. |
| Certificate validation score | `u8` arithmetic could subtract 115 from 100. That panics in debug builds; in release it wraps, so an expired, mismatched certificate could score 100 [read]. Fixed, with a regression test. |
| QUIC certificate scores | "Assume valid for QUIC": 80/80 certificate sub-scores with no certificate [read]. Dead code, removed. |
| MIT license badge | There was no LICENSE file. |
| `--ignore-mismatch` | Parsed, then never read. Removed. |

### 1.4 Codepoint and OID errors

These were confirmed against primary sources (§9) and fixed in Phase 1.

- **Supported groups.**
  - 4587 (0x11EB) was labelled X25519MLKEM512. It is **SecP256r1MLKEM768**.
  - 4589 (0x11ED) was labelled X25519MLKEM1024. It is **SecP384r1MLKEM1024**.
  - 25498 (0x639A) was labelled X25519Kyber512. It is **SecP256r1Kyber768Draft00** (obsolete).
  - 4590/4591 were invented "P256 hybrids". They are assigned, but to
    **curveSM2MLKEM768** and **MLKEM1024X448** (both drafts).
  - 4592 is unassigned.
  - 4585/4586 (ML-KEM-512 hybrids, draft) were missing.
  - 0x11EC was additionally treated as a "hybrid cipher suite".
- **Signature schemes.**
  - Dilithium codepoints 0x0B01–0x0B03 and 0xFEA0–0xFEA9 were invented or experimental.
  - The real assignments are **mldsa44/65/87 = 0x0904–0x0906**
    (draft-ietf-tls-mldsa) and **slhdsa_* = 0x0911–0x091C** (draft-reddy-tls-slhdsa).
  - The classical table had wrong names: 0x0809–0x080B are `rsa_pss_pss_*`, not
    `rsa_pss_rsae_*`. 0x080C/0x080D are not ECDSA.
- **Extensions.** The table was misnumbered from 0x001C on, so `key_share`
  appeared as 0x001C. It is 0x0033.
- **OIDs.**
  - The composite arc 2.16.840.1.114027.80.8.1.x (old draft) is replaced by
    **RFC 10073: 1.3.6.1.5.5.7.6.37–.54**.
  - 1.3.6.1.4.1.2.267.1.x "Kyber/ML-KEM/Dilithium" OIDs were not real
    assignments, and the OQS/IBM Round-3 OIDs (1.3.9999.x, …2.267.7.x) could not
    be verified, so both were dropped.
  - ML-KEM SPKI OIDs (2.16.840.1.101.3.4.4.1–3, RFC 9935) were missing.
  - HashML-DSA OIDs (…3.32–.34) are now flagged: RFC 9881 §8.3 says they MUST
    NOT appear in certificates. That becomes a natural finding in M4.
- **Security categories.** ML-KEM-768 was "Level 2" and ML-KEM-1024 "Level 3".
  FIPS 203 says Category 3 and Category 5.
- **Heuristics.** Substring matching treated "lms", SIKE (broken), Rainbow
  (broken), Picnic, "NTRU" and the bare word "PQC" as PQC evidence. That is gone:
  the only test now is a registry lookup.

### 1.5 Phase 1 changes (this branch)

| Commit | Change |
|---|---|
| 2355031 | Committed the February WIP (ErrorCode/ScanError model) after review |
| 489871a | Repo root cleaned. Scan outputs, `test_debug` and zsh scripts moved to an ignored `.archive/`; `.gitignore` rewritten |
| e2eb88a | rustfmt |
| 6b975e2 | Dropped oqs (and its liboqs C build), quinn, quinn-proto, webpki 0.22, base64, ring, hex and the audit-pin hack. webpki-roots 0.25 → 1.x; reqwest without openssl; `cargo update` (rustls 0.23.46). **Audit: 32 → 0.** Network test `#[ignore]`d |
| 78d3e66 | Single cited codepoint/OID registry; all fixes in §1.4; negotiated group taken from rustls instead of guessed; SAN via x509-parser |
| 0f96e7d | `tracing` instead of 119 print calls; stdout carries only results. `QUANTASEEK_DEBUG` and all `QUANTASEEK_*` env vars removed; clap derive; version from Cargo.toml |
| 5e95e63 | Score underflow, four `Box::leak` hostname leaks, RSA key size, saturating backoff |
| 8174a06 | clippy clean with `-D warnings` |
| 739def9 | GitHub Actions CI (fmt, clippy, test on Linux and macOS, MSRV 1.88, audit, deny), SHA-pinned; deny.toml |
| dac71c6 + README commit | Crate docs fixed; `--ports` removed (it could not work); README rewritten with verified limitations |

**Intentionally not done in Phase 1.** Each item below is a behaviour change,
not hygiene, and they are scheduled in M1:
- redirect certificate replacement
- the port bug
- profiles
- estimated metrics
- hostname heuristics

**Review note on the February WIP.** In `analyze_pqc_support` (library API, not
used by the CLI), `pqc_signature_observed` is set true in the branch whose
status says "Offered by client". That marks something as observed when it was
not. It is handled by the provenance model in M1.

**Bug in the archived `testnew.zsh`.** `jq -R 'fromjson? | …' -s` slurps the
whole file into one string, `fromjson?` fails silently on it, and that is why
`success-summary-*.json` was 0 bytes. The fix is to drop `-s` from the first jq
and pipe into `jq -s`. Not fixed, because the script is archived; M2 replaces it.

### 1.6 Milestone M1 changes (branch `m1-truthful-output`)

| Commit | Change |
|---|---|
| 8a77cee | Scan orchestration moved into `quanta_seek::scan`; injectable trust anchors; in-process rustls test servers (`tests/support`). **Pre-existing bug:** the client Finished was never flushed, so servers never completed the handshake the scanner called complete |
| 65a5e07 | `host:port`, `[v6]:port` and bare IPv6 targets; the handshake uses that port |
| f25a3a2 | `--sni` |
| 601a7b6 | Fake QUIC path, hostname heuristics, issuer-name "mock certificate" filters, `--tls12` and the CT stub removed. A handshake failure after TCP connect now sets `error` |
| 8cd3cf1 | Redirect following is opt-in (`--follow-redirects`) and reported in `http_redirect`; the target certificate is never replaced |
| 93b8a38 | Real profiles (`default`, `classical`, `hybrid`, `mlkem`, `all`). Outcomes classified by error type into `server_result` / `network` / `scanner`, with inferred interpretations. **Pre-existing bug:** read errors were flattened to strings, so timeouts were unclassifiable |
| 1ec1b1b | `ScanOptions::connect_to`; hostname-independence test |
| c76b46c | Output replaced by schema v0 (`schema/scan-result.v0.json`) with observed / derived / inferred / not-implemented provenance. Full chain, HelloRetryRequest, TLS 1.2 signature scheme and ServerHello evidence added. Scoring and every estimated field removed; JSON Lines output; default port 443 only |
| (this commit) | README and ROADMAP updated for M1 |

**Regressions found during M1.**
- *From Phase 1:* none confirmed in behaviour. The two pre-existing bugs above
  (unflushed Finished, flattened I/O errors) predate Phase 1, but Phase 1 did
  not catch them because it added no integration tests.
- *Introduced in M1 and fixed before commit:* the rewritten handshake loop used
  a 16 KiB read buffer, but rustls `read_tls` consumes at most 4096 bytes per
  call (`READ_SIZE` in the rustls deframer). Larger server flights were
  truncated and timed out. The live before/after run caught this on
  microsoft.com; it is now covered by `large_server_flight_is_read_completely`.

**Before and after, same five hosts [ran].** Baselines were recorded with the
Phase 1 binary before any M1 change.
- Before: 3 of 5 (google.com, microsoft.com and cloudflare.com) reported
  their redirect destination's `www.` certificate as the target's. Each output had 30 top-level fields, including a weighted score and
  estimated metrics.
- After: all 5 report the target's own chain (3–4 certificates), the
  negotiated group X25519MLKEM768 (`hybrid`, RFC 10024), the server signature
  scheme, and derived PQC values with their basis.
- `example.com:443`: `connection_failed` before, `completed` after.
- `-p standard google.com` → X25519MLKEM768 before; `-p classical google.com`
  → x25519 after.

### 1.7 Milestone M2 changes (branch `m2-testbed`)

| Commit | Change |
|---|---|
| b3a19e7 | Docker testbed (15 servers, OpenSSL 3.5.9 and Go 1.27, pinned by digest), `testbed/confirm.sh` ground truth, `tests/testbed.rs` (`--features testbed`), four ignored `m3_*` tests |
| 5181059 | **Scanner bug found by fuzzing:** `Target::parse("[]")` accepted an empty host. Bracketed and multi-colon hosts must now be IPv6 literals |
| aeca7ef | cargo-fuzz targets `server_hello`, `certificate_report`, `target_parse` |
| 408ef91 | Registry invariant tests (every entry cited and unique); IPv6 literal handshake test |
| 6bc459d | CI: offline tests, testbed job, nightly fuzz workflow. **Never run on GitHub** |
| (this commit) | README and ROADMAP for M2 |

The server table, ground-truth method and excluded fixtures are in
[testbed/README.md](testbed/README.md).

**One ground-truth correction during M2.** The first TLS 1.2 check used
s_client's default signature_algorithms order and expected
`ecdsa_secp256r1_sha256`, while QuantaSeek reported `ecdsa_secp384r1_sha384`.
Re-running s_client with rustls's offer order made OpenSSL report
`ecdsa_secp384r1_sha384` with digest SHA-384. The scanner was right, and the
check had not mirrored the scanner's offer. Rule for future fixtures: a
second-tool check must send the same offer as the scanner profile it is
compared with. The schema docs now note that in TLS 1.2 an ECDSA codepoint
does not bind the curve.

---

## 2. Standards landscape (as of 2026-11-13)

| Item | Status | Implication |
|---|---|---|
| FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA) | Final (Aug 2024) | Base algorithms |
| **RFC 10024**: ECDHE-MLKEM hybrids (X25519MLKEM768 4588, SecP256r1MLKEM768 4587, SecP384r1MLKEM1024 4589) | Published Aug 2026. IANA lists X25519MLKEM768 as Recommended=Y | The baseline "PQC-ready" check for TLS |
| draft-ietf-tls-mlkem (pure MLKEM512/768/1024 = 512–514) | Draft (-09+, IETF Last Call reported Jul 2026 [secondary]); IANA Recommended=N | Report it, but don't treat it as the expected configuration |
| draft-ietf-tls-mldsa (mldsa44/65/87 = 0x0904–0x0906) | IESG-approved Jul 2026 as Informational, RFC not yet published [secondary] | ML-DSA handshake signatures. rustls 0.23.46 can verify them |
| draft-ietf-tls-composite-mldsa | WG draft -00 (Oct 2026) [secondary] | Watch: TLS codepoints for composites not assigned yet |
| RFC 9881 (ML-DSA in X.509), RFC 9909 (SLH-DSA), RFC 9935 (ML-KEM), **RFC 10073** (Composite ML-DSA, Nov 2026) | Published | Certificate OIDs in `constants.rs` |
| X25519Kyber768Draft00 (25497), SecP256r1Kyber768Draft00 (25498) | Obsolete (IANA Recommended=D) | Finding: pre-standard Kyber still enabled |
| **NIST IR 8547** "Transition to Post-Quantum Cryptography Standards" | Final, 2026-10-27 [ran: CSRC page] | Quantum-vulnerable public-key algorithms deprecated after 2030 and disallowed after 2035; hybrids reportedly exempt from the 2035 disallowance [secondary]. **Exact tables to be read from the PDF before encoding** |
| CNSA 2.0 (NSA) | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512. Web browsers, servers and cloud services "support and prefer" by 2025, exclusive by 2033 [secondary] | A policy pack in which X25519MLKEM768 is *non-compliant* (it needs ML-KEM-1024) |
| BSI TR-02102-1 (2026-01) | Recommends hybrid key establishment; dates for ending classical-only use (end of 2030/2031) [secondary] | Policy pack. Verify against the TR text |
| ANSSI | Recommends hybridation [secondary]; no primary 2026 document found | Policy pack. Primary source still needed |
| US EO 14412 / OMB M-26-15 | 2030-12-31 PQ key establishment, 2031-12-31 signatures for federal HVA systems [secondary] | Possible US federal pack |

**rustls 0.23.46 capability [read from the crate source].**
- Key exchange: X25519MLKEM768, SECP256R1MLKEM768, MLKEM768, MLKEM1024.
- Not supported: SecP384r1MLKEM1024, MLKEM512, the SM2/X448 hybrids.
- Signatures: verifies ML-DSA-44/65/87.
- Default ClientHello: only X25519MLKEM768, x25519, secp256r1, secp384r1.

Any detection limited to rustls therefore has structural false negatives, and
that is why M3 exists.

**Rule:** a policy rule that cites a [secondary] fact above must not ship until
the primary text has been read and quoted in the rule's metadata.

---

## 3. Competitive landscape

None of the products below was evaluated hands-on. The statements come from
public docs and one preprint, and should be validated before they are used in
marketing.

| Tool | PQC capability (public info) | Gap QuantaSeek can fill |
|---|---|---|
| testssl.sh | Mar 2026 commit added decryption of PQ-KEX handshakes and parsing of ML-KEM key shares, when the local OpenSSL supports them [secondary]. A 2026 preprint (arXiv 2609.07849) reports its grade does not reflect PQC | Depends on the local OpenSSL build; bash; no policy mapping; no CBOM |
| sslyze | Per the same preprint, bundled crypto predates ML-KEM, so 0 mentions against an X25519MLKEM768 server [secondary] | — |
| Qualys SSL Labs | Key exchange reported in classical-equivalent bits; not expressible for PQ groups [secondary] | Hosted only; public hosts only |
| Anvil Secure **pqcscan** | Rust, BSD-2-Clause, TLS and SSH, JSON results plus HTML/CSV/XML report [ran: README] | **The closest open-source competitor.** Compete on evidence quality, policy packs, CBOM/SARIF and a deterministic test corpus |
| OpenShift tls-scanner | `-pqc-check` built on testssl.sh [secondary] | Pass/fail only |
| DigiCert PQC checker | Web check for hybrid groups [secondary] | Single host, web-only |
| Commercial inventory/CBOM: IBM Quantum Safe, SandboxAQ AQtive Guard, Keyfactor, CyberArk (Venafi), QuSecure, Encryption Consulting, CryptoNext | Broad discovery (network, host, code), CBOM; enterprise pricing [secondary] | Heavy, opaque and expensive. They need a trustworthy network-TLS sensor, which is a possible partner and OEM channel rather than only a competitor |

**Where QuantaSeek can be distinctly better:**
1. **Evidence-grade results.** Every finding carries the exact ClientHello sent,
   the ServerHello and alerts received, a timestamp and a tool version. Anyone
   can re-run it and get the same verdict, and none of the competitors above
   advertises this.
2. **Complete PQC enumeration that does not depend on a TLS library.** A custom
   prober tests every registered PQC group (including those rustls and OpenSSL
   can't negotiate), server preference, HRR, downgrade and large-ClientHello
   tolerance.
3. **Observed / inferred / not-observable provenance on every field.** This is
   the trust feature auditors need, and it is a project rule.
4. **Policy packs with citations and dates** (CNSA 2.0, NIST IR 8547, BSI,
   ANSSI). Each finding states which clause it violates.
5. **Native CycloneDX CBOM plus SARIF output** from a single static binary that
   fits in CI.
6. **A public, reproducible test corpus** (containerised servers with known
   configurations) that doubles as a benchmark other tools can be measured
   against.

---

## 4. Target product and buyer

**Product.** A PQC-readiness scanner and inventory for network endpoints (TLS
first, then SSH and STARTTLS). Its output is evidence-backed findings mapped to
named policies, plus a CBOM.

**Buyers and users.**
- **Primary buyer: security, crypto-governance and PKI teams** in regulated
  sectors (finance, government suppliers, telco, healthcare) who must produce a
  cryptographic inventory and migration plan. Drivers: NIST IR 8547, OMB
  M-26-15, CNSA 2.0 for National Security System (NSS) suppliers, BSI/ANSSI in
  the EU, DORA ICT-risk reporting.
- **Influencer and gatekeeper: auditors and assessors.** They need reproducible
  evidence and policy citations.
- **Secondary: DevSecOps and platform teams**, who want a CI gate ("this service
  must negotiate a PQC hybrid") and drift alerts.
- **Channel: consultancies** running PQC assessments, and CBOM/inventory
  vendors needing a network sensor (OEM).

**Not the target:** a general TLS hygiene grader. testssl.sh and SSL Labs own
that, and QuantaSeek should cover classical checks only as needed for PQC
findings.

---

## 5. Technical roadmap

### Proposed order, and why it differs from the brief

The brief proposed: detection engine → findings → scale → tests → protocols →
commercial. The audit suggests two changes:

1. **Add M1 "Truthful output" first.** The current output still contains
   fabricated metrics, a replaced certificate and a broken port path. Building a
   prober on top would carry these into a new engine. M1 is small and removes
   every known false statement.
2. **Move the test infrastructure (M2) before the prober (M3).** A hand-built
   ClientHello prober can only be trusted once it has been verified against
   servers with known configurations. Without the testbed, M3's acceptance
   criteria cannot be checked.

Sequence: **M1 Truthful output → M2 Testbed → M3 Detection engine → M4 Findings
and policy → M5 Scale and integration → M6 Protocol breadth → M7 Commercial
layer.** M5's packaging items (Docker, signed releases) can start in parallel
with M4.

Every milestone keeps the provenance rule: each reported value is `observed`,
`inferred` (with the inference basis), `not_observable`, or `not_implemented`.

### M1: Truthful output — done 2026-11-13 (branch `m1-truthful-output`)

Delivered as scoped above (§1.6): ports and IPv6, SNI override, opt-in
redirects with a separate field, real profiles, estimated fields and scoring
removed, hostname heuristics and the fake QUIC path removed, provenance on
every derived or inferred value, schema v0 published and validated, JSON
Lines output. The old `pqc_signature_observed` "offered" bug is gone with the
code that contained it; `pqc.handshake_signature` replaces it.

Acceptance results [ran, 2026-11-13]. Checks 1 and 2 referred to v-pre-0 field
names that schema v0 renamed. The original form fails for that reason only;
the v0 form is now the criterion.

| # | Check | Result |
|---|---|---|
| 1 | `quantaseek -q example.com:443 \| jq -e '.outcome.status == "completed" and .target.port == 443'` | pass (original `.handshake_complete` form: field no longer exists) |
| 2 | `quantaseek -q google.com \| jq -e '.certificate_chain[0].san_dns \| index("google.com") != null'` | pass (original `.certificate.san` form: field no longer exists) |
| 3 | `cargo test --test profiles classical_profile_offers_no_pq_group` (local rustls server offering X25519MLKEM768 + x25519; the M2 testbed does not exist yet) | pass |
| 4 | `git grep -nE 'time_penalty_ms: Some\(200\)\|Some\(150\) // Typical\|Some\(25\.0\)' src` | no matches |
| 5 | `cargo test --test schema` (committed schema == generated; four outputs validated with `jsonschema`; golden files) | pass |
| 6 | `git grep -n 'contains("demo")\|oqstest.net\|duckdns' src` | no matches |

Left for later milestones, because they need the prober or the testbed:
- **Chain reporting on validation failure.** A chain that fails webpki
  validation (expired, wrong name, SLH-DSA / composite / Ed448 signatures that
  webpki 0.103 cannot verify) is reported only as `certificate_rejected`. The
  verifier sees the certificates before rejecting them, so they could be
  reported with `validated: false`. → **M3**, together with independent chain
  analysis.
- **Confirming *why* a restrictive profile was rejected** (no shared group vs.
  other negotiation failure). The cause is reported as `inferred`, and only
  per-group probing can confirm it. → **M3**.
- **Groups rustls cannot offer** (SecP384r1MLKEM1024, MLKEM512, SM2/X448
  hybrids). → **M3** prober.
- **Fixtures with ML-DSA, SLH-DSA, composite and HashML-DSA certificates**,
  needed to test `family` classification end to end (rcgen cannot issue them
  in the configuration used). → **M2**.
- **IPv6 connection test.** Parsing is tested; a `[::1]` handshake test is not
  written yet. → **M2**.
- **Exit codes for CI gating.** The exit code is still 0 whenever output was
  produced. → **M4** (finding thresholds).

### M2: Deterministic testbed — done 2026-11-13 (branch `m2-testbed`)

Delivered (§1.7):
- `testbed/compose.yml` with 15 servers on 127.0.0.1:443xx. Each server's
  ground truth comes from its configuration and was confirmed with
  `openssl s_client` from the same image (`testbed/confirm.sh`, 49 checks).
- `tests/testbed.rs` asserts the confirmed group, certificate algorithms,
  chain SHA-256 and provenance for every server.
- Four ignored `m3_*` tests that fail today.
- Three fuzz targets on the parsers that exist after M1, which replaced the
  pre-M1 list.
- Registry invariant tests.

Changes from the plan:
- Golden files are the hand-rolled normaliser added in M1
  (`tests/schema.rs`), not `insta`. A new dependency was not needed.
- The fuzz targets differ from the pre-M1 list: M1 deleted the old
  ServerHello and extension parsers.
- Not built (reasons in testbed/README.md):
  - X25519Kyber768Draft00 and RFC 10073 composite chains: no maintained
    implementation.
  - HashML-DSA leaf: OpenSSL 3.5.9 cannot produce one.
  - Large-ClientHello middlebox: needs a purpose-built proxy, moved to M3.
  - rustls `tlsserver-mio`: duplicates `tests/support`.

Acceptance [ran on macOS arm64, Docker 28.0.4, unless noted]:

| # | Check | Result |
|---|---|---|
| 1 | `docker compose -f testbed/compose.yml up -d --build --wait && cargo test --features testbed` | **Passed**, run by the project owner on 2026-11-13 after the Docker restart (testbed: 13 passed, 4 ignored). Not run on Linux CI |
| 2 | each testbed server has a test asserting the exact group, certificate algorithm and provenance | 15 servers, all covered by `tests/testbed.rs` |
| 3 | `cargo +nightly fuzz run server_hello -- -max_total_time=300` | 10.0M executions in 301 s, no crash; certificate_report 6.5M; target_parse 13.2M after the fix |
| 4 | `cargo test` without the feature uses no network | **Passed**, run by the project owner on 2026-11-13 in a `--network none` Linux container. The GitHub `unshare` job has not run |

### M3: Detection engine (about 4–6 weeks)

**Definition of done includes**
`cargo test --features testbed --test testbed -- --ignored` passing against
the M2 testbed. These four tests fail today:
- `m3_secp384r1mlkem1024_server_group_is_reported`
- `m3_mlkem512_server_group_is_reported`
- `m3_slhdsa_signed_chain_is_reported`: report a chain webpki cannot verify
- `m3_invalid_certificates_are_reported`: report expired, mismatched and
  self-signed chains as not validated

M3 also adds the large-ClientHello middlebox proxy to the testbed, with
ground truth established by construction.

Scope:
- **Custom ClientHello prober** (no TLS library), sending one probe per
  question:
  - **Group enumeration.** Offer exactly one group, with a key share, against
    every PQC and classical group in the registry. Classify each as accepted,
    HRR to another group, or alert/close, and record the alert code.
  - **Server preference.** Offer pairs in both orders.
  - **HRR behaviour.** Offer the group in `supported_groups` without a key share.
  - **Downgrade.** Offer PQC plus classical with only a classical key share.
    Does the server HRR to PQC (good) or accept classical (finding)?
  - **Large ClientHello tolerance.** Probe with a 1.2 KB ML-KEM share and with
    split-record and split-segment variants, to detect middlebox and server
    breakage.
- **Full-handshake validation** stays on rustls: chain validation, ML-DSA
  CertificateVerify capture, full chain extraction (all certificates, not just
  the leaf).
- **Certificate analysis across the chain:** ML-DSA, SLH-DSA, composite and
  HashML-DSA keys and signatures at each position.
- **Direct QUIC Initial.** Hand-built Initial packet with the same ClientHello
  matrix and Initial-key decryption of the server Initial and Handshake. This is
  the only way to observe QUIC PQC without a QUIC stack.
- **Rate limiting inside the prober.** Probes per host per second, with
  jittered spacing. Abort on repeated resets.

Acceptance:
- `quantaseek probe localhost:<openssl-p384mlkem1024-only> -q | jq -e '.groups.accepted == ["SecP384r1MLKEM1024"]'`
- against the HRR-forcing server: `.groups.hrr | length > 0`
- against the "accepts classical when PQC is offered" server, the result contains finding `QS-KEX-002`
- composite-chain server: `.certificates[1].signature_algorithm == "id-MLDSA65-ECDSA-P384-SHA512"` with `provenance == "observed"`
- QUIC testbed server (quic-go or ngtcp2): QUIC group reported with `transport == "quic"`, no TCP connection made (verified by test harness)
- total probes per target ≤ documented budget (e.g. ≤ 40) and default spacing ≥ 100 ms, asserted by the harness

### M4: Findings model and policy packs (about 3–4 weeks)

Scope:
- **The `Finding` type.** Fields:
  - `id` (stable, e.g. `QS-KEX-001`)
  - `title`, `severity` (info/low/medium/high/critical)
  - `evidence[]` (references to the probe transcripts)
  - `provenance`, `remediation`
  - `references[]` (RFC or policy clause with quote)
  - `introduced_in` (version)
- **A rule catalogue in data** (`rules/*.toml`). Every rule has fixtures from
  the M2 testbed. Examples:
  - no PQC key exchange
  - only pre-standard Kyber accepted
  - PQC offered but classical accepted without HRR (downgrade-able)
  - rejects large ClientHello
  - HashML-DSA certificate (RFC 9881 §8.3)
  - ML-KEM-768 under a CNSA 2.0 policy (needs 1024)
  - RSA/ECDSA-only chain (NIST IR 8547 deprecation date)
  - certificate expired or invalid
- **Policy packs** (`policies/{nist-ir-8547,cnsa-2.0,bsi-tr-02102-1,anssi}.toml`).
  Each maps rule IDs to severity and deadlines, with citations to the primary
  text.
- **Score derived from findings only**, by documented aggregation, and
  replaceable. The current weighted score is deleted.
- `--policy <pack>` CLI. Exit codes for CI gating: 0 = pass, 1 = findings at or
  above a threshold, 2 = scan error.

Acceptance:
- `cargo test rules::` runs every rule against its positive and negative testbed fixture
- `quantaseek --policy cnsa-2.0 localhost:<x25519mlkem768> ; test $? -eq 1` and the JSON includes `QS-KEX-010` with a CNSA citation
- `scripts/check-rule-metadata` fails if any rule or policy entry lacks a primary-source reference
- removing all findings yields score 100 and adding one critical caps it as documented (property test)

### M5: Scale and integration (about 4–6 weeks; packaging can overlap M4)

Scope:
- **Targets.** Target files, CIDR expansion with an explicit `--allow-cidr` and
  a hard cap, and DNS name lists.
- **Concurrency.** Bounded concurrency (global and per-host), global and
  per-host rate limits, exponential backoff.
- **Resumable scans.** A SQLite state file with `--resume`.
- **Config file.** `quantaseek.toml`, with CLI flags overriding it.
  Environment variables only for secrets, never for behaviour.
- **Outputs.**
  - JSON Lines plus a versioned JSON Schema (`schema/v1`)
  - **SARIF 2.1.0**
  - **CycloneDX 1.6+ CBOM**: cryptographic assets per endpoint, with protocol,
    algorithm and certificate components
  - a self-contained HTML report
  - CSV
- **Distribution.** A distroless Docker image (multi-arch) and a GitHub Action
  (`uses: …/quantaseek-action@v1` with SARIF upload).
- **Releases.** cargo-dist; cosign keyless signatures, SLSA build provenance and
  a CycloneDX SBOM of the tool itself.

Acceptance:
- `quantaseek scan --targets testbed/targets.txt --concurrency 16 --rate 50/s` scans all testbed hosts; a test asserts the maximum observed concurrency never exceeds the limit
- kill mid-scan, re-run with `--resume`: no target is scanned twice (asserted by testbed connection logs)
- `quantaseek … --format sarif | sarif-fmt` validates; `--format cbom` validates with `cyclonedx validate --input-version v1_6`
- `cosign verify-blob --certificate-identity-regexp … quantaseek-x86_64-unknown-linux-gnu.tar.gz` succeeds on a release artifact
- Golden-file tests for every output format

### M6: Protocol breadth (sequenced by demand)

1. **SSH key exchange.** Advertised and negotiated KEX via KEXINIT, plus host key
   algorithms. Drivers: `mlkem768x25519-sha256` (believed to be OpenSSH's
   default since 10.0; verify) and `sntrup761x25519-sha512`. The demand signal
   is strong: pqcscan already covers SSH, and so do inventories.
2. **STARTTLS.** SMTP (25/587), IMAP, POP3, LDAP, PostgreSQL, MySQL. These reuse
   the M3 prober after the plaintext upgrade.
3. **Others on demand.** RDP, XMPP, MQTT/TLS, DTLS, Kerberos/PKINIT.

Acceptance: testbed containers (OpenSSH 10.x, Postfix with OpenSSL 3.5, …) with
fixture tests, mirroring M2 and M3.

### M7: Commercial layer

See §7. Technically:
- a service (API plus scheduler)
- per-tenant scan history and **drift detection** (group, certificate or policy
  status changed since last scan)
- alerting (Slack, email, webhook)
- an evidence archive with signed reports
- SSO/RBAC and audit logs
- a REST API with an OpenAPI spec

Acceptance is defined once the licensing decision (D1) is made.

---

## 6. Production readiness

**Testing**
- Unit tests for parsers and tables.
- Testbed integration (M2) and golden files.
- Fuzzing.
- Property tests for scoring and aggregation.
- Coverage tracked with `cargo llvm-cov` (installed locally); target ≥ 80% on
  parsers, rules and output.
- A no-network guarantee for default `cargo test`.

**CI** (added in Phase 1)
- fmt, clippy `-D warnings`, test (Linux, macOS), MSRV 1.88, `cargo audit
  --deny warnings`, `cargo deny`.
- Add later: Windows (once the aws-lc-sys build is verified), nightly fuzz,
  testbed job, `cargo semver-checks` on the library once the API is declared
  stable, and Renovate or Dependabot for actions and crates.

**Releases**
- SemVer.
- A CHANGELOG (Keep a Changelog).
- A versioned output schema, with breaking schema changes only on minor bumps
  before 1.0 and on major bumps after.
- Signed artifacts, SBOM and provenance (M5).
- A release checklist that includes re-checking `constants.rs` against IANA.

**Supply chain**
- Pinned action SHAs (done), `--locked` builds (done), and a deny.toml licence
  allow-list (done).
- Add later: `cargo vet` or `cargo crev` imports, a minimal dependency policy
  (one TLS stack; reqwest is only needed for redirect following, which M1 may
  remove), reproducible-build check, and OpenSSF Scorecard.
- Note: aws-lc-rs brings a C/assembly build. If FIPS-validated crypto is ever
  required, the aws-lc-rs `fips` feature is the path.

**Documentation**
- README, kept true. Keep the "Limitations" section and update it with every
  milestone.
- Output schema reference.
- A rule catalogue page per finding ID.
- Policy pack pages with citations.
- `SECURITY.md` (vulnerability disclosure), `CONTRIBUTING.md` (DCO or CLA per
  D3), architecture notes.

**Legal and ethical scanning policy**
- Default to a conservative probe budget and rate.
- Identify the scanner. Use a configurable HTTP User-Agent and document the
  probe patterns, so operators can recognise them.
- Require explicit flags for CIDR and large target lists. Print an
  authorisation reminder for non-RFC1918 ranges at scale.
- Support an exclusion list (`--exclude-file`), and a project-hosted opt-out
  process if a hosted service ever scans third parties.
- No exploitation, no fuzzing of live targets, no credential handling.
- Results are sensitive. No telemetry by default; documented local storage;
  encryption at rest in the service.
- Get legal review of terms for the hosted service (US CFAA, UK Computer
  Misuse Act, EU NIS2/DORA contexts) before any third-party scanning offer.

---

## 7. Commercial viability

These are options. The decisions belong to the owner.

### 7.1 Licensing models

| Option | Pros | Cons |
|---|---|---|
| **Apache-2.0** (or MIT/Apache dual) for all code | Maximum adoption; auditors and enterprises can inspect and vendor it; patent grant (Apache); matches the Rust ecosystem | Anyone, including CBOM vendors, can embed or resell it; monetisation must come from service, support and data |
| MPL-2.0 | File-level copyleft keeps improvements to the scanner open; still enterprise-friendly | Less familiar; weak protection against SaaS reuse |
| AGPL-3.0 core plus commercial licence (dual) | Deters closed SaaS clones; dual-licensing revenue | Many enterprises ban AGPL internally, which conflicts with the "auditors trust it" goal; requires a CLA |
| Source-available (BSL 1.1 / FSL) converting to Apache after N years | Protects against competitors in the early years | Not OSI open source; reduces community trust and contributions; some buyers object |
| Fully proprietary | Simplest to monetise | Loses the transparency that is the product's core trust argument; competes head-on with funded vendors |

### 7.2 Open-core boundary (if open core)

**Open:**
- the scanner CLI and library
- prober, rules engine and all finding rules
- JSON, SARIF, CBOM and HTML outputs
- the testbed
- at least one policy pack (NIST IR 8547)

Detection accuracy must never be paywalled. A paid tier that "finds more" would
undermine trust in the free one.

**Commercial:**
- the hosted or self-hosted service: scheduling, history, drift, dashboards,
  multi-tenant, SSO/RBAC, audit log, API
- **maintained policy packs with an SLA** (CNSA 2.0, BSI, ANSSI, sector packs),
  updated within N days of a standards change
- signed, auditor-ready evidence reports
- support and indemnity
- OEM licences for inventory vendors

### 7.3 Packaging

1. Free CLI, GitHub Action and Docker image.
2. **Pro**: self-hosted server, single team, maintained packs, report templates.
3. **Enterprise**: SSO, RBAC, multi-tenant, on-prem/air-gapped support, SLA.
4. **OEM/API** licence for CBOM platforms.
5. **Assessment service**: a fixed-fee PQC readiness assessment using the tool.
   This brings early revenue and discovery.

### 7.4 Pricing hypotheses (unvalidated)

These need around 10–15 discovery interviews before any price is published.
- Pro: about $3k–$10k per year, up to about 1,000 endpoints.
- Enterprise: about $25k–$100k+ per year, banded by endpoint count and
  deployment model.
- OEM: a revenue share or a per-sensor fee.
- Assessment: about $10k–$40k per engagement.

The anchor to test: commercial inventory suites are typically sold as large
enterprise deals [secondary], which leaves room below them for a focused,
transparent tool.

### 7.5 Go-to-market

1. **Credibility first.**
   - Publish the testbed and a methodology paper.
   - Publish a comparison of tools against the testbed, factual and reproducible.
   - Report scan data only in aggregate. Name a specific site only when it
     agrees, or when the site itself publishes the configuration.
2. **Developer adoption.** GitHub Action and CI gate ("fail if no PQC hybrid").
   Write-ups timed to standards milestones: RFC 10024, ML-DSA RFC publication,
   NIST IR 8547.
3. **Channel.** PQC consultancies and auditors (give them evidence-report
   features), and OEM talks with CBOM vendors who lack an accurate network
   sensor.
4. **Compliance hooks.** Policy packs named after the documents buyers are
   measured against.

### 7.6 Recommendation

**Apache-2.0 open core with DCO contributions.** All detection, rules, outputs
and the NIST pack are open. The service, maintained policy packs with SLA,
signed evidence reports, enterprise features and OEM licences are commercial.

The reasoning: the product's core claim is "you can trust and reproduce this".
A permissive, inspectable scanner is the strongest form of that claim, and it
is what auditors and regulated enterprises can adopt without legal friction.
Revenue comes from the parts that cost ongoing work (policy maintenance,
service operation, evidence workflows), not from hiding detection. If a SaaS
clone emerges as a real threat, keep the service code proprietary (already the
plan) rather than relicensing the scanner.

---

## 8. Decisions needed from the owner

1. **D1 License** for the scanner (§7.1). The recommendation is Apache-2.0. The
   README currently states that no license has been granted.
2. **D2 Commercial model.** Open core vs. fully open plus services vs.
   proprietary. This decides what lives in this repository.
3. **D3 Contributions.** DCO (recommended with Apache-2.0) or CLA (needed for
   dual licensing).
4. **D4 Default branch.** *Decided:* `main`. Still open: whether the remote
   default `master` and the `dev` branch should be retired.
5. **D5 Output compatibility.** *Decided:* breaking is acceptable; published as
   schema v0 with a `schema_version` field.
6. **D6 HTTP redirect following.** *Decided:* off by default, opt-in with
   `--follow-redirects`, reported in a separate field.
7. **D7 Profiles.** *Decided:* real profiles limited to groups rustls
   implements. Done in M1.
   - *M3 probing (decided 2026-11-13):* per-group probing is opt-in
     (`--probe`), with a capped probe budget and at least 100 ms between
     probes by default. The default scan stays one handshake.
8. **D8 Policy-pack priority.** Which jurisdictions first? Suggested: NIST IR
   8547 (open) and CNSA 2.0, then BSI and ANSSI.
9. **D9 Live-scan policy for research and marketing.** *Interim for M3:*
   local testbed only, no public hosts. Which public hosts may be
   scanned, at what rate, and whether results are ever published.
10. **D10 Platform support.** Is Windows a release target? It affects CI and
    the aws-lc-sys toolchain.
11. **D11 Archive.** `.archive/` holds the February scan outputs, the
    `test_debug` binary, the zsh scripts and FEATURES_AND_LIMITATIONS.md. It is
    git-ignored. Delete it, or move it out of the repository?

---

## 9. Appendix

### 9.1 Verification log (Phase 0, Phase 1, M1 and M2)

- **Builds and tools.**
  - Builds: `cargo build`, `cargo test`, `cargo clippy --all-targets`,
    `cargo fmt --check`, `cargo audit`, `cargo deny check`, before and after.
  - MSRV: `cargo +1.88.0 check --all-targets --locked`.
- **Live scans** (one handshake sequence each, a few seconds apart):
  - google.com, cloudflare.com, example.com, pq.cloudflareresearch.com,
    microsoft.com
  - `-p classic google.com`
  - `example.com:443`
  - `-v google.com` (redirect trace)
- **rustls capabilities:** read from
  `~/.cargo/registry/src/*/rustls-0.23.46/src/crypto/aws_lc_rs/{mod.rs,pq/mod.rs}`.
- **Unused dependencies:** confirmed by removing them and building.

- **M1 live scans** (2026-11-13): the same five hosts before (Phase 1 binary)
  and after; `example.com:443`; `-p standard`/`-p classical google.com`;
  `--follow-redirects google.com`; `-p mlkem example.com` (→
  `handshake_rejected`, alert `HandshakeFailure`); `-p classical
  pq.cloudflareresearch.com` (→ x25519). Each was one handshake sequence,
  a few seconds apart. microsoft.com was scanned three extra times while
  diagnosing the read-buffer regression.
- **M1 source reads:** rustls 0.23.46 `ALL_KX_GROUPS` and `READ_SIZE`;
  rustls-webpki 0.103.17 supported signature algorithms.

- **M2** (no public-host scans):
  - Read from the pinned OpenSSL 3.5.9 build:
    `openssl list -tls-groups -tls1_3`, `-tls-signature-algorithms`,
    `-signature-algorithms` and `-kem-algorithms`.
  - Go 1.27.4 `crypto/tls` docs (CurvePreferences, CurveIDs).
  - oqs-provider ALGORITHMS.md (no Kyber groups; composites under
    1.3.9999.7).
  - `testbed/confirm.sh`: 49 checks.
  - `tests/testbed.rs`: 13 tests and 4 ignored.
  - Fuzzing: 3 × 300 s.
  - Attempted: default tests in a `--network none` Linux container. Aborted
    by a Docker daemon crash, so no result.

### 9.2 Primary sources consulted (2026-11-13)

- IANA TLS Supported Groups and SignatureScheme registries:
  <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>
- IANA TLS ExtensionType Values:
  <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
- NIST CSOR algorithm registrations:
  <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
- RFC 10024, RFC 9881, RFC 9909, RFC 9935, RFC 10073 (full texts from rfc-editor.org)
- NIST IR 8547 final landing page: <https://csrc.nist.gov/pubs/ir/8547/final>
- draft-ietf-lamps-pq-composite-sigs datatracker page (now RFC 10073)
- pqcscan README: <https://github.com/anvilsecure/pqcscan>

### 9.3 Secondary sources (to be replaced by primary ones before use in rules)

- postquantum.com: draft-ietf-tls-mlkem Last Call; NIST IR 8547 final summary;
  BSI TR-02102 coverage; CNSA 2.0 FAQ coverage.
- IETF announce: draft-ietf-tls-mldsa-05 approval.
- Cloud Security Alliance research note on NIST IR 8547 / OMB M-26-15.
- Phoronix: rustls 0.23.44 and 0.23.46 release coverage.
- arXiv 2609.07849 (PQC delivery across scanners).
- Vendor pages and comparisons: QCecuring, Encryption Consulting.

### 9.4 Facts not re-verified this session

These are from prior knowledge and must be checked before they are relied on:
- the default PQC behaviour of OpenSSH 10.x, OpenSSL 3.5, Go 1.24 and Chrome
- CycloneDX 1.6 CBOM field names
