# Contributing to QuantaSeek

## Licence and sign-off

QuantaSeek is licensed under the [Apache License, Version 2.0](LICENSE). By
contributing, you agree that your contribution is licensed under the same
terms (Apache-2.0 §5).

Every commit must carry a Developer Certificate of Origin sign-off. The DCO
(version 1.1, <https://developercertificate.org/>) is a statement that you
wrote the change, or otherwise have the right to submit it under the
project's licence. Add the sign-off with `git commit -s`, which appends:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and an email address you can be reached at. Commits
without a sign-off cannot be merged. There is no contributor licence
agreement.

## Before you open a pull request

Run what CI runs:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
```

If you changed detection, probing or findings, also run the Docker testbed
(see [testbed/README.md](testbed/README.md)):

```bash
docker compose -f testbed/compose.yml up -d --build --wait
sh testbed/confirm.sh
cargo test --features testbed --test testbed --locked
docker compose -f testbed/compose.yml down
```

If you changed the JSON report, regenerate the schema and the golden files,
and commit them in the same pull request:

```bash
cargo run --quiet -- --print-schema > schema/scan-result.v0.json
UPDATE_GOLDEN=1 cargo test --test schema
```

## Rules for changes

- **Mark provenance.** Every reported value is `observed`, `derived` or
  `inferred`. Anything not seen on the wire must not be reported as
  `observed`.
- **Don't patch around limitations.** If a capability does not work, report
  it as unsupported or not evaluated and document it in the README. Never
  report a guess as a result.
- **Ground truth before assertions.** A test's expected value must come from
  an independent source: the testbed's `openssl s_client` checks, an RFC, or
  the server's configuration. It must not come from QuantaSeek's own output.
- **Keep default tests offline.** Tests that need the public internet must be
  `#[ignore]`d. CI runs the default suite with no network.
- **Cite rules.** A new finding rule needs metadata in `rules/rules.toml`,
  with a verbatim quote from its primary source.
- **Keep scanning gentle.** Live tests may only touch the small set of public
  test endpoints already used, with one handshake sequence each.

## Reporting security issues

Do not open a public issue for a vulnerability; see [SECURITY.md](SECURITY.md).
