#!/bin/sh
# Independent ground truth for the testbed: OpenSSL s_client from the same
# image, run inside each container against its own server. QuantaSeek is not
# involved. Every expectation in tests/testbed.rs must agree with a line here.
#
#   docker compose -f testbed/compose.yml up -d --build --wait
#   sh testbed/confirm.sh
set -u
cd "$(dirname "$0")"
fail=0

# check <service> "<s_client args>" <grep -E pattern>...
check() {
  svc=$1 args=$2; shift 2
  out=$(docker compose exec -T "$svc" sh -c \
    "openssl s_client -connect 127.0.0.1:4443 -servername localhost -CAfile /out/ca.pem $args </dev/null 2>&1")
  for pattern in "$@"; do
    if printf '%s\n' "$out" | grep -Eq -- "$pattern"; then
      echo "PASS $svc [$args] ~ /$pattern/"
    else
      echo "FAIL $svc [$args] ~ /$pattern/"; fail=1
    fi
  done
}

ok='Verify return code: 0 \(ok\)'
rejected='alert handshake failure|alert number 40'

# Key exchange: the configured group is negotiated; a classical-only offer is refused.
check x25519mlkem768       "-groups X25519MLKEM768"     "Negotiated TLS1.3 group: X25519MLKEM768" "$ok"
check x25519mlkem768       "-groups x25519"             "$rejected"
check secp256r1mlkem768    "-groups SecP256r1MLKEM768"  "Negotiated TLS1.3 group: SecP256r1MLKEM768" "$ok"
check secp256r1mlkem768    "-groups X25519MLKEM768:x25519" "$rejected"
check secp384r1mlkem1024   "-groups SecP384r1MLKEM1024" "Negotiated TLS1.3 group: SecP384r1MLKEM1024" "$ok"
check secp384r1mlkem1024   "-groups X25519MLKEM768:SecP256r1MLKEM768:MLKEM768:MLKEM1024:x25519:secp256r1:secp384r1" "$rejected"
check mlkem1024            "-groups MLKEM1024"          "Negotiated TLS1.3 group: MLKEM1024" "$ok"
check mlkem1024            "-groups MLKEM768:x25519"    "$rejected"
check mlkem512             "-groups MLKEM512"           "Negotiated TLS1.3 group: MLKEM512" "$ok"
check mlkem512             "-groups X25519MLKEM768:SecP256r1MLKEM768:MLKEM768:MLKEM1024:x25519:secp256r1:secp384r1" "$rejected"
# OpenSSL prints "Peer Temp Key" (not "Negotiated ... group") for classical groups.
check classical            "-groups x25519"             "Peer Temp Key: X25519" "Protocol: TLSv1.3" "$ok"
check classical            "-groups MLKEM1024:MLKEM768" "$rejected"
check classical            "-groups X25519MLKEM768:SecP256r1MLKEM768" "$rejected"
# HelloRetryRequest: first key share x25519, server wants secp384r1 -> two ServerHellos.
check hrr-secp384r1        "-groups x25519:secp384r1 -msg" "Peer Temp Key: ECDH, secp384r1"
hrr=$(docker compose exec -T hrr-secp384r1 sh -c \
  "openssl s_client -connect 127.0.0.1:4443 -CAfile /out/ca.pem -groups x25519:secp384r1 -msg </dev/null 2>&1" \
  | grep -c '<<< TLS 1.3, Handshake .*ServerHello')
[ "$hrr" -eq 2 ] && echo "PASS hrr-secp384r1 two ServerHello messages (HRR)" \
  || { echo "FAIL hrr-secp384r1 ServerHello count $hrr"; fail=1; }
# Offers mirroring QuantaSeek's profiles (same groups, same first key share).
check classical            "-groups X25519MLKEM768:x25519:secp256r1:secp384r1" "Peer Temp Key: X25519" "$ok"
check secp256r1mlkem768    "-groups X25519MLKEM768:SecP256r1MLKEM768 -msg" "Negotiated TLS1.3 group: SecP256r1MLKEM768"
n=$(docker compose exec -T secp256r1mlkem768 sh -c \
  "openssl s_client -connect 127.0.0.1:4443 -CAfile /out/ca.pem -groups X25519MLKEM768:SecP256r1MLKEM768 -msg </dev/null 2>&1" \
  | grep -c '<<< TLS 1.3, Handshake .*ServerHello')
[ "$n" -eq 2 ] && echo "PASS secp256r1mlkem768 HRR when first share is X25519MLKEM768" \
  || { echo "FAIL secp256r1mlkem768 ServerHello count $n"; fail=1; }
check hrr-secp384r1        "-groups X25519MLKEM768:x25519:secp256r1:secp384r1" "Peer Temp Key: ECDH, secp384r1"
check tls12-classical      "-tls1_2"                    "Protocol: TLSv1.2" "Peer Temp Key: X25519" "Peer signature type: ecdsa_secp256r1_sha256" "$ok"
# TLS 1.2: the server picks the hash from the client's signature_algorithms
# order. rustls lists ECDSA+SHA-384 first, so with rustls's order the P-256
# key signs with SHA-384 (codepoint ecdsa_secp384r1_sha384; in TLS 1.2 the
# codepoint does not bind the curve).
check tls12-classical      "-tls1_2 -sigalgs ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256:ed25519:rsa_pss_rsae_sha512" "Peer signature type: ecdsa_secp384r1_sha384" "Peer signing digest: SHA384"
check tls12-classical      "-tls1_3"                    "alert protocol version|alert number 70|no protocols available"

# Certificates.
check cert-mldsa65               "" "Peer signature type: mldsa65" "s:CN=QuantaSeek testbed leaf \(mldsa65\)" "i:CN=QuantaSeek testbed root \(mldsa65\)" "$ok"
check cert-mldsa65-intermediate  "" "Peer signature type: ecdsa_secp256r1_sha256" "1 s:CN=QuantaSeek testbed inter \(mldsa65\)" "$ok"
check cert-slhdsa-ca             "" "i:CN=QuantaSeek testbed root \(slhdsa\)" "$ok"
check cert-expired               "" "Verify return code: 10 \(certificate has expired\)"
check cert-mismatch              "-verify_hostname localhost" "Verify return code: 62 \(hostname mismatch\)"
check cert-self-signed           "" "Verify return code: (18|19|20|21) "

# Second implementation.
check go-x25519mlkem768    "-groups X25519MLKEM768"     "Negotiated TLS1.3 group: X25519MLKEM768" "$ok"
check go-x25519mlkem768    "-groups x25519:secp256r1"   "$rejected"

# Certificate algorithms as written (from the exported chains, not from TLS).
for svc in cert-mldsa65 cert-mldsa65-intermediate cert-slhdsa-ca; do
  docker compose exec -T "$svc" sh -c \
    'openssl storeutl -noout -text -certs /out/chain.pem | grep -E "Subject:|Signature Algorithm:|Public Key Algorithm:" | sort -u' \
    | sed "s/^/INFO $svc /"
done

exit $fail
