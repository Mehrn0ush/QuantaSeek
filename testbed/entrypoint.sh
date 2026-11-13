#!/bin/sh
# Generate this server's PKI at start-up, export the public certificates to
# /out, then run the TLS server. Private keys stay inside the container.
#
# Environment:
#   SERVER  openssl | go                     (default openssl)
#   GROUPS  key-exchange groups the server accepts, colon-separated
#   CERT    ecdsa | mldsa65 | mldsa65-intermediate | slhdsa-ca |
#           expired | mismatch | self-signed  (default ecdsa)
#   TLS     tls13 | tls12 | any               (default any)
set -eu

SERVER=${SERVER:-openssl}
CERT=${CERT:-ecdsa}
TLS=${TLS:-any}
: "${GROUPS:?GROUPS must be set}"

W=$(mktemp -d)
cd "$W"
# x509v3 extension sections for each certificate role.
cat > ext.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
authorityKeyIdentifier = keyid
[leaf_mismatch]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:other.invalid
authorityKeyIdentifier = keyid
[leaf_self]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
CNF

key() { # alg file
  case "$1" in
    ecdsa) openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
    mldsa65) openssl genpkey -quiet -algorithm ML-DSA-65 -out "$2" ;;
    slhdsa) openssl genpkey -quiet -algorithm SLH-DSA-SHA2-128s -out "$2" ;;
  esac
}
root() { # name alg
  key "$2" "$1.key"
  openssl req -x509 -new -key "$1.key" -subj "/CN=QuantaSeek testbed $1 ($2)" -days 30 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.pem"
}
issue() { # name alg issuer section [x509 validity args...]
  name=$1 alg=$2 issuer=$3 section=$4; shift 4
  key "$alg" "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=QuantaSeek testbed $name ($alg)" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" \
    -extfile ext.cnf -extensions "$section" "$@" -out "$name.pem"
}

EXTRA=""   # certificates sent after the leaf
case "$CERT" in
  ecdsa)
    root root ecdsa; issue leaf ecdsa root leaf -days 30 ;;
  mldsa65)
    root root mldsa65; issue leaf mldsa65 root leaf -days 30 ;;
  mldsa65-intermediate)
    root root ecdsa; issue inter mldsa65 root intermediate -days 30
    issue leaf ecdsa inter leaf -days 30; EXTRA=inter.pem ;;
  slhdsa-ca)
    root root slhdsa; issue leaf ecdsa root leaf -days 30 ;;
  expired)
    root root ecdsa
    issue leaf ecdsa root leaf -not_before 20250101000000Z -not_after 20250201000000Z ;;
  mismatch)
    root root ecdsa; issue leaf ecdsa root leaf_mismatch -days 30 ;;
  self-signed)
    # The exported root did not issue the leaf: validation must fail.
    root root ecdsa
    key ecdsa leaf.key
    openssl req -x509 -new -key leaf.key -subj "/CN=QuantaSeek testbed self-signed leaf" \
      -days 30 -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -addext "basicConstraints=critical,CA:FALSE" -out leaf.pem ;;
  *) echo "unknown CERT=$CERT" >&2; exit 2 ;;
esac

# Export public material only.
mkdir -p /out
cp root.pem /out/ca.pem
cat leaf.pem ${EXTRA} > /out/chain.pem
printf 'server=%s\ngroups=%s\ncert=%s\ntls=%s\nopenssl=%s\n' \
  "$SERVER" "$GROUPS" "$CERT" "$TLS" "$(openssl version)" > /out/config.txt

case "$TLS" in
  tls13) TLSFLAGS="-tls1_3" ;;
  tls12) TLSFLAGS="-tls1_2" ;;
  any) TLSFLAGS="" ;;
  *) echo "unknown TLS=$TLS" >&2; exit 2 ;;
esac

case "$SERVER" in
  openssl)
    chain_args=""
    [ -n "$EXTRA" ] && chain_args="-cert_chain $EXTRA"
    # shellcheck disable=SC2086
    exec openssl s_server -quiet -www -accept 4443 -cert leaf.pem -key leaf.key \
      $chain_args -groups "$GROUPS" $TLSFLAGS ;;
  go)
    cat leaf.pem ${EXTRA} > served.pem
    exec goserver -addr :4443 -cert served.pem -key leaf.key -groups "$GROUPS" ;;
  *) echo "unknown SERVER=$SERVER" >&2; exit 2 ;;
esac
