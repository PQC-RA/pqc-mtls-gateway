#!/usr/bin/env bash
# certsize.sh: is certificate DER size deterministic, and why did the classical
# reference column not match while every PQC row did?
#
# DER size is fully determined by: algorithm, subject DN, issuer DN, serial,
# validity encoding, and the extension set. Nothing else. So a mismatch means the
# construction differed, not the system.
#
# This (a) re-derives every PQC row from the live PKI, and (b) shows how far a
# classical leaf moves under realistic DN/extension choices.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
PKI=/etc/pki/pqc-ca
W=/tmp/certsize; rm -rf $W; mkdir -p $W; cd $W
OUT=$WORKDIR/certsize.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }
der(){ $OSSL x509 -in "$1" -outform DER 2>/dev/null | wc -c; }

say "=============== A. PQC rows, straight from the live PKI ==============="
say "  | role | paper | measured | subject |"
say "  |------|------:|---------:|---------|"
row(){ # row <label> <paper> <file>
  local dn; dn=$($OSSL x509 -in "$3" -noout -subject 2>/dev/null | sed 's/^subject=//')
  say "  | $1 | $2 | **$(der "$3")** | \`$dn\` |"
}
row "Root CA"          5822 $PKI/root/certs/root-ca.crt
row "Intermediate CA"  6016 $PKI/intermediate/certs/intermediate-ca.crt
row "Server (TLS leaf)" 6107 /etc/ssl/pqc/server-mldsa65.crt
row "OCSP signing"     5882 $PKI/ocsp/ocsp-pq.crt

say
say "  Client leaf: the paper says 6,134 B. That row is identity-dependent,"
say "  the DN is chosen per enrollment, so it is NOT a fixed property:"
for c in $EXPORT_DIR/client.crt "$REPO"/admin-cert/gateway-admin.crt; do
  [ -f "$c" ] || continue
  pem=$(mktemp); awk '/BEGIN CERT/,/END CERT/' "$c" > $pem
  say "    $(der $pem) B  <- $($OSSL x509 -in $pem -noout -subject 2>/dev/null | sed 's/^subject=//')"
  rm -f $pem
done

say
say "=============== B. Why the classical column did not match ==============="
say "  A classical leaf's size under different, all-plausible constructions."
say "  Paper: RSA-2048 CA 851 B, ECDSA P-256 server 562 B, RSA-2048 client 765 B."
say

$OSSL genrsa -out ca.key 2048 2>/dev/null
mkca(){ $OSSL req -x509 -new -key ca.key -out "$2" -days 30 -subj "$1" 2>/dev/null; }
mkleaf(){ # mkleaf <subj> <keyfile> <out> [extfile]
  $OSSL req -new -key "$2" -out l.csr -subj "$1" 2>/dev/null
  if [ -n "${4:-}" ]; then
    $OSSL x509 -req -in l.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out "$3" -days 30 -extfile "$4" 2>/dev/null
  else
    $OSSL x509 -req -in l.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out "$3" -days 30 2>/dev/null
  fi
}
$OSSL ecparam -name prime256v1 -genkey -noout -out ec.key 2>/dev/null
$OSSL genrsa -out rsa.key 2048 2>/dev/null
printf 'subjectAltName=DNS:pqc-gw.local\n' > san1.ext
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' > san2.ext
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > san3.ext

say "  --- RSA-2048 self-signed CA, by DN length"
for dn in "/CN=ca" "/C=BG/O=PQC-GW/CN=Classical CA" "/C=BG/O=PQC-GW/OU=Certificate Authority Operations/CN=PQC-GW Classical Root CA G1"; do
  mkca "$dn" ca.crt; say "    $(der ca.crt) B   $dn"
done
mkca "/C=BG/O=PQC-GW/CN=Classical CA" ca.crt   # settle on a middling CA for the leaves

say "  --- ECDSA P-256 server leaf"
mkleaf "/CN=pqc-gw.local" ec.key s1.crt              ; say "    $(der s1.crt) B   short DN, no extensions"
mkleaf "/C=BG/O=PQC-GW/OU=PQC-Gateway/CN=pqc-gw.local" ec.key s2.crt        ; say "    $(der s2.crt) B   paper-style DN, no extensions"
mkleaf "/C=BG/O=PQC-GW/OU=PQC-Gateway/CN=pqc-gw.local" ec.key s3.crt san1.ext ; say "    $(der s3.crt) B   + SAN DNS only"
mkleaf "/C=BG/O=PQC-GW/OU=PQC-Gateway/CN=pqc-gw.local" ec.key s4.crt san2.ext ; say "    $(der s4.crt) B   + SAN IP+DNS  (what the rebuild used)"
mkleaf "/C=BG/O=PQC-GW/OU=PQC-Gateway/CN=pqc-gw.local" ec.key s5.crt san3.ext ; say "    $(der s5.crt) B   + SAN IP+DNS + KU + EKU"

say "  --- RSA-2048 client leaf"
mkleaf "/CN=client" rsa.key c1.crt                                    ; say "    $(der c1.crt) B   short DN"
mkleaf "/C=BG/O=PQC-GW/OU=M2M-Client/CN=gateway-admin" rsa.key c2.crt ; say "    $(der c2.crt) B   paper-style DN"

say
say "  --- the deployment's own classical certs, for reference"
for f in /etc/ssl/pqc/enroll-classical.crt /etc/ssl/pqc/internal-tls.crt $PKI/enroll-classical-ca.crt; do
  [ -f "$f" ] || continue
  alg=$($OSSL x509 -in "$f" -noout -text 2>/dev/null | grep -m1 "Public Key Algorithm" | sed 's/.*: //')
  say "    $(der "$f") B   $(basename $f)  ($alg)"
done
say
say "raw -> $OUT"
