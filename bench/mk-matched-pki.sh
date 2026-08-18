#!/usr/bin/env bash
# mk-matched-pki.sh: build two THREE-TIER PKIs that are byte-identical in every
# respect except the signature algorithm.
#
# THE POINT: certificate DER size is determined by algorithm, subject DN, issuer
# DN, serial, validity encoding and extension set. Hold all of those constant and
# the size difference IS the algorithm difference -- no "construction-dependent"
# caveat, no unreproducible column. That is what went wrong with the published
# classical column, which cannot be reconstructed from what survives.
#
#   pqc/           ML-DSA-65   root -> intermediate -> {server, client, ocsp}
#   classical/     ECDSA P-256 root -> intermediate -> {server, client, ocsp}
#   classical-rsa/ RSA-2048    root -> intermediate -> {server, client, ocsp}
#
# The pure-ML-KEM arm deliberately REUSES pqc/, so the only variable between the
# hybrid and pure arms is the key-exchange group.
#
# WHY FIVE ROLES AND TWO CLASSICAL ARMS: the paper's certificate-size table has
# five roles including an OCSP signer, and its classical column is RSA-2048 for
# the root and client with ECDSA P-256 only for the server leaf. A four-role
# ECDSA-only comparison cannot replace that column without silently changing
# what the root and client rows are measured against. Both additions are pure
# keygen and signing, so neither is exposed to the testbed's timing variance.
set -euo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this campaign builds its PKIs and writes its output. Defaults to the
# directory the scripts live in. Several of these REBUILD it from scratch, so
# point it somewhere disposable rather than at a directory you care about.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
ROOT=$WORKDIR/pki
DAYS=3650

# --- identical across BOTH arms -----------------------------------------------
DN_ROOT="/C=BG/O=PQC-GW/OU=Certificate Authority Operations/CN=PQC-GW Root CA G1"
DN_INT="/C=BG/O=PQC-GW/OU=M2M Certificate Issuing CA/CN=PQC-GW Intermediate CA G1"
DN_SRV="/C=BG/O=PQC-GW/OU=PQC-Gateway/CN=pqc-gw.local"
DN_CLI="/C=BG/O=PQC-GW/OU=Admin/CN=gateway-admin"
DN_OCSP="/C=BG/O=PQC-GW/OU=OCSP Responder/CN=PQC-GW OCSP Signer G1"
# Serials are PINNED: -CAcreateserial picks a random 159-bit value whose DER
# length varies run to run, which would leak into the size comparison.
SER_INT=0x1001; SER_SRV=0x1002; SER_CLI=0x1003; SER_OCSP=0x1004

rm -rf "$ROOT"; mkdir -p "$ROOT"; cd "$ROOT"

cat > ca.ext <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
cat > int.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:pqc-gw.local,DNS:localhost,IP:127.0.0.1
EOF
cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
# id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2.1) is what a delegated responder
# certificate carries so clients do not try to revocation-check the responder
# itself. It is a 2-byte DER NULL, present in both arms, so it cancels out.
cat > ocsp.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
1.3.6.1.5.5.7.48.1.5=DER:05:00
EOF

genkey() { # genkey <alg> <out>
  case "$1" in
    mldsa) $OSSL genpkey -algorithm ML-DSA-65 -out "$2" ;;
    ecdsa) $OSSL ecparam -name prime256v1 -genkey -noout -out "$2" ;;
    rsa)   $OSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" ;;
    *) echo "unknown alg $1" >&2; return 1 ;;
  esac
}

build() { # build <alg> <dir>
  local alg=$1 d=$2
  mkdir -p "$d"; ( cd "$d"
    genkey "$alg" root.key
    # Self-sign via a CSR rather than `req -x509`: `req` has no -extfile, and we
    # need the extension set and serial pinned exactly as for the other certs.
    $OSSL req -new -key root.key -out root.csr -subj "$DN_ROOT"
    $OSSL x509 -req -in root.csr -signkey root.key -set_serial 0x1000 \
      -out root.crt -days $DAYS -extfile ../ca.ext

    genkey "$alg" int.key
    $OSSL req -new -key int.key -out int.csr -subj "$DN_INT"
    $OSSL x509 -req -in int.csr -CA root.crt -CAkey root.key -set_serial $SER_INT \
      -out int.crt -days $DAYS -extfile ../int.ext

    genkey "$alg" server.key
    $OSSL req -new -key server.key -out server.csr -subj "$DN_SRV"
    $OSSL x509 -req -in server.csr -CA int.crt -CAkey int.key -set_serial $SER_SRV \
      -out server.crt -days $DAYS -extfile ../server.ext

    genkey "$alg" client.key
    $OSSL req -new -key client.key -out client.csr -subj "$DN_CLI"
    $OSSL x509 -req -in client.csr -CA int.crt -CAkey int.key -set_serial $SER_CLI \
      -out client.crt -days $DAYS -extfile ../client.ext

    genkey "$alg" ocsp.key
    $OSSL req -new -key ocsp.key -out ocsp.csr -subj "$DN_OCSP"
    $OSSL x509 -req -in ocsp.csr -CA int.crt -CAkey int.key -set_serial $SER_OCSP \
      -out ocsp.crt -days $DAYS -extfile ../ocsp.ext

    # chain files for the three transmit policies
    cat int.crt root.crt          > ca-chain.crt        # trust store
    cp  client.crt                  client-leaf.pem     # policy A: leaf only
    cat client.crt int.crt        > client-int.pem      # policy B: leaf+intermediate
    cat client.crt int.crt root.crt > client-full.pem   # policy C: leaf+int+root
    cp  server.crt                  server-leaf.pem
    cat server.crt int.crt        > server-int.pem
  )
}

echo "[*] building ML-DSA-65 PKI";   build mldsa pqc
echo "[*] building ECDSA P-256 PKI"; build ecdsa classical
echo "[*] building RSA-2048 PKI";    build rsa   classical-rsa

ARMS="pqc classical classical-rsa"
ROLES="root int server client ocsp"

# --- verification -------------------------------------------------------------
der(){ $OSSL x509 -in "$1" -outform DER | wc -c; }
fail=0
echo
echo "=== chain validity (every arm must verify) ==="
for a in $ARMS; do
  for leaf in server client ocsp; do
    if $OSSL verify -CAfile $a/ca-chain.crt $a/$leaf.crt >/dev/null 2>&1; then
      echo "  OK   $a/$leaf.crt"
    else
      echo "  FAIL $a/$leaf.crt"; fail=1
    fi
  done
done

echo
echo "=== DNs must be byte-identical across arms ==="
for role in $ROLES; do
  a=$($OSSL x509 -in pqc/$role.crt -noout -subject)
  ok=1
  for arm in classical classical-rsa; do
    b=$($OSSL x509 -in $arm/$role.crt -noout -subject)
    [ "$a" = "$b" ] || { echo "  MISMATCH $role in $arm"; echo "    pqc: $a"; echo "    $arm: $b"; ok=0; fail=1; }
  done
  if [ $ok -eq 1 ]; then echo "  OK   $role  ${a#subject=}"; fi
done

echo
echo "=== certificate sizes (DER bytes), difference is PURELY the algorithm ==="
printf "  %-12s %10s %10s %8s %10s %8s\n" role ML-DSA-65 ECDSA-P256 ratio RSA-2048 ratio
for role in $ROLES; do
  p=$(der pqc/$role.crt); e=$(der classical/$role.crt); r=$(der classical-rsa/$role.crt)
  printf "  %-12s %10s %10s %8s %10s %8s\n" "$role" "$p" "$e" \
    "$(awk -v x=$p -v y=$e 'BEGIN{printf "%.2fx",x/y}')" "$r" \
    "$(awk -v x=$p -v y=$r 'BEGIN{printf "%.2fx",x/y}')"
done

echo
echo "=== CSV for the paper ==="
{ echo "role,mldsa65,ecdsa_p256,ratio_ecdsa,rsa2048,ratio_rsa"
  for role in $ROLES; do
    p=$(der pqc/$role.crt); e=$(der classical/$role.crt); r=$(der classical-rsa/$role.crt)
    echo "$role,$p,$e,$(awk -v x=$p -v y=$e 'BEGIN{printf "%.2f",x/y}'),$r,$(awk -v x=$p -v y=$r 'BEGIN{printf "%.2f",x/y}')"
  done
} | tee "$ROOT/cert-sizes.csv"

echo
echo "=== transmit policies (bytes on the wire, client side) ==="
printf "  %-22s %10s %10s\n" policy ML-DSA-65 ECDSA-P256
for f in client-leaf client-int client-full; do
  p=$(cat pqc/$f.pem | $OSSL crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | $OSSL pkcs7 -print_certs -outform DER 2>/dev/null | wc -c || echo 0)
  printf "  %-22s %10s %10s\n" "$f" \
    "$(grep -c 'BEGIN CERT' pqc/$f.pem) certs" "$(grep -c 'BEGIN CERT' classical/$f.pem) certs"
done

echo
[ $fail -eq 0 ] && echo "PKI OK -> $ROOT" || { echo "*** VERIFICATION FAILED ***"; exit 1; }
