#!/usr/bin/env bash
# setup-classical-arm.sh: build THROWAWAY hermetic PKIs for the comparison
# arms and expose matched loopback s_server endpoints.
#
# WHY: this is a PQC-only deployment. No classical certificate exists, so a
# classical baseline CANNOT be measured against the live gateway -- it has to be
# constructed. Both arms are identical except for the algorithms.
#
#   PQC arm       :4433  X25519MLKEM768 + ML-DSA-65 (both peers)
#   Classical arm :4434  X25519          + ECDSA P-256 server / RSA-2048 client
#
# Resumption is disabled on both (-no_ticket -no_cache) so every connection is a
# full handshake. Tear down with: pkill -f 's_server -accept 443[34]'
#
# NOTE: server certs MUST carry subjectAltName IP:127.0.0.1. `openssl s_client`
# does not verify hostnames by default, but curl does -- without a SAN, curl
# aborts after the server has already completed its side of the handshake and
# reports time_appconnect=0, which looks like "0 ms handshakes" rather than a
# failure. Learned the hard way.
set -euo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
export OPENSSL_CONF=/etc/ssl/openssl.cnf
D="$WORKDIR/hermetic"
SAN="subjectAltName=IP:127.0.0.1,DNS:localhost"

pkill -f "s_server -accept 4433" 2>/dev/null || true
pkill -f "s_server -accept 4434" 2>/dev/null || true
sleep 1
rm -rf "$D"; mkdir -p "$D/pqc" "$D/classical"; cd "$D"

gen_key() { # gen_key <alg> <out>
  case "$1" in
    ML-DSA-65) $OSSL genpkey -algorithm ML-DSA-65 -out "$2" 2>/dev/null ;;
    EC-P256)   $OSSL ecparam -name prime256v1 -genkey -noout -out "$2" 2>/dev/null ;;
    RSA-2048)  $OSSL genrsa -out "$2" 2048 2>/dev/null ;;
  esac
}

mk() { # mk <dir> <ca-alg> <srv-alg> <cli-alg>
  local d=$1 ca=$2 srv=$3 cli=$4
  ( cd "$d"
    gen_key "$ca" ca.key
    $OSSL req -x509 -new -key ca.key -out ca.crt -days 30 -subj "/CN=bench-$d-ca" 2>/dev/null
    # server: SAN is mandatory (see header note)
    gen_key "$srv" server.key
    $OSSL req -new -key server.key -out server.csr -subj "/CN=bench-$d-server" \
      -addext "$SAN" 2>/dev/null
    $OSSL x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out server.crt -days 30 -copy_extensions copyall 2>/dev/null
    # client: no SAN needed
    gen_key "$cli" client.key
    $OSSL req -new -key client.key -out client.csr -subj "/CN=bench-$d-client" 2>/dev/null
    $OSSL x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out client.crt -days 30 2>/dev/null )
  # fail loud if the SAN did not make it into the signed cert
  $OSSL x509 -in "$d/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "127.0.0.1" \
    || { echo "FATAL: $d server cert has no IP:127.0.0.1 SAN, curl will report 0 ms handshakes"; exit 1; }
}

echo "[*] hermetic PQC PKI (ML-DSA-65 throughout)"
mk pqc ML-DSA-65 ML-DSA-65 ML-DSA-65
echo "[*] hermetic classical PKI (ECDSA P-256 server / RSA-2048 client)"
mk classical EC-P256 EC-P256 RSA-2048

echo "[*] starting PQC endpoint :4433 (resumption OFF)"
nohup $OSSL s_server -accept 4433 -cert pqc/server.crt -key pqc/server.key \
  -verifyCAfile pqc/ca.crt -Verify 2 -groups X25519MLKEM768 -tls1_3 \
  -no_ticket -no_cache -www >/tmp/s_server_pqc.log 2>&1 &
echo "[*] starting classical endpoint :4434 (resumption OFF)"
nohup $OSSL s_server -accept 4434 -cert classical/server.crt -key classical/server.key \
  -verifyCAfile classical/ca.crt -Verify 2 -groups X25519 -tls1_3 \
  -no_ticket -no_cache -www >/tmp/s_server_classical.log 2>&1 &
sleep 2
ss -ltn 2>/dev/null | grep -E ":(4433|4434)" || { echo "FATAL: endpoints not listening, see /tmp/s_server_*.log"; exit 1; }

# prove curl (not just s_client) can complete a handshake on both arms
for pair in "4433:pqc:X25519MLKEM768" "4434:classical:X25519"; do
  p=${pair%%:*}; rest=${pair#*:}; dir=${rest%%:*}; grp=${rest##*:}
  ac=$(curl -s -o /dev/null -w "%{time_appconnect}" --cert "$dir/client.crt" --key "$dir/client.key" \
       --cacert "$dir/ca.crt" --curves "$grp" --tlsv1.3 "https://127.0.0.1:$p/" 2>/dev/null)
  case "$ac" in 0.000000|"") echo "FATAL: curl handshake FAILED on :$p (appconnect=$ac)"; exit 1 ;; esac
  # The live gateway sends exactly ONE certificate. s_server with -CAfile also sends
  # its CA (2 certs, ~+5.5KB on the PQC arm), which silently makes the arms
  # non-comparable to the deployment. -verifyCAfile keeps verification without
  # chain-building. Assert it, so this can never regress unnoticed.
  n=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$p -cert "$dir/client.crt" \
      -key "$dir/client.key" -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE")
  [ "$n" = "1" ] || { echo "FATAL: :$p server sends $n certs, expected 1 (leaf-only, as the gateway does)"; exit 1; }
  echo "[ok] :$p curl handshake OK (appconnect=${ac}s), server sends $n cert"
done
echo "[ok] hermetic arms ready under $D"
