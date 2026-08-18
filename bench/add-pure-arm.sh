#!/usr/bin/env bash
# add-pure-arm.sh: add the third arm from the original three-arm comparison:
# PURE ML-KEM-768 key exchange (no X25519 hedge) + ML-DSA-65 auth, on :4435.
# Reuses the hermetic PQC PKI so the ONLY difference from :4433 is the group.
set -uo pipefail
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
cd "$BENCH_HOME"
# Same resolution as setup-classical-arm.sh, so producer and consumer agree.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
D="$WORKDIR/hermetic/pqc"
PORT=4435

# `openssl list -tls-groups` prints ALL groups on one colon-separated line,
# so match membership in that line rather than per-line.
AVAIL=$($OSSL list -tls-groups 2>/dev/null | tr -d ' ')
GROUP=""
for g in MLKEM768 mlkem768; do
  case ":$AVAIL:" in *":$g:"*) GROUP="$g"; break ;; esac
done
[ -z "$GROUP" ] && { echo "FATAL: pure ML-KEM-768 group not offered by this OpenSSL"; echo "  available: $AVAIL"; exit 1; }
echo "[*] pure-KEM group resolved to: $GROUP"

pkill -f "s_server -accept $PORT" >/dev/null 2>&1 || true
sleep 1
nohup $OSSL s_server -accept $PORT -cert $D/server.crt -key $D/server.key \
  -verifyCAfile $D/ca.crt -Verify 2 -groups "$GROUP" -tls1_3 \
  -no_ticket -no_cache -www >/tmp/s_server_pure.log 2>&1 &
sleep 2
ss -ltn 2>/dev/null | grep -q ":$PORT" || { echo "FATAL: :$PORT not listening"; tail -5 /tmp/s_server_pure.log; exit 1; }

ac=$(curl -s -o /dev/null -w "%{time_appconnect}" --cert $D/client.crt --key $D/client.key \
     --cacert $D/ca.crt --curves "$GROUP" --tlsv1.3 "https://127.0.0.1:$PORT/" 2>/dev/null)
case "$ac" in 0.000000|"") echo "FATAL: curl handshake failed on :$PORT"; exit 1 ;; esac
n=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$PORT -cert $D/client.crt -key $D/client.key \
    -groups "$GROUP" -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE")
[ "$n" = "1" ] || { echo "FATAL: :$PORT sends $n certs, expected 1"; exit 1; }
neg=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$PORT -cert $D/client.crt -key $D/client.key \
      -groups "$GROUP" 2>/dev/null | grep -E "Negotiated TLS1.3 group" | sed 's/^ *//')
echo "[ok] :$PORT up, appconnect=${ac}s, 1 cert, $neg"
echo "$GROUP" > /tmp/pure_group
