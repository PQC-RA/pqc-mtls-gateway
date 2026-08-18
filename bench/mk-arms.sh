#!/usr/bin/env bash
# mk-arms.sh: stand up three stripped gateway arms from the REAL gateway image,
# differing ONLY in key-exchange group and certificate algorithm.
#
#   C classical  :9443  X25519           ECDSA P-256 certs
#   H hybrid     :9444  X25519MLKEM768   ML-DSA-65 certs   <- the deployment
#   P pure       :9445  MLKEM768         ML-DSA-65 certs   (same PKI as H)
#
# Stripped: no management-api, custodian, OCSP, CRL, pki-dist, ct-log, redis.
# Also no Lua policy plane -- it runs AFTER the handshake, so it cannot affect
# handshake bytes, handshake latency or TLS CPU, which are the measured
# quantities. Its absence is identical across arms. This does mean end-to-end
# request latency here is NOT comparable to the deployed gateway; we do not
# report that figure.
#
# Every arm is ASSERTED before any measurement runs: negotiated group must match
# the arm, and the server must send exactly the configured number of certificates.
# That assertion is the one that would have caught the published classical arm
# silently keeping the post-quantum group.
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
BASE=$WORKDIR
PKI=$BASE/pki
CONF=$BASE/conf
IMAGE=pqc-gateway:1.0.0
NET=pqc-gw_pqc-pki
# Resolve the backend by service name; a container IP changes whenever the
# network is recreated, and a stale one fails as a timeout rather than loudly.
BACKEND=${BACKEND:-http://shadow-mock:80}
mkdir -p "$CONF"

# arm  port  group             pki-dir
ARMS="classical:9443:X25519:classical
hybrid:9444:X25519MLKEM768:pqc
pure:9445:MLKEM768:pqc"

gen_conf() { # gen_conf <arm> <group> <pkidir>
  local arm=$1 grp=$2 pki=$3
  cat > "$CONF/$arm.conf" <<EOF
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx-$arm.pid;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 443 ssl;
        server_name pqc-gw.local;

        ssl_protocols TLSv1.3;
        ssl_certificate     /pki/server.crt;
        ssl_certificate_key /pki/server.key;

        # Pin the group for THIS arm. Asserted on the wire before measuring.
        ssl_conf_command Groups $grp;

        # Mutual TLS. ssl_client_certificate is the TRUST STORE (root+intermediate);
        # it is not transmitted. depth 2 allows leaf -> intermediate -> root.
        ssl_verify_client on;
        ssl_client_certificate /pki/ca-chain.crt;
        ssl_verify_depth 2;

        ssl_session_tickets off;
        ssl_session_cache   off;

        location / {
            proxy_pass $BACKEND;
            proxy_set_header Host \$host;
        }
    }
}
EOF
}

echo "[*] tearing down any previous arms"
for a in classical hybrid pure; do docker rm -f "remeasure-$a" >/dev/null 2>&1 || true; done

echo "[*] starting arms"
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  gen_conf "$arm" "$grp" "$pki"
  docker run -d --name "remeasure-$arm" --network "$NET" \
    -p "127.0.0.1:$port:443" \
    -v "$PKI/$pki:/pki:ro" \
    -v "$CONF/$arm.conf:/etc/nginx/nginx.conf:ro" \
    --entrypoint nginx "$IMAGE" -g 'daemon off;' >/dev/null
  echo "    $arm -> :$port  group=$grp  pki=$pki"
done <<< "$ARMS"

sleep 4

echo
echo "=== ASSERTIONS (a failure here means no measurement may proceed) ==="
# OpenSSL reports the negotiated group DIFFERENTLY depending on its kind:
#   PQ / hybrid  -> "Negotiated TLS1.3 group: X25519MLKEM768"
#   classical ECDH -> "Peer Temp Key: X25519, 253 bits"   (and NO group line)
# Grepping only the first makes a classical arm look unverifiable and a
# PQ-contaminated arm look fine. Check both, and fail closed if neither appears.
# Session info goes to STDERR, so capture 2>&1 -- suppressing it is what hid
# this the first time.
group_of() {  # group_of <s_client output>
  local g
  g=$(printf '%s' "$1" | grep -oE 'Negotiated TLS1.3 group: [^ ]+' | head -1 | sed 's/.*: //')
  [ -n "$g" ] || g=$(printf '%s' "$1" | grep -oE 'Peer Temp Key: [A-Za-z0-9_-]+' | head -1 | sed 's/.*: //')
  printf '%s' "${g:-UNKNOWN}"
}
fail=0
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  case "$arm" in classical) want_sig="ecdsa" ;; *) want_sig="mldsa65" ;; esac
  out=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$port \
        -CAfile "$PKI/$pki/ca-chain.crt" \
        -cert "$PKI/$pki/client.crt" -key "$PKI/$pki/client.key" \
        -groups "$grp" -showcerts 2>&1 || true)
  neg=$(group_of "$out")
  sig=$(printf '%s' "$out" | grep -oE 'Peer signature type: [^ ]+' | head -1 | sed 's/.*: //')
  ncert=$(printf '%s' "$out" | grep -c "BEGIN CERTIFICATE" || true)
  vok=$(printf '%s' "$out" | grep -c "Verify return code: 0 (ok)" || true)

  printf "  %-10s group=%-16s sig=%-24s certs=%s verify=%s\n" \
    "$arm" "$neg" "${sig:-NONE}" "$ncert" "$([ "${vok:-0}" -ge 1 ] && echo ok || echo FAIL)"
  [ "$neg" = "$grp" ]            || { echo "     *** GROUP MISMATCH: expected $grp, got $neg ***"; fail=1; }
  case "${sig:-}" in *$want_sig*) : ;; *) echo "     *** SIGALG MISMATCH: expected *$want_sig*, got ${sig:-NONE} ***"; fail=1 ;; esac
  [ "${ncert:-0}" = "1" ]        || { echo "     *** SERVER SENT $ncert CERTS, expected 1 ***"; fail=1; }
  [ "${vok:-0}" -ge 1 ]          || fail=1
done <<< "$ARMS"

echo
echo "=== cross-check: an arm must REFUSE a client from the other PKI ==="
code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" --cacert "$PKI/pqc/ca-chain.crt" \
       --cert "$PKI/classical/client.crt" --key "$PKI/classical/client.key" \
       --curves X25519MLKEM768 https://127.0.0.1:9444/ 2>/dev/null || echo 000)
echo "  classical client -> hybrid arm : HTTP ${code}  (expect 000/400, NOT 200)"
[ "$code" = "200" ] && { echo "  *** untrusted client ACCEPTED ***"; fail=1; }

echo
if [ $fail -eq 0 ]; then echo "ALL ARMS VERIFIED, safe to measure."; else echo "*** ASSERTIONS FAILED, do NOT measure ***"; exit 1; fi
