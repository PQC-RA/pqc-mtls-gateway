#!/usr/bin/env bash
# check-ocsp-and-policy-values.sh: three further checks against values the paper prints.
#
#   §V-E  zero-reload policy update latency   (paper: ~4.7 ms)
#   §VI-B OCSP -rother comparison             (paper: ~15.5 KB / +46% vs ~9.5 KB / +28%)
#   Finding 1 quantum buffer, via the sendRawCert policy option
#
# The OCSP comparison runs TWO SEPARATE responders on spare ports and queries
# them directly, so
# the live gateway and its stapling are never touched.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
PKI=/etc/pki/pqc-ca
CA=$PKI/ca-chain.crt
C=$REPO/admin-cert/gateway-admin.crt
K=$REPO/admin-cert/gateway-admin.key
E="$EXPORT_DIR"
OUT=$WORKDIR/ocsp-and-policy-values.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }
ADM=(curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1")

##############################################################################
say "=============== OCSP response size, -rother vs responder-leaf ==============="
say "  (paper §VI-B: full signer chain ~15.5 KB / +46%; responder leaf ~9.5 KB / +28%)"
say "  Two throwaway responders on :19080 / :19081. The live responder is untouched."
pkill -f "ocsp -port 1908" 2>/dev/null || true; sleep 1
COMMON=(-index $PKI/intermediate/db/index.txt -CA $PKI/intermediate/certs/intermediate-ca.crt
        -rsigner $PKI/ocsp/ocsp-pq.crt -rkey $PKI/ocsp/ocsp-pq.key -ndays 7 -nmin 60 -ignore_err)
nohup $OSSL ocsp -port 19080 "${COMMON[@]}"                                             >/tmp/ocsp_leaf.log 2>&1 &
nohup $OSSL ocsp -port 19081 "${COMMON[@]}" -rother $PKI/intermediate/certs/intermediate-ca.crt >/tmp/ocsp_rother.log 2>&1 &
sleep 2
ss -ltn 2>/dev/null | grep -qE ":19080" || { say "  FATAL: :19080 not listening"; tail -3 /tmp/ocsp_leaf.log | tee -a "$OUT"; }
ss -ltn 2>/dev/null | grep -qE ":19081" || { say "  FATAL: :19081 not listening"; tail -3 /tmp/ocsp_rother.log | tee -a "$OUT"; }

ask(){ # ask <port> <outfile>
  timeout 25 $OSSL ocsp -issuer $PKI/intermediate/certs/intermediate-ca.crt \
    -cert $E/client.crt -url http://127.0.0.1:$1 -respout "$2" -noverify >/dev/null 2>&1
  wc -c < "$2" 2>/dev/null || echo 0
}
L=$(ask 19080 /tmp/resp_leaf.der)
R=$(ask 19081 /tmp/resp_rother.der)
say "  responder leaf only (current config) : ${L} B"
say "  with -rother (full signer chain)     : ${R} B"
if [ "${L:-0}" -gt 0 ] && [ "${R:-0}" -gt 0 ]; then
  say "  difference                           : $((R-L)) B  (one ML-DSA-65 intermediate)"
  NOSTAPLE=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA -cert $E/client.crt -key $E/client.key 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}')
  TOT=$(( ${NOSTAPLE:-0} + 22481 ))
  say "  no-staple handshake total (read ${NOSTAPLE:-?} + written 22,481) = ${TOT} B"
  awk -v l="$L" -v r="$R" -v t="$TOT" 'BEGIN{
    printf "  leaf-only staple   = +%.1f%% of the whole handshake  (paper: +28%%)\n", 100*l/t;
    printf "  -rother staple     = +%.1f%% of the whole handshake  (paper: +46%%)\n", 100*r/t;
  }' | tee -a "$OUT"
fi
pkill -f "ocsp -port 1908" 2>/dev/null || true

##############################################################################
say
say "=============== zero-reload policy update latency ==============="
say "  (paper §V-E: policy updates applied in ~4.7 ms, no nginx reload)"
CN="gapzr-$RANDOM"
cd $REPO
PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=$CA PQC_ADMIN_CERT=$C PQC_ADMIN_KEY=$K \
  ./scripts/issue-cert.sh "$CN" http://shadow-mock:80 >/tmp/issue3.log 2>&1
CRT=$REPO/certs/$CN/$CN.crt; KEY=$REPO/certs/$CN/$CN.key
[ -f "$CRT" ] || { say "  FATAL: issuance failed"; tail -12 /tmp/issue3.log | tee -a "$OUT"; }
code(){ timeout 10 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" --cert "$CRT" --key "$KEY" https://127.0.0.1/api/v1/status 2>/dev/null; }
put(){ "${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$CN" -H "Content-Type: application/json" \
        -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"$1\"],\"rate_limit\":{\"rps\":10000,\"burst\":20000}}" -o /dev/null -w "%{time_total}" 2>/dev/null; }

say "  (a) admin PUT round-trip, 5 samples, control-plane cost:"
for i in 1 2 3 4 5; do
  t=$(put "/api/"); say "      PUT $i: $(awk -v x="$t" 'BEGIN{printf "%.2f", x*1000}') ms"
done

say "  (b) end-to-end: PUT a deny, then poll until the data plane refuses"
say "      NOTE: each probe is a full PQC handshake (~5 ms), so this BOUNDS the"
say "      apply time from above, it cannot resolve below one probe."
for r in 1 2 3; do
  put "/api/" >/dev/null; sleep 1
  [ "$(code)" = "200" ] || { say "      round $r: baseline not 200, skipping"; continue; }
  S=$(date +%s.%N); put "/blocked/" >/dev/null
  for j in $(seq 1 400); do [ "$(code)" != "200" ] && break; done
  Ee=$(date +%s.%N)
  say "      round $r: deny applied within $(echo "($Ee-$S)*1000" | bc -l | cut -c1-6) ms after $j probe(s)"
done
put "/api/" >/dev/null
say "  (c) gateway reload count, must be zero for a policy change:"
docker exec pqc-gateway sh -c "grep -c 'reload' /var/log/nginx/error.log 2>/dev/null" 2>/dev/null | sed 's/^/      reload lines in error.log: /' | tee -a "$OUT"

##############################################################################
say
say "=============== header sizing for sendRawCert routes ==============="
say "  A route may opt in to sendRawCert, and policy_router.lua then forwards the"
say "  client certificate as an escaped header. An ML-DSA-65 certificate does not"
say "  fit nginx default 8 KB header buffer, which is why nginx.conf sets"
say "  large_client_header_buffers 4 32k. This checks the header against both."
ESC=$(python3 - "$E/client.crt" <<'PY'
import sys,urllib.parse
pem=open(sys.argv[1]).read()
print(len(urllib.parse.quote(pem, safe='')))
PY
)
PEM=$(wc -c < "$E/client.crt")
say "  client cert PEM              : ${PEM} B"
say "  URL-escaped (what nginx sets): ${ESC} B    <- paper Finding 1: 8,850-10,347 B"
say "  nginx default header buffer  : 8,192 B"
say "  configured here              : large_client_header_buffers 4 32k"
awk -v e="$ESC" 'BEGIN{ if(e>8192) printf "  ==> %d B exceeds the 8 KB default by %d B, so the 32k buffer above is required\n", e, e-8192;
                        else printf "  ==> %d B fits inside the 8 KB default\n", e }' | tee -a "$OUT"

say "  -- enabling sendRawCert on CN=$CN and re-testing the data path"
"${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$CN" -H "Content-Type: application/json" \
  -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"/api/\"],\"sendRawCert\":true,\"rate_limit\":{\"rps\":10000,\"burst\":20000}}" >/dev/null 2>&1
sleep 2
say "     request with sendRawCert=true  -> HTTP $(code)"
docker exec pqc-gateway sh -c "grep -i 'sendRawCert' /var/log/nginx/error.log 2>/dev/null | tail -2" 2>/dev/null | sed 's/^/     log: /' | tee -a "$OUT"
"${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$CN" -H "Content-Type: application/json" \
  -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"/api/\"],\"sendRawCert\":false,\"rate_limit\":{\"rps\":10000,\"burst\":20000}}" >/dev/null 2>&1
sleep 1
say "     request with sendRawCert=false -> HTTP $(code)  (restored)"

say
say "=============== CLEANUP ==============="
"${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$CN" >/dev/null 2>&1
SER=$($OSSL x509 -in "$CRT" -noout -serial 2>/dev/null | cut -d= -f2)
"${ADM[@]}" -X POST "https://127.0.0.1/admin/certs/revoke" -H "Content-Type: application/json" \
  -d "{\"serial\":\"$SER\",\"reason\":\"cessationOfOperation\"}" >/dev/null 2>&1
say "  revoked test identity $CN (serial $SER); route removed"
say "raw -> $OUT"
