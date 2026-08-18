#!/usr/bin/env bash
# check-negative-controls-detail.sh: the two negative controls that need more than an exit code.
#
# Revocation is exercised through POST /admin/certs/revoke with
# {"serial","reason"}, which is the endpoint that performs it.
#
# For the classical-keyed certificate, curl alone reports HTTP 400, which is
# ambiguous: 400 is also what nginx returns when NO client certificate was sent.
# This pins down the mechanism by capturing the response body and nginx's own
# verify state.
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
W="$WORKDIR/negative-controls-work"
OUT=$WORKDIR/negative-controls-detail.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }
ADM=(curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1")

say "=============== classical-keyed cert: what exactly does the gateway do? ==============="
say "  400 alone is ambiguous, nginx also returns 400 when NO client cert was sent."
say "  Comparing a VALID ML-DSA-65 identity against the two bypass certificates."
say

probe(){ # probe <label> <crt> <key>
  local label=$1 crt=$2 key=$3
  local body code
  body=$(timeout 20 curl -s --cacert "$CA" --cert "$crt" --key "$key" \
         -w "\n__CODE__%{http_code}" https://127.0.0.1/api/v1/status 2>/dev/null)
  code=$(echo "$body" | grep -o '__CODE__.*' | sed 's/__CODE__//')
  local text; text=$(echo "$body" | sed 's/__CODE__.*//' | tr -d '\n' | head -c 150)
  say "  $label"
  say "     HTTP ${code:-000}   body: ${text:-<empty>}"
  # what did the TLS layer actually conclude about the client certificate?
  local sc
  sc=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:443 -CAfile "$CA" \
       -cert "$crt" -key "$key" -tls1_3 2>&1 \
       | grep -iE "^Verify return code|alert|Client Certificate|no client certificate" | head -2 | tr '\n' ' ')
  say "     s_client: ${sc:-<none>}"
}

BENCH="$EXPORT_DIR"
probe "CONTROL, valid ML-DSA-65 (bench-client)" "$BENCH/client.crt" "$BENCH/client.key"
for alg in rsa ec; do
  [ -s $W/$alg.crt ] || continue
  BCN=$($OSSL x509 -in $W/$alg.crt -noout -subject | sed 's/.*CN *= *//;s/,.*//')
  "${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$BCN" \
    -H "Content-Type: application/json" \
    -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"/api/\"],\"rate_limit\":{\"rps\":1000,\"burst\":2000}}" >/dev/null 2>&1
  sleep 1
  probe "BYPASS, $alg key, signed by the legitimate ML-DSA-65 intermediate (CN=$BCN, route present)" $W/$alg.crt $W/$alg.key
  "${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$BCN" >/dev/null 2>&1
done
say
say "  -- gateway error log, last few client-certificate lines:"
docker exec pqc-gateway sh -c "tail -200 /var/log/nginx/error.log 2>/dev/null | grep -iE 'certificate|sigalg|no suitable|unsupported' | tail -5" 2>/dev/null | sed 's/^/     /' | tee -a "$OUT"

say
say "=============== revoke via POST /admin/certs/revoke ==============="
CN="gaprev-$RANDOM"
cd $REPO
PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=$CA PQC_ADMIN_CERT=$C PQC_ADMIN_KEY=$K \
  ./scripts/issue-cert.sh "$CN" http://shadow-mock:80 >/tmp/issue2.log 2>&1
CRT=$REPO/certs/$CN/$CN.crt; KEY=$REPO/certs/$CN/$CN.key
[ -f "$CRT" ] || { say "FATAL: issuance failed"; tail -15 /tmp/issue2.log | tee -a "$OUT"; exit 1; }
SER=$($OSSL x509 -in "$CRT" -noout -serial | cut -d= -f2)
req(){ timeout 20 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" --cert "$CRT" --key "$KEY" https://127.0.0.1/api/v1/status 2>/dev/null; }
say "  issued CN=$CN serial $SER; pre-revocation request -> HTTP $(req)  (expect 200)"

R=$("${ADM[@]}" -X POST "https://127.0.0.1/admin/certs/revoke" \
     -H "Content-Type: application/json" \
     -d "{\"serial\":\"$SER\",\"reason\":\"cessationOfOperation\"}" 2>&1)
say "  revoke -> $(echo "$R" | head -c 200)"

say "  waiting for the CRL to carry serial $SER ..."
found=0
for i in $(seq 1 30); do
  if $OSSL crl -in $PKI/hybrid-combined-crl.pem -noout -text 2>/dev/null | grep -qi "Serial Number: *$SER"; then
    say "    serial appears in the CRL after ~$((i*2)) s"; found=1; break
  fi
  sleep 2
done
[ "$found" = "1" ] || say "    *** serial never appeared in the CRL within 60 s ***"

say "  -- offline path validation (the paper's X509 error 23):"
V=$($OSSL verify -crl_check -CAfile "$CA" -CRLfile $PKI/hybrid-combined-crl.pem "$CRT" 2>&1)
echo "$V" | sed 's/^/     /' | tee -a "$OUT"
echo "$V" | grep -q "error 23" && say "  ==> PASS: error 23 (certificate revoked)" || say "  ==> *** no error 23 ***"

say "  -- live data plane: request with the revoked certificate"
for i in $(seq 1 20); do
  CODE=$(req); [ "$CODE" != "200" ] && break; sleep 3
done
say "     HTTP ${CODE}  after ~$((i*3)) s   (expect a refusal, not 200)"
[ "$CODE" = "200" ] && say "  ==> *** REVOKED CERT STILL ACCEPTED BY THE DATA PLANE ***" || say "  ==> PASS: refused"
docker exec pqc-gateway sh -c "grep -ihE 'revoked' /var/log/nginx/error.log 2>/dev/null | tail -2" 2>/dev/null | sed 's/^/     data plane: /' | tee -a "$OUT"

"${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$CN" >/dev/null 2>&1
say
say "  revoked in CA index now: $(grep -c '^R' $PKI/intermediate/db/index.txt)"
say "raw -> $OUT"
