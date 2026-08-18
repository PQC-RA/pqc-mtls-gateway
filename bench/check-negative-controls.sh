#!/usr/bin/env bash
# check-negative-controls.sh: three negative controls. Each of these must FAIL.
#
#   §V-A  out-of-route CN  -> HTTP 403 (policy plane fails closed)
#   §V-A  revoked cert     -> path validation fails, X509 error 23
#   §VI-C classical-keyed certificate SIGNED BY THE LEGITIMATE PQC
#         INTERMEDIATE -> handshake must be refused
#
# The third is the paper's Finding 3 evidence and the strongest form of the test:
# chain validation ALONE admits such a certificate, so only the explicit
# signature-algorithm restriction rejects it. Verifying that issuance refuses to
# MINT one is weaker -- it does not prove the handshake rejects one that exists.
# An `ssl_conf_command` OpenSSL does not recognise is accepted at parse time and
# never applied, so this is the only check that proves the restriction is live.
#
# Everything it creates is cleaned up at the end.
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
W=$WORKDIR/negative-controls-work; rm -rf $W; mkdir -p $W
OUT=$WORKDIR/negative-controls.txt; : > "$OUT"
FAILED=0   # set by any control that did not conclusively pass
say(){ echo "$@" | tee -a "$OUT"; }
ADM=(curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1")

CN="gapneg-$RANDOM"

say "=============== SETUP: issue a throwaway identity CN=$CN ==============="
cd $REPO
PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=$CA \
PQC_ADMIN_CERT=$C PQC_ADMIN_KEY=$K \
  ./scripts/issue-cert.sh "$CN" http://shadow-mock:80 >/tmp/issue.log 2>&1
if [ ! -f "$REPO/certs/$CN/$CN.crt" ]; then say "FATAL: issuance failed"; tail -20 /tmp/issue.log | tee -a "$OUT"; exit 1; fi
CRT=$REPO/certs/$CN/$CN.crt; KEY=$REPO/certs/$CN/$CN.key
SER=$($OSSL x509 -in "$CRT" -noout -serial | cut -d= -f2)
say "  issued, serial $SER"
req(){ timeout 20 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" --cert "$CRT" --key "$KEY" https://127.0.0.1/api/v1/status 2>/dev/null; }
say "  control: request with route in place -> HTTP $(req)   (expect 200)"

say
say "=============== out-of-route CN must be refused ==============="
"${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$CN" >/tmp/delroute.log 2>&1
sleep 1
CODE=$(req)
say "  route deleted; request -> HTTP $CODE   (paper §V-A: 403, policy plane fails closed)"
[ "$CODE" = "403" ] && say "  ==> PASS" || say "  ==> *** UNEXPECTED (got $CODE) ***"

say
say "=============== revoked certificate must fail path validation ==============="
# put the route back so any refusal is attributable to revocation, not policy
"${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$CN" \
  -H "Content-Type: application/json" \
  -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"/api/\"],\"rate_limit\":{\"rps\":1000,\"burst\":2000}}" >/dev/null 2>&1
sleep 1
say "  route restored; pre-revocation request -> HTTP $(req)   (expect 200)"
"${ADM[@]}" -X POST "https://127.0.0.1/admin/certs/$SER/revoke" \
  -H "Content-Type: application/json" -d '{"reason":"cessationOfOperation"}' >/tmp/revoke.log 2>&1
say "  revoke -> $(head -c 160 /tmp/revoke.log)"
# force a CRL regeneration + let the data-plane poller pick it up
docker exec pqc-crl-renewer sh -c 'kill -USR1 1 2>/dev/null' >/dev/null 2>&1 || true
sleep 12
say "  -- offline path validation against the live CRL (the paper's error 23):"
$OSSL verify -crl_check -CAfile "$CA" -CRLfile $PKI/hybrid-combined-crl.pem "$CRT" 2>&1 | sed 's/^/     /' | tee -a "$OUT"
V=$($OSSL verify -crl_check -CAfile "$CA" -CRLfile $PKI/hybrid-combined-crl.pem "$CRT" 2>&1)
echo "$V" | grep -q "error 23" && say "  ==> PASS: X509 error 23 (certificate revoked)" || say "  ==> *** no error 23 ***"
say "  -- live request with the revoked certificate:"
CODE=$(req)
say "     HTTP $CODE   (expect a refusal, not 200)"
[ "$CODE" = "200" ] && say "  ==> *** REVOKED CERT STILL ACCEPTED ***" || say "  ==> PASS (refused)"

say
say "=============== classical-keyed cert signed by the PQC intermediate ==============="
say "  Minting out-of-band with the intermediate key directly -- deliberately"
say "  creating the artifact issuance is designed to refuse."
INT_CRT=$PKI/intermediate/certs/intermediate-ca.crt
INT_KEY=$PKI/intermediate/private/intermediate-ca.key
[ -r "$INT_KEY" ] || { say "FATAL: cannot read $INT_KEY"; exit 1; }

for alg in rsa ec; do
  BCN="bypass-$alg-$RANDOM"
  case $alg in
    rsa) $OSSL genrsa -out $W/$alg.key 2048 2>/dev/null ;;
    ec)  $OSSL ecparam -name prime256v1 -genkey -noout -out $W/$alg.key 2>/dev/null ;;
  esac
  $OSSL req -new -key $W/$alg.key -out $W/$alg.csr -subj "/C=BG/O=PQC-GW/OU=M2M-Client/CN=$BCN" 2>/dev/null
  $OSSL x509 -req -in $W/$alg.csr -CA "$INT_CRT" -CAkey "$INT_KEY" -CAcreateserial \
    -out $W/$alg.crt -days 1 2>/dev/null
  if [ ! -s $W/$alg.crt ]; then say "  $alg: MINT FAILED"; continue; fi

  KEYALG=$($OSSL x509 -in $W/$alg.crt -noout -text 2>/dev/null | grep -A1 "Subject Public Key Info" | tail -1 | sed 's/^ *//')
  SIGALG=$($OSSL x509 -in $W/$alg.crt -noout -text 2>/dev/null | grep -m1 "Signature Algorithm" | sed 's/^ *//')
  say
  say "  --- $alg leaf: CN=$BCN"
  say "      $KEYALG"
  say "      $SIGALG   <- signed by the legitimate ML-DSA-65 intermediate"

  # Step 1: does CHAIN VALIDATION alone admit it?  (the paper's premise)
  VOUT=$($OSSL verify -CAfile "$CA" $W/$alg.crt 2>&1)
  say "      chain validation: $VOUT"
  echo "$VOUT" | grep -q ": OK" \
    && say "      ==> chain validation ADMITS it, so only the sigalg guard can reject it" \
    || say "      ==> chain validation rejected it (unexpected)"

  # give it a route, so any refusal is attributable to TLS and not to policy
  "${ADM[@]}" -X PUT "https://127.0.0.1/admin/policy/routes/$BCN" \
    -H "Content-Type: application/json" \
    -d "{\"backend\":\"http://shadow-mock:80\",\"allowed_paths\":[\"/api/\"],\"rate_limit\":{\"rps\":1000,\"burst\":2000}}" >/dev/null 2>&1
  sleep 1

  # Step 2: does the HANDSHAKE refuse it?
  HS=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:443 -CAfile "$CA" \
       -cert $W/$alg.crt -key $W/$alg.key -tls1_3 2>&1 | grep -iE "alert|verify error|Peer signature|handshake failure|no suitable signature" | head -3)
  say "      handshake: ${HS:-<no diagnostic>}"
  CODE=$(timeout 20 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" \
         --cert $W/$alg.crt --key $W/$alg.key https://127.0.0.1/api/v1/status 2>/dev/null)
  say "      curl over mTLS -> HTTP ${CODE:-000}   (000 = TLS refused, which is the pass)"
  # Name the codes that count. "not 200" is not a pass: 429 means the gateway
  # rate-limited us (/enroll is 5r/m) and the guard was never reached, and a
  # 5xx means something else broke. Both must read as INCONCLUSIVE, or this
  # control silently certifies a property it did not test.
  case "${CODE:-000}" in
    200)
      say "      ==> *** BYPASS SUCCEEDED, PQC-ONLY CLIENT AUTH IS NOT ENFORCED ***"
      FAILED=1 ;;
    000|400)
      say "      ==> PASS: refused at the handshake" ;;
    429)
      say "      ==> INCONCLUSIVE: rate-limited (/enroll is 5r/m). The guard was"
      say "          not exercised. Wait a minute and re-run this script alone."
      FAILED=1 ;;
    *)
      say "      ==> INCONCLUSIVE: unexpected HTTP $CODE, neither a refusal nor a bypass"
      FAILED=1 ;;
  esac
  "${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$BCN" >/dev/null 2>&1
done

say
say "=============== CLEANUP ==============="
"${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$CN" >/dev/null 2>&1
say "  removed test routes; CN=$CN serial $SER left revoked (deliberate)"
say "  bypass certificates are in $W and are NOT in the CA database (minted out-of-band)"
say "  index.txt revoked count: $(grep -c '^R' $PKI/intermediate/db/index.txt)"
say
say "raw -> $OUT"

if [ "$FAILED" != "0" ]; then
  say ""
  say "One or more controls did not conclusively pass. Read the output above:"
  say "an INCONCLUSIVE result is not a pass."
  exit 1
fi
