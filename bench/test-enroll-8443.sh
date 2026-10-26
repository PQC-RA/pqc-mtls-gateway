#!/usr/bin/env bash
# test-enroll-8443.sh: acceptance tests for the post-quantum-only :8443
# enrollment endpoint. Asserts; prints PASS/FAIL per check; exit = failures.
#
#   1  PQ clients enroll a test CN: the host curl (needs OpenSSL 3.5+), curl in
#      the curlimages/curl container (OpenSSL 3.5+), and scripts/issue-cert.sh
#   2  classical-only clients are refused at the handshake: curl on a pre-3.5
#      libssl (no ML-KEM), classical groups only, PQ group but classical
#      sigalgs only (what a current browser offers)
#   3  a client still trusting the old enroll-classical-ca fails verification,
#      and issue-cert.sh prints the post-quantum-only hint
#   4  the token is consumed only by a successful enrollment; every failure
#      above, a CN mismatch and a non-ML-DSA CSR leave it unused
#   5  CN mismatch -> 403, token unused, then the right CN succeeds with it
#   6  replay of a used token: the same request is refused (403) or, by a
#      management-api that supports replay, answered with the SAME certificate;
#      a new key -> 403; no new issuance either way
#   7  (SIGN_FAILURE_TEST=1) token state when the CA custodian is down
#   L  telemetry: access-log line with kex/server_sig for every request, and a
#      named refusal reason in the handshake log for every refused handshake
#
# It writes to a running gateway: it creates enrollment tokens and issues five
# certificates (CN_PREFIX...), which stay valid until you revoke them, and with
# SIGN_FAILURE_TEST=1 it stops and restarts the CA custodian. So it refuses to
# run unless ENROLL8443_I_UNDERSTAND=1. It reads the gateway's log volume and
# the CA index on this host, so HOST must be a loopback address.
#
# Env (defaults = the deployment on this host, docker-compose.yml as shipped):
#   ENROLL_PORT (8443)  ADMIN_PORT (443)  HOST (127.0.0.1)  SNI (pqc-gw.local)
#   CA        PQ chain that verifies the gateway   (/etc/pki/pqc-ca/ca-chain.crt)
#   OLD_CA    classical enrollment CA              (/etc/pki/pqc-ca/enroll-classical-ca.crt)
#   PKI       CA tree, for index.txt               (/etc/pki/pqc-ca)
#   ADMIN_CRT/ADMIN_KEY  admin identity for token creation (admin-cert/gateway-admin.*)
#   LOG_DIR   gateway /var/log/nginx on the host   (pqc-gw_pqc-logs-nginx volume)
#   CLASSIC_LIBDIR  directory holding a pre-3.5 libssl/libcrypto (/usr/lib/x86_64-linux-gnu)
#   CN_PREFIX (enroll-test-)  CUSTODIAN (pqc-ca-custodian)  SIGN_FAILURE_TEST (0)
set -uo pipefail
if [ "${ENROLL8443_I_UNDERSTAND:-0}" != 1 ]; then
  echo "refusing to run: this creates enrollment tokens and issues certificates on a"
  echo "running gateway. Set ENROLL8443_I_UNDERSTAND=1."
  exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
HOST=${HOST:-127.0.0.1}; SNI=${SNI:-pqc-gw.local}
case "$HOST" in 127.*|::1|localhost) ;; *) echo "refusing non-loopback HOST=$HOST: this test reads the gateway's logs and CA index on this host"; exit 2 ;; esac
ENROLL_PORT=${ENROLL_PORT:-8443}; ADMIN_PORT=${ADMIN_PORT:-443}
CA=${CA:-/etc/pki/pqc-ca/ca-chain.crt}; OLD_CA=${OLD_CA:-/etc/pki/pqc-ca/enroll-classical-ca.crt}
PKI=${PKI:-/etc/pki/pqc-ca}
ADMIN_CRT=${ADMIN_CRT:-$ROOT/admin-cert/gateway-admin.crt}; ADMIN_KEY=${ADMIN_KEY:-$ROOT/admin-cert/gateway-admin.key}
LOG_DIR=${LOG_DIR:-/var/lib/docker/volumes/pqc-gw_pqc-logs-nginx/_data}
CLASSIC_LIBDIR=${CLASSIC_LIBDIR:-/usr/lib/x86_64-linux-gnu}
CN_PREFIX=${CN_PREFIX:-enroll-test-}; CUSTODIAN=${CUSTODIAN:-pqc-ca-custodian}
OSSL=${OSSL:-/opt/openssl/bin/openssl}; export OPENSSL_CONF=/etc/ssl/openssl.cnf
ACC=$LOG_DIR/pqc-enroll-access.log; HS=$LOG_DIR/pqc-enroll-handshake.log
for f in "$ACC" "$HS"; do touch -a "$f" 2>/dev/null; [ -r "$f" ] || { echo "FATAL: cannot read $f"; exit 2; }; done

RUN_ID=${RUN_ID:-$(date +%s | tail -c 6)}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAILS=0; N=0
URL="https://$SNI:$ENROLL_PORT/enroll"; RES=(--resolve "$SNI:$ENROLL_PORT:$HOST" --resolve "$SNI:$ADMIN_PORT:$HOST")
ok(){ N=$((N+1)); echo "PASS  $*"; }
bad(){ N=$((N+1)); FAILS=$((FAILS+1)); echo "FAIL  $*"; }
expect(){ local label=$1 want=$2 got=$3; [ "$got" = "$want" ] && ok "$label ($got)" || bad "$label (want $want, got $got)"; }
tid(){ echo "${1:0:13}..."; }   # never print a whole token

admin(){ curl -sS --max-time 15 --cacert "$CA" --cert "$ADMIN_CRT" --key "$ADMIN_KEY" -H X-PQC-CSRF:1 "${RES[@]}" "$@"; }
new_token(){ admin -X POST "https://$SNI:$ADMIN_PORT/admin/certs/enrollment-tokens?cn=$1&ttl=600" \
  | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
token_state(){ admin "https://$SNI:$ADMIN_PORT/admin/certs/enrollment-tokens" | T="$1" python3 -I -c '
import json,os,sys
for e in json.load(sys.stdin):
    if e["token"]==os.environ["T"]: print("used" if e["used"] else "unused"); break
else: print("absent")'; }
csr(){ # csr <cn> [alg]   -> $W/<cn>.csr (+ .key)
  local cn=$1 alg=${2:-ML-DSA-65}
  case $alg in RSA) $OSSL genrsa -out "$W/$cn.key" 2048 2>/dev/null ;;
               *)   $OSSL genpkey -algorithm "$alg" -out "$W/$cn.key" 2>/dev/null ;; esac
  $OSSL req -new -key "$W/$cn.key" -out "$W/$cn.csr" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$cn" 2>/dev/null; }
payload(){ CSR="$W/$1.csr" T="$2" python3 -I -c 'import json,os; print(json.dumps({"csr":open(os.environ["CSR"]).read(),"enrollmentToken":os.environ["T"]}))' > "$W/$1.json"; }
# The endpoint allows 5 req/min per IP (limit_req pqc_enroll, burst 3). Every
# request that reaches HTTP is paced 12.5 s apart so the tests measure the
# backend, not the rate limiter. Refused handshakes never reach limit_req.
pace(){ local now last; now=$(date +%s%N); last=$(cat "$W/last" 2>/dev/null || echo 0)
  local wait_ms=$(( 12500 - (now - last) / 1000000 )); [ $wait_ms -gt 0 ] && sleep "$(awk "BEGIN{print $wait_ms/1000}")"
  date +%s%N > "$W/last"; }
# enroll <json> [extra curl args] -> prints "<curl rc> <http code>", body in $W/body
enroll(){ local j=$1; shift; local code rc; pace
  code=$(curl -sS -o "$W/body" -w '%{http_code}' --max-time 15 --cacert "$CA" "${RES[@]}" "$@" \
         -H 'Content-Type: application/json' --data-binary @"$j" "$URL" 2>"$W/err"); rc=$?; echo "$rc $code"; }
idx(){ wc -l < "$PKI/intermediate/db/index.txt"; }
mark(){ A0=$(wc -l < "$ACC"); H0=$(wc -l < "$HS"); }
newacc(){ sleep 0.6; tail -n +$((A0+1)) "$ACC"; }
newhs(){ sleep 0.6; tail -n +$((H0+1)) "$HS"; }
reason(){ newhs | grep -o 'PQC-TLS refusing handshake: reason=[a-z0-9_]*' | head -1 | sed 's/.*reason=//'; }

echo "== versions =="
echo "   host curl      : $(curl -V | head -1 | grep -oE 'curl [0-9.]+|OpenSSL/[0-9.]+' | tr '\n' ' ')"
echo "   classical curl : $(LD_LIBRARY_PATH=$CLASSIC_LIBDIR curl -V | head -1 | grep -oE 'curl [0-9.]+|OpenSSL/[0-9.]+' | tr '\n' ' ')"
echo "   container curl : $(docker run --rm --network none curlimages/curl:latest -V | head -1 | grep -oE 'curl [0-9.]+|OpenSSL/[0-9.]+' | tr '\n' ' ')"
echo "   s_client       : $($OSSL version)"
IDX0=$(idx); echo "   CA index lines at start: $IDX0"

echo; echo "== 1. post-quantum clients enroll =="
CN1=${CN_PREFIX}pq-${RUN_ID}; T1=$(new_token "$CN1"); csr "$CN1"; payload "$CN1" "$T1"
expect "token $(tid "$T1") for $CN1 before enrolling" unused "$(token_state "$T1")"
mark; read -r rc code <<<"$(enroll "$W/$CN1.json")"
expect "1a host curl enrolls $CN1" "0 201" "$rc $code"
python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$W/body" "$W/$CN1.crt" 2>/dev/null
expect "1a issued cert verifies against the PQ chain" OK "$($OSSL verify -CAfile "$CA" "$W/$CN1.crt" 2>&1 | grep -o 'OK$')"
expect "1a issued cert key type" ML-DSA-65 "$($OSSL x509 -in "$W/$CN1.crt" -noout -text | grep -m1 'Public Key Algorithm' | sed 's/.*: //')"
expect "1a token consumed by the success" used "$(token_state "$T1")"
L=$(newacc | grep '"uri":"/enroll"' | tail -1)
echo "$L" | grep -q '"kex":"X25519MLKEM768".*"server_sig":"id-ml-dsa-65"' && ok "1a access log: kex X25519MLKEM768, server_sig id-ml-dsa-65" || bad "1a access log line: $L"
cp "$W/$CN1.json" "$W/replay.json"; cp "$W/$CN1.crt" "$W/keep-$CN1.crt"

CN1B=${CN_PREFIX}pq35-${RUN_ID}; T1B=$(new_token "$CN1B"); csr "$CN1B"; payload "$CN1B" "$T1B"
pace; code=$(docker run --rm --network host --user 0:0 -v "$W:/w:ro" -v "$CA:/ca.crt:ro" curlimages/curl:latest \
  -sS -o /dev/null -w '%{http_code}' --max-time 15 --cacert /ca.crt --resolve "$SNI:$ENROLL_PORT:$HOST" \
  -H 'Content-Type: application/json' --data-binary @"/w/$CN1B.json" "$URL" 2>&1)
expect "1b curlimages/curl (container) enrolls $CN1B" 201 "$code"
expect "1b token consumed" used "$(token_state "$T1B")"

CN1C=${CN_PREFIX}script-${RUN_ID}; pace
out=$(cd "$W" && PQC_GATEWAY="https://$HOST:$ADMIN_PORT" PQC_ENROLL_URL="https://$HOST:$ENROLL_PORT/enroll" \
  PQC_CA_CHAIN="$CA" PQC_ENROLL_CA="$CA" PQC_ADMIN_CERT="$ADMIN_CRT" PQC_ADMIN_KEY="$ADMIN_KEY" PQC_OUT_DIR="$W/$CN1C" \
  "$ROOT/scripts/issue-cert.sh" "$CN1C" 2>&1); rc=$?
expect "1c issue-cert.sh enrolls $CN1C" 0 "$rc"
[ $rc = 0 ] || echo "$out" | tail -5 | sed 's/^/      /'

echo; echo "== 2. classical-only clients are refused (token must stay unused) =="
CN2=${CN_PREFIX}classic-${RUN_ID}; T2=$(new_token "$CN2"); csr "$CN2"; payload "$CN2" "$T2"
mark; code=$(LD_LIBRARY_PATH=$CLASSIC_LIBDIR curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --cacert "$CA" "${RES[@]}" \
  -H 'Content-Type: application/json' --data-binary @"$W/$CN2.json" "$URL" 2>"$W/err"); rc=$?
expect "2a curl on the pre-3.5 libssl in $CLASSIC_LIBDIR: handshake refused (curl rc 35)" "35 000" "$rc $code"
expect "2a refusal reason logged" no_pq_group "$(reason)"
echo "      client: $(cut -c1-150 "$W/err")"
mark; read -r rc code <<<"$(enroll "$W/$CN2.json" --curves X25519:P-256)"
expect "2b host curl restricted to X25519:P-256: handshake refused" "35 000" "$rc $code"
expect "2b refusal reason logged" no_pq_group "$(reason)"
mark; r=$(echo | timeout 10 $OSSL s_client -connect "$HOST:$ENROLL_PORT" -servername "$SNI" -CAfile "$CA" \
  -groups X25519MLKEM768 -sigalgs 'ECDSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA256:rsa_pss_rsae_sha256:ed25519' 2>&1)
echo "$r" | grep -q 'Cipher is (NONE)\|alert handshake failure\|no shared' && ok "2c hybrid group but classical sigalgs only (browser-like): handshake refused" || bad "2c handshake was not refused"
expect "2c refusal reason logged" no_pq_sigalg "$(reason)"
echo "      nginx: $(newhs | grep -oE 'SSL_do_handshake\(\) failed \(SSL: error:[^)]*\)' | head -1 | cut -c1-140)"
expect "2  no access-log line for any refused handshake" 0 "$(newacc | wc -l)"
expect "2  token $(tid "$T2") still unused after refused handshakes" unused "$(token_state "$T2")"

echo; echo "== 3. a client expecting the old ECDSA certificate fails =="
mark; read -r rc code <<<"$(enroll "$W/$CN2.json" --cacert "$OLD_CA")"
expect "3a PQ-capable curl trusting only enroll-classical-ca: verify fails (curl rc 60)" "60 000" "$rc $code"
echo "      client: $(cut -c1-140 "$W/err")"
expect "3a no request reached the endpoint" 0 "$(newacc | wc -l)"
out=$(cd "$W" && ENROLLMENT_TOKEN="$T2" PQC_GATEWAY="https://$HOST:$ADMIN_PORT" PQC_ENROLL_URL="https://$HOST:$ENROLL_PORT/enroll" \
  PQC_CA_CHAIN="$CA" PQC_ENROLL_CA="$OLD_CA" PQC_OUT_DIR="$W/old-$CN2" "$ROOT/scripts/issue-cert.sh" "$CN2" 2>&1); rc=$?
[ $rc != 0 ] && echo "$out" | grep -q 'post-quantum-only' && ok "3b issue-cert.sh with PQC_ENROLL_CA=enroll-classical-ca fails and prints the hint" || bad "3b issue-cert.sh rc=$rc, hint missing"
echo "$out" | sed -n '/ERROR: curl failed during enrollment/,$p' | sed 's/^/      | /'
expect "3  token still unused" unused "$(token_state "$T2")"

echo; echo "== 5. CN mismatch -> 403, token not consumed =="
CN5=${CN_PREFIX}cn-${RUN_ID}; T5=$(new_token "$CN5"); csr "${CN5}-other"; payload "${CN5}-other" "$T5"
I0=$(idx); mark; read -r rc code <<<"$(enroll "$W/${CN5}-other.json")"
expect "5a CSR CN=${CN5}-other with a token for $CN5" "0 403" "$rc $code"
echo "      body: $(head -c 160 "$W/body")"
expect "5a token unused after the mismatch" unused "$(token_state "$T5")"
expect "5a no certificate issued" "$I0" "$(idx)"
newacc | grep -q '"status":403.*"kex":"X25519MLKEM768"' && ok "5a 403 logged with TLS fields" || bad "5a 403 not in access log"
csr "$CN5"; payload "$CN5" "$T5"; read -r rc code <<<"$(enroll "$W/$CN5.json")"
expect "5b same token, right CN, enrolls" "0 201" "$rc $code"
expect "5b token now used" used "$(token_state "$T5")"

echo; echo "== 4. token consumed only on success: other failure modes =="
CN4=${CN_PREFIX}tok-${RUN_ID}; T4=$(new_token "$CN4")
csr "$CN4" RSA; payload "$CN4" "$T4"; I0=$(idx)
read -r rc code <<<"$(enroll "$W/$CN4.json")"
expect "4a RSA-2048 CSR refused" "0 400" "$rc $code"
echo "      body: $(head -c 140 "$W/body")"
printf '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\nnot a csr\\n-----END CERTIFICATE REQUEST-----\\n","enrollmentToken":"%s"}' "$T4" > "$W/bad.json"
read -r rc code <<<"$(enroll "$W/bad.json")"
expect "4b malformed CSR refused" "0 400" "$rc $code"
expect "4  token unused after 2a-2c, 3, 4a, 4b" unused "$(token_state "$T4")"
expect "4  no certificate issued by the failures" "$I0" "$(idx)"
csr "$CN4"; payload "$CN4" "$T4"; read -r rc code <<<"$(enroll "$W/$CN4.json")"
expect "4c then a valid ML-DSA-65 CSR enrolls" "0 201" "$rc $code"
expect "4c token used only now" used "$(token_state "$T4")"

echo; echo "== 6. token replay: never a second certificate =="
I0=$(idx); read -r rc code <<<"$(enroll "$W/replay.json")"
# A byte-identical replay of the 1a request. A management-api that supports
# replay answers it with the certificate already issued under the token (201,
# same serial, nothing new issued; a captured request yields only that public
# certificate); one that does not refuses it (403). Either is safe. What must
# never happen is a new certificate.
if [ "$rc $code" = "0 403" ]; then
  ok "6a byte-identical replay of the 1a request refused (403)"
elif [ "$rc $code" = "0 201" ]; then
  python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1])).get("certificate",""))' "$W/body" "$W/6a.crt" 2>/dev/null
  expect "6a byte-identical replay answered with the 1a certificate (same serial)" "$($OSSL x509 -in "$W/keep-$CN1.crt" -noout -serial 2>/dev/null)" "$($OSSL x509 -in "$W/6a.crt" -noout -serial 2>/dev/null)"
else
  bad "6a byte-identical replay of the 1a request (want 403, or 201 with the same certificate; got $rc $code)"
fi
echo "      body: $(head -c 120 "$W/body")"
CN6=$CN1; csr "${CN6}"; payload "${CN6}" "$T1"; read -r rc code <<<"$(enroll "$W/${CN6}.json")"
expect "6b used token with a fresh key and CSR" "0 403" "$rc $code"
expect "6  no certificate issued by the replays" "$I0" "$(idx)"

if [ "${SIGN_FAILURE_TEST:-0}" = 1 ]; then
  echo; echo "== 7. signing fails after the token checks (CA custodian stopped) =="
  CN7=${CN_PREFIX}custodian-${RUN_ID}; T7=$(new_token "$CN7"); csr "$CN7"; payload "$CN7" "$T7"
  docker stop "$CUSTODIAN" >/dev/null
  read -r rc code <<<"$(enroll "$W/$CN7.json")"
  docker start "$CUSTODIAN" >/dev/null
  echo "      enroll with custodian down: curl rc $rc, HTTP $code, body: $(head -c 140 "$W/body")"
  s=$(token_state "$T7"); echo "      token state afterwards: $s"
  for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$CUSTODIAN")" = healthy ] && break; sleep 1; done
  read -r rc code <<<"$(enroll "$W/$CN7.json")"
  echo "      retry with custodian healthy: HTTP $code"
  if [ "$s" = unused ]; then ok "7 token survives a signing failure"
  else bad "7 token BURNED by a failed signing (consumed before the custodian signs, a management-api behaviour)"; fi
fi

echo; echo "== L. telemetry samples =="
echo "   last 5 lines of $(basename "$ACC"):"; tail -n 5 "$ACC" | sed 's/^/   /'
echo "   refusal lines from this run in $(basename "$HS"):"
grep 'PQC-TLS refusing' "$HS" | tail -n 3 | sed -E 's/^[0-9\/: ]+\[warn\] [0-9#]+: \*[0-9]+ /   /' | cut -c1-330
echo; echo "CA index lines: start $IDX0, end $(idx) (expected +5: 1a, 1b, 1c, 5b, 4c)"
echo "The certificates issued for ${CN_PREFIX}*-${RUN_ID} stay valid; revoke them if this is not a throwaway stack."
echo; [ "$FAILS" = 0 ] && echo "ENROLL :8443 TESTS OK ($N checks)" || echo "*** $FAILS of $N ENROLL :8443 CHECK(S) FAILED ***"
exit "$FAILS"
