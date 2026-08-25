#!/usr/bin/env bash
# verify-suite.sh: the non-timing tests from the original campaign, with
# evidence captured verbatim to evidence/ for citation.
#
# CI runs this suite, so a failing guard has to turn the build red. Without the
# RC accumulator below the script printed "*** ... ***" and still exited 0,
# which meant the bring-up step that runs it could never fail.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
OSSL=/opt/openssl/bin/openssl
cd "$(dirname "$0")"
E="$EXPORT_DIR"
PKI=/etc/pki/pqc-ca
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
EV=evidence; mkdir -p $EV
CA=$PKI/ca-chain.crt; C=$REPO/admin-cert/gateway-admin.crt; K=$REPO/admin-cert/gateway-admin.key

RC=0
fail(){ echo "  ==> *** $* ***"; RC=1; }

# A CI runner has no /root/measure-export: nothing under scripts/ or .github/
# creates it. Sections 1, 2 and 4 read a client identity from there, so on a
# runner they silently degraded to blank output and measured nothing. The admin
# certificate is ML-DSA-65, issued by the same intermediate, and deploy.sh has
# already written it by the time this runs, so it is the correct fallback.
if [ -r "$E/client.crt" ] && [ -r "$E/client.key" ]; then
  CLI_CRT=$E/client.crt; CLI_KEY=$E/client.key; CLI_SRC="measure-export"
elif [ -r "$C" ] && [ -r "$K" ]; then
  CLI_CRT=$C; CLI_KEY=$K; CLI_SRC="admin-cert"
else
  CLI_CRT=""; CLI_KEY=""; CLI_SRC="none"
fi
if [ -r "$E/ca-chain.crt" ]; then CLI_CA=$E/ca-chain.crt; else CLI_CA=$CA; fi
echo "client identity for sections 1/2/4: $CLI_SRC"
[ -n "$CLI_CRT" ] || fail "no usable client identity, sections 1/2/4 cannot measure anything"

echo
echo "=============== 1. CERTIFICATE SIZES (DER bytes) ==============="
der() { $OSSL x509 -in "$1" -outform DER 2>/dev/null | wc -c; }
{
printf '%-28s %8s\n' "role" "DER B"
printf '%-28s %8s\n' "Root CA"          "$(der $PKI/root/certs/root-ca.crt)"
printf '%-28s %8s\n' "Intermediate CA"  "$(der $PKI/intermediate/certs/intermediate-ca.crt)"
printf '%-28s %8s\n' "Server (TLS leaf)" "$(der /etc/ssl/pqc/server-mldsa65.crt)"
printf '%-28s %8s\n' "Client (leaf)"    "$(der ${CLI_CRT:-/nonexistent})"
printf '%-28s %8s\n' "enroll-classical leaf" "$(der /etc/ssl/pqc/enroll-classical.crt)"
printf '%-28s %8s\n' "internal-tls leaf"     "$(der /etc/ssl/pqc/internal-tls.crt)"
} | tee $EV/cert-sizes.txt
echo "  ML-DSA-65 pubkey/sig reference: 1952 B / 3309 B (FIPS 204)"

echo
echo "=============== 2. OCSP STAPLING ==============="
echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA \
  -cert $CLI_CRT -key $CLI_KEY -status 2>/dev/null > $EV/ocsp-staple.txt
grep -E "OCSP Response Status|Cert Status|Responder Id|Signature Algorithm|number of responses" $EV/ocsp-staple.txt | head -6 | sed 's/^/  /'
NOSTAPLE=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA -cert $CLI_CRT -key $CLI_KEY 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}')
WITHSTAPLE=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA -cert $CLI_CRT -key $CLI_KEY -status 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}')
# No -servername here, so these are the IP-literal figures. Sending SNI moves
# the server flight by exactly four bytes, which is enough to make two
# otherwise identical runs disagree, so the arm is stated rather than left to
# be inferred: the published 11,071 / 20,540 B were measured with SNI.
echo "  (measured without SNI; sending it adds 4 B to each figure below)"
echo "  server flight without staple: ${NOSTAPLE} B"
echo "  server flight with staple   : ${WITHSTAPLE} B"
[ -n "$NOSTAPLE" ] && [ -n "$WITHSTAPLE" ] && echo "  staple adds                 : $((WITHSTAPLE-NOSTAPLE)) B"

echo
echo "=============== 3. PQC-ONLY CLIENT AUTH ==============="
echo "  -- handshake guard: which sigalgs does the server request?"
echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA 2>/dev/null \
  | grep -E "Requested Signature Algorithms" | tee $EV/sigalgs.txt | sed 's/^/     /'
echo "  -- issuance guard: RSA / EC / ML-DSA-44 CSRs must be refused"
IDXB=$($OSSL dgst -sha256 $PKI/intermediate/db/index.txt | awk '{print $2}')
TD=$(mktemp -d)
for alg in rsa ec mldsa44; do
  case $alg in
    rsa)     $OSSL genrsa -out $TD/k.pem 2048 2>/dev/null ;;
    ec)      $OSSL ecparam -name prime256v1 -genkey -noout -out $TD/k.pem 2>/dev/null ;;
    mldsa44) $OSSL genpkey -algorithm ML-DSA-44 -out $TD/k.pem 2>/dev/null ;;
  esac
  $OSSL req -new -key $TD/k.pem -out $TD/c.csr -subj "/C=BG/O=ACME/OU=M2M-Client/CN=badalg-$alg" 2>/dev/null
  TOK=$(timeout 25 curl -sk --cacert $CA --cert $C --key $K -H "X-PQC-CSRF:1" \
        -X POST "https://127.0.0.1/admin/certs/enrollment-tokens?cn=badalg-$alg&ttl=120" 2>/dev/null \
        | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])" 2>/dev/null)
  P=$(CSR=$TD/c.csr T="$TOK" python3 -c "import json,os;print(json.dumps({'csr':open(os.environ['CSR']).read(),'enrollmentToken':os.environ['T']}))")
  R=$(timeout 30 curl -sS --cacert $PKI/enroll-classical-ca.crt -X POST https://127.0.0.1:8443/enroll \
      -H "Content-Type: application/json" -d "$P" -w "\n%{http_code}" 2>/dev/null)
  echo "     $alg -> HTTP $(echo "$R"|tail -1)  $(echo "$R"|sed '$d'|head -c 110)"
done
rm -rf $TD
IDXA=$($OSSL dgst -sha256 $PKI/intermediate/db/index.txt | awk '{print $2}')
echo "  CA index SHA-256 before: ${IDXB:0:24}"
echo "  CA index SHA-256 after : ${IDXA:0:24}"
[ "$IDXB" = "$IDXA" ] && echo "  ==> CA DATABASE UNCHANGED (fail-closed before any write)" \
  || fail "CA DB MUTATED, issuance guard leaked"

# G10, the strongest form of the PQC-only client-auth test. The issuance guard
# above proves the CA refuses to MINT a classical-keyed certificate; it does NOT
# prove the gateway refuses one that already exists. Chain validation alone
# ADMITS such a certificate, because it checks that the leaf is signed by a
# trusted CA and never constrains the leaf's own subject key, so only the
# explicit ssl_conf_command ClientSignatureAlgorithms restriction can reject it.
# An ssl_conf_command OpenSSL does not recognise is accepted at parse time and
# never applied, and an omitted one passes `nginx -t` in silence, so this is the
# only check that proves the restriction is live. That is why it belongs in CI
# rather than in a benchmark script run by hand.
echo "  -- handshake guard: classical cert SIGNED BY THE LEGITIMATE intermediate must be refused"
INT_CRT=$PKI/intermediate/certs/intermediate-ca.crt
INT_KEY=$PKI/intermediate/private/intermediate-ca.key
if [ ! -r "$INT_KEY" ]; then
  fail "cannot read the intermediate key, G10 could not run"
else
  G=$(mktemp -d)
  for alg in rsa ec; do
    BCN="g10-$alg-$$"
    case $alg in
      rsa) $OSSL genrsa -out $G/$alg.key 2048 2>/dev/null ;;
      ec)  $OSSL ecparam -name prime256v1 -genkey -noout -out $G/$alg.key 2>/dev/null ;;
    esac
    $OSSL req -new -key $G/$alg.key -out $G/$alg.csr -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$BCN" 2>/dev/null
    # Minted out-of-band with the intermediate key: deliberately the artifact
    # issuance refuses to produce. Never enters the CA database.
    $OSSL x509 -req -in $G/$alg.csr -CA "$INT_CRT" -CAkey "$INT_KEY" -set_serial "0x7f$RANDOM" \
      -out $G/$alg.crt -days 1 2>/dev/null
    if [ ! -s $G/$alg.crt ]; then fail "$alg: could not mint the test certificate"; continue; fi
    $OSSL verify -CAfile "$CA" $G/$alg.crt >/dev/null 2>&1 \
      && echo "     $alg: chain validation ADMITS it, only the sigalg guard can reject it" \
      || echo "     $alg: chain validation rejected it (unexpected; G10 is then not testing what it should)"
    # Route it, so any refusal is attributable to TLS and not to policy.
    timeout 25 curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1" \
      -X PUT "https://127.0.0.1/admin/policy/routes/$BCN" -H "Content-Type: application/json" \
      -d '{"backend":"http://shadow-mock:80","allowed_paths":["/api/"],"rate_limit":{"rps":1000,"burst":2000}}' \
      >/dev/null 2>&1
    sleep 1
    CODE=$(timeout 25 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" \
           --cert $G/$alg.crt --key $G/$alg.key https://127.0.0.1/api/v1/status 2>/dev/null)
    echo "     $alg: mTLS with the classical leaf -> HTTP ${CODE:-000}"
    [ "$CODE" = "200" ] \
      && fail "$alg BYPASS SUCCEEDED, PQC-ONLY CLIENT AUTH IS NOT ENFORCED" \
      || echo "     ==> PASS: refused"
    timeout 25 curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1" \
      -X DELETE "https://127.0.0.1/admin/policy/routes/$BCN" >/dev/null 2>&1
  done
  rm -rf $G
fi

echo
echo "=============== 4. FUNCTIONAL VALIDATION ==============="
for path in /admin/health /api/v1/status /telemetry/x /; do
  code=$(timeout 25 curl -s -o /dev/null -w "%{http_code}" --cacert $CLI_CA \
         --cert $CLI_CRT --key $CLI_KEY "https://127.0.0.1$path" 2>/dev/null)
  printf "  %-18s -> HTTP %s\n" "$path" "$code"
done
# mTLS enforcement is a security invariant independent of any route policy: a
# connection with no client certificate must never reach a backend. This is the
# one assertion in this section that cannot produce a false red from a missing
# route, so it is the one that carries a fail().
echo "  -- no client certificate (mTLS enforcement):"
NOCERT=$(timeout 25 curl -s -o /dev/null -w "%{http_code}" --cacert $CLI_CA \
         https://127.0.0.1/api/v1/status 2>/dev/null)
echo "     no-cert -> HTTP ${NOCERT:-000}"
[ "$NOCERT" = "200" ] && fail "mTLS NOT ENFORCED, a certificateless request reached the backend" \
  || echo "     ==> PASS: refused"

echo
echo "=============== 5. CRL / REVOCATION STATE ==============="
echo "  revoked in CA index : $(grep -c '^R' $PKI/intermediate/db/index.txt)"
echo "  serials in live CRL : $($OSSL crl -in $PKI/hybrid-combined-crl.pem -noout -text 2>/dev/null | grep -c 'Serial Number:')"
$OSSL crl -in $PKI/hybrid-combined-crl.pem -noout -text 2>/dev/null | grep -E "Signature Algorithm|Last Update|Next Update" | head -3 | sed 's/^/  /'
docker exec pqc-gateway sh -c "grep -ihE 'revoked serial' /var/log/nginx/error.log 2>/dev/null | tail -1" 2>/dev/null | sed 's/^/  data plane: /'
echo
echo "evidence -> $(pwd)/$EV/"
[ "$RC" -eq 0 ] && echo "ALL GUARDS PASSED" || echo "*** ONE OR MORE GUARDS FAILED ***"
exit "$RC"
