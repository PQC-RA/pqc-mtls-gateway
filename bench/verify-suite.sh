#!/usr/bin/env bash
# verify-suite.sh: the non-timing tests from the original campaign, with
# evidence captured verbatim to evidence/ for citation.
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

echo "=============== 1. CERTIFICATE SIZES (DER bytes) ==============="
der() { $OSSL x509 -in "$1" -outform DER 2>/dev/null | wc -c; }
{
printf '%-28s %8s\n' "role" "DER B"
printf '%-28s %8s\n' "Root CA"          "$(der $PKI/root/certs/root-ca.crt)"
printf '%-28s %8s\n' "Intermediate CA"  "$(der $PKI/intermediate/certs/intermediate-ca.crt)"
printf '%-28s %8s\n' "Server (TLS leaf)" "$(der /etc/ssl/pqc/server-mldsa65.crt)"
printf '%-28s %8s\n' "Client (leaf)"    "$(der $E/client.crt)"
printf '%-28s %8s\n' "enroll-classical leaf" "$(der /etc/ssl/pqc/enroll-classical.crt)"
printf '%-28s %8s\n' "internal-tls leaf"     "$(der /etc/ssl/pqc/internal-tls.crt)"
} | tee $EV/cert-sizes.txt
echo "  ML-DSA-65 pubkey/sig reference: 1952 B / 3309 B (FIPS 204)"

echo
echo "=============== 2. OCSP STAPLING ==============="
echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA \
  -cert $E/client.crt -key $E/client.key -status 2>/dev/null > $EV/ocsp-staple.txt
grep -E "OCSP Response Status|Cert Status|Responder Id|Signature Algorithm|number of responses" $EV/ocsp-staple.txt | head -6 | sed 's/^/  /'
NOSTAPLE=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA -cert $E/client.crt -key $E/client.key 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}')
WITHSTAPLE=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:443 -CAfile $CA -cert $E/client.crt -key $E/client.key -status 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}')
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
[ "$IDXB" = "$IDXA" ] && echo "  ==> CA DATABASE UNCHANGED (fail-closed before any write)" || echo "  ==> *** CA DB MUTATED, issuance guard leaked ***"

echo
echo "=============== 4. FUNCTIONAL VALIDATION ==============="
for path in /admin/health /api/v1/status /telemetry/x /; do
  code=$(timeout 25 curl -s -o /dev/null -w "%{http_code}" --cacert $E/ca-chain.crt \
         --cert $E/client.crt --key $E/client.key "https://127.0.0.1$path" 2>/dev/null)
  printf "  %-18s -> HTTP %s\n" "$path" "$code"
done
echo "  -- no client certificate (mTLS enforcement):"
timeout 25 curl -s -o /dev/null -w "     no-cert -> HTTP %{http_code}\n" --cacert $E/ca-chain.crt https://127.0.0.1/api/v1/status 2>/dev/null

echo
echo "=============== 5. CRL / REVOCATION STATE ==============="
echo "  revoked in CA index : $(grep -c '^R' $PKI/intermediate/db/index.txt)"
echo "  serials in live CRL : $($OSSL crl -in $PKI/hybrid-combined-crl.pem -noout -text 2>/dev/null | grep -c 'Serial Number:')"
$OSSL crl -in $PKI/hybrid-combined-crl.pem -noout -text 2>/dev/null | grep -E "Signature Algorithm|Last Update|Next Update" | head -3 | sed 's/^/  /'
docker exec pqc-gateway sh -c "grep -ihE 'revoked serial' /var/log/nginx/error.log 2>/dev/null | tail -1" 2>/dev/null | sed 's/^/  data plane: /'
echo
echo "evidence -> $(pwd)/$EV/"
