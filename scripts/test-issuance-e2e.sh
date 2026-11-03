#!/usr/bin/env bash
# test-issuance-e2e.sh: end-to-end certificate-issuance regression test against
# a LIVE gateway. Run it post-deploy (server-side, where PQ OpenSSL + the admin
# cert live) or from an integration CI that has a running stack.
#
# WHY THIS EXISTS
#   Issuance spans the gateway, the enrollment listener and the CA custodian.
#   The :8443 enrollment listener has had its own trust anchor before (a
#   classical ECDSA certificate) and now shares the ML-DSA chain with the data
#   plane; each change of that kind breaks a client that still expects the
#   other. A unit test of any one part passes while the path between them is
#   broken. This drives the real flow end
#   to end and fails loudly if any step regresses.
#
# WHAT IT CHECKS
#   1. issue-cert.sh completes issuance for a fresh CN (this is the step the
#      enrollment-CA bug broke) and produces a certificate file.
#   2. A request through the gateway with that client cert returns the backend's
#      200 body (route + mTLS + JWT hand-off all work).
#   3. Revoking that certificate answers 200 or 202, and its serial reaches the
#      published combined CRL. Then the test route is removed.
#
# Overridable env (defaults suit a server-local run):
#   PQC_GATEWAY PQC_CA_CHAIN PQC_ENROLL_CA PQC_ADMIN_CERT PQC_ADMIN_KEY
#   PQC_OPENSSL SMOKE_BACKEND
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GW="${PQC_GATEWAY:-https://127.0.0.1}"
CA_CHAIN="${PQC_CA_CHAIN:-/var/lib/pqc-ca-public/ca-chain.crt}"
# :8443 is post-quantum-only since 2026-10 and is verified with the PQ chain.
ENROLL_CA="${PQC_ENROLL_CA:-$CA_CHAIN}"
ADMIN_CERT="${PQC_ADMIN_CERT:-$ROOT_DIR/admin-cert/gateway-admin.crt}"
ADMIN_KEY="${PQC_ADMIN_KEY:-$ROOT_DIR/admin-cert/gateway-admin.key}"
OSSL="${PQC_OPENSSL:-/opt/openssl/bin/openssl}"
BACKEND="${SMOKE_BACKEND:-http://shadow-mock:80}"
GW_HOST="$(echo "$GW" | sed 's|https://||; s|[:/].*||')"

CN="issuance-smoke-$$"
OUT_DIR="$ROOT_DIR/certs/$CN"

fail() { echo "FAIL: $*" >&2; exit 1; }
trap 'rm -rf "$OUT_DIR" 2>/dev/null || true' EXIT

# A PQ-capable openssl, an admin cert, and the two CAs are prerequisites.
{ [ -x "$OSSL" ] || command -v "$OSSL" >/dev/null 2>&1; } || fail "PQ OpenSSL not found at '$OSSL' (set PQC_OPENSSL)"
[ -f "$ADMIN_CERT" ] || fail "admin cert not found at '$ADMIN_CERT' (set PQC_ADMIN_CERT)"
[ -f "$CA_CHAIN" ]   || fail "CA chain not found at '$CA_CHAIN' (set PQC_CA_CHAIN)"

# Raw HTTPS via PQ openssl s_client (system curl can't do the PQC handshake).
# $1 method  $2 path  $3 cafile  $4 client_cert  $5 client_key  $6 body(optional) $7 extra_header(optional)
_https() {
    local method="$1" path="$2" cafile="$3" cert="$4" key="$5" body="${6:-}" xhdr="${7:-}"
    {
        printf '%s %s HTTP/1.1\r\n' "$method" "$path"
        printf 'Host: %s\r\n' "$GW_HOST"
        printf 'Connection: close\r\n'
        [ -n "$xhdr" ] && printf '%s\r\n' "$xhdr"
        if [ "$method" = "POST" ]; then
            printf 'Content-Type: application/json\r\n'
            printf 'Content-Length: %d\r\n' "${#body}"
        fi
        printf '\r\n'
        [ -n "$body" ] && printf '%s' "$body"
    } | OPENSSL_CONF=/etc/ssl/openssl.cnf "$OSSL" s_client -quiet -connect "$GW_HOST:443" \
        -CAfile "$cafile" -cert "$cert" -key "$key" -tls1_3 2>/dev/null || true
}

echo "== [1/3] Issue a fresh certificate end-to-end (CN=$CN) =="
PQC_GATEWAY="$GW" PQC_CA_CHAIN="$CA_CHAIN" PQC_ENROLL_CA="$ENROLL_CA" \
PQC_ADMIN_CERT="$ADMIN_CERT" PQC_ADMIN_KEY="$ADMIN_KEY" PQC_OPENSSL="$OSSL" \
    "$ROOT_DIR/scripts/issue-cert.sh" "$CN" "$BACKEND" \
    || fail "issue-cert.sh exited non-zero, enrollment/issuance regressed"

CRT="$OUT_DIR/$CN.crt"
KEY="$OUT_DIR/$CN.key"
[ -s "$CRT" ] || fail "no certificate at $CRT, the enrollment step did not complete"
echo "   OK: certificate issued ($CRT)"

echo "== [2/3] Request through the gateway with the issued cert (expect the backend 200) =="
RESP="$(_https GET /api/v1/status "$CA_CHAIN" "$CRT" "$KEY")"
echo "$RESP" | tail -1 | grep -q "pqc-shadow-success" \
    || fail "gateway did not return the expected backend body (last line: $(echo "$RESP" | tail -1))"
echo "   OK: gateway returned the backend 200"

echo "== [3/3] Revoke the test cert (200 or 202, and it reaches the published CRL), remove the test route =="
# A failed revoke is a failure, not a warning: a revoke that answered 500 was
# reported as "could not confirm" here and the run still passed (pre-merge
# review 9-1, an image from before ADR-024 PR 3).
SERIAL="$("$OSSL" x509 -in "$CRT" -noout -serial | cut -d= -f2 | tr 'a-f' 'A-F')"
[ -n "$SERIAL" ] || fail "cannot read the serial of $CRT"
REV="$(_https POST /admin/certs/revoke "$CA_CHAIN" "$ADMIN_CERT" "$ADMIN_KEY" \
    "{\"serial\":\"$SERIAL\",\"reason\":\"unspecified\"}" "X-PQC-CSRF: 1")"
REV_STATUS="$(printf '%s\n' "$REV" | sed -n '1s#^HTTP/1\.[01] \([0-9][0-9][0-9]\).*#\1#p')"
case "$REV_STATUS" in
    200|202) echo "   revoke answered $REV_STATUS for serial $SERIAL" ;;
    *) fail "revoke of serial $SERIAL answered '${REV_STATUS:-no status}', not 200 or 202 (body: $(printf '%s\n' "$REV" | tail -1))" ;;
esac
# 200: the custodian published a CRL carrying it before answering; 202: it
# keeps retrying, so allow it a while.
CRL_FILE="${PQC_PUBLIC_CRL:-/var/lib/pqc-ca-public/hybrid-combined-crl.pem}"
in_crl() { "$OSSL" crl -in "$CRL_FILE" -noout -text | grep -qE "Serial Number: *0*$SERIAL\$"; }
if [ "$REV_STATUS" = 200 ]; then
    in_crl || fail "revoke answered 200 but $CRL_FILE does not list serial $SERIAL"
else
    for _ in $(seq 1 30); do in_crl && break; sleep 1; done
    in_crl || fail "revoke answered 202 but serial $SERIAL is not in $CRL_FILE after 30 s"
fi
echo "   OK: serial $SERIAL is in the published CRL"
_https DELETE "/admin/policy/routes/$CN" "$CA_CHAIN" "$ADMIN_CERT" "$ADMIN_KEY" "" "X-PQC-CSRF: 1" >/dev/null

echo
echo "PASS, issuance works end-to-end (issue -> route -> mTLS request -> 200 -> revoke -> CRL)."
