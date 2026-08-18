#!/usr/bin/env bash
# =============================================================================
# verify-admin-sha256.sh: check the admin fingerprint allowlist end to end
# =============================================================================
# Proves, from a real certificate and with NO project dependencies (only
# openssl + node), that:
#
#   1. The fingerprint the gateway derives, SHA-256(DER), is identical to the
#      value an operator pastes from `openssl x509 -fingerprint -sha256`. If
#      those ever diverge, every admin request returns 403.
#   2. nginx's built-in $ssl_client_fingerprint is SHA-1, a different 40-char
#      value, which is why the allowlist must not be fed from it.
#   3. The guard's authorization core accepts a valid SHA-256 fingerprint and
#      STRICTLY REJECTS: a SHA-1 fingerprint, a wrong fingerprint, a missing
#      fingerprint (unauthenticated), and a SHA-1-only (misconfigured) allowlist
#      All fail closed.
#
# The full JWT signature/issuer/audience verification is covered by the Jest
# suite (src/common/guards/jwt-auth.guard.spec.ts); this script isolates the
# SHA-256 fingerprint authorization that the Lua gateway and the guard share.
#
# Usage:   ./scripts/verify-admin-sha256.sh
# Exit:    0 = all checks passed, 1 = any check failed
# =============================================================================
set -euo pipefail

# Organization name written into every certificate this deployment issues.
# The root CA policy requires the intermediate to MATCH it, so it must be the
# same value everywhere; that is why it is one variable rather than a literal
# in each subject line.
PKI_ORG="${PKI_ORG:-PQC-GW}"

# ── Locate an openssl (prefer the stack's PQ build; fall back to system) ──────
OSSL=""
for cand in "${OPENSSL_BIN:-}" /opt/openssl/bin/openssl "$(command -v openssl 2>/dev/null || true)"; do
    [ -n "$cand" ] && [ -x "$cand" ] && { OSSL="$cand"; break; }
done
[ -z "$OSSL" ] && { echo "FATAL: no openssl found"; exit 1; }

command -v node >/dev/null 2>&1 || { echo "FATAL: node is required"; exit 1; }

# Use ML-DSA-65 when available (the product's real client algorithm); otherwise
# fall back to RSA so the cryptographic-alignment proof still runs anywhere.
KEY_ALG="ML-DSA-65"
if ! OPENSSL_CONF=/dev/null "$OSSL" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa"; then
    KEY_ALG="RSA"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "Using openssl: $OSSL"
echo "Client key algorithm: $KEY_ALG"
echo ""

# ── 1. Generate a client certificate (the admin cert) ────────────────────────
if [ "$KEY_ALG" = "RSA" ]; then
    "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/c.key" -out "$WORK/c.crt" \
        -days 1 -subj "/C=BG/O=${PKI_ORG}/OU=admin/CN=ops-admin" >/dev/null 2>&1
else
    "$OSSL" genpkey -algorithm ML-DSA-65 -out "$WORK/c.key" >/dev/null 2>&1
    "$OSSL" req -x509 -key "$WORK/c.key" -out "$WORK/c.crt" \
        -days 1 -subj "/C=BG/O=${PKI_ORG}/OU=admin/CN=ops-admin" >/dev/null 2>&1
fi

# ── 2. Derive the fingerprints three ways ────────────────────────────────────
norm() { sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z' | tr -d '[:space:]'; }
# (a) What admin_jwt.lua / cert_fingerprint.lua compute: SHA-256 of the DER.
FPR_DER_SHA256="$("$OSSL" x509 -in "$WORK/c.crt" -outform DER | "$OSSL" dgst -sha256 | norm)"
# (b) What an operator pastes into ADMIN_CERT_FINGERPRINTS.
FPR_OPENSSL_SHA256="$("$OSSL" x509 -in "$WORK/c.crt" -noout -fingerprint -sha256 | norm)"
# (c) The legacy SHA-1 value nginx exposes as $ssl_client_fingerprint.
FPR_SHA1="$("$OSSL" x509 -in "$WORK/c.crt" -noout -fingerprint -sha1 | norm)"

PASS=0; FAIL=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; echo "          got='$2' want='$3'"; FAIL=$((FAIL+1)); fi; }

echo "── Cryptographic alignment ──────────────────────────────────────────────"
ck "SHA-256(DER) == openssl -fingerprint -sha256 (operator paste value)" "$FPR_DER_SHA256" "$FPR_OPENSSL_SHA256"
ck "SHA-256 fingerprint is 64 hex chars"                                 "${#FPR_DER_SHA256}" "64"
ck "SHA-1 fingerprint is 40 hex chars (the legacy lockout value)"        "${#FPR_SHA1}" "40"
if [ "$FPR_DER_SHA256" != "$FPR_SHA1" ]; then echo "  PASS  SHA-256 != SHA-1 (mismatch is the documented 403 cause)"; PASS=$((PASS+1)); else echo "  FAIL  SHA-256 == SHA-1 (impossible)"; FAIL=$((FAIL+1)); fi
echo ""

# ── 3. Replicate the guard's authorization core and run the decision matrix ──
echo "── Guard authorization matrix (mirrors jwt-auth.guard.ts) ───────────────"
node - "$FPR_DER_SHA256" "$FPR_SHA1" <<'NODE'
// Self-contained mirror of the guard's SHA-256 authorization core.
const [, , SHA256_GOOD, SHA1_BAD] = process.argv;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const normalize = (fp) => fp.replace(/[:\s]/g, "").toLowerCase();
function parseAllowlist(raw) {            // == parseAdminFingerprints()
  const valid = new Set();
  for (const e of (raw ?? "").split(/[,\s]+/).map(normalize).filter(Boolean)) {
    if (SHA256_HEX.test(e)) valid.add(e);   // reject non-SHA-256 (e.g. SHA-1)
  }
  return valid;
}
function authorize(allowlistRaw, tokenFpr) {  // == guard step 5 (fail-closed)
  const allow = parseAllowlist(allowlistRaw);
  const fpr = typeof tokenFpr === "string" ? normalize(tokenFpr) : "";
  return !!fpr && allow.has(fpr);
}

const cases = [
  ["valid SHA-256 fpr on SHA-256 allowlist",        SHA256_GOOD, SHA256_GOOD, true ],
  ["SHA-1 fpr rejected against SHA-256 allowlist",  SHA256_GOOD, SHA1_BAD,    false],
  ["wrong SHA-256 fpr rejected",                    SHA256_GOOD, "f".repeat(64), false],
  ["missing fpr (unauthenticated) rejected",        SHA256_GOOD, undefined,   false],
  ["SHA-1-only allowlist (misconfig) => deny all",  SHA1_BAD,    SHA1_BAD,    false],
  ["empty allowlist (unset) => deny all",           "",          SHA256_GOOD, false],
];

let pass = 0, fail = 0;
for (const [label, allowlist, fpr, want] of cases) {
  const got = authorize(allowlist, fpr);
  if (got === want) { console.log(`  PASS  ${label}`); pass++; }
  else { console.log(`  FAIL  ${label} (got ${got}, want ${want})`); fail++; }
}
console.log(`\nGuard matrix: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
NODE
NODE_RC=$?

echo ""
echo "── Summary ──────────────────────────────────────────────────────────────"
echo "Crypto-alignment checks: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ] && [ "$NODE_RC" -eq 0 ]; then
    echo "RESULT: ✅ ALL CHECKS PASSED, admin authorization is SHA-256 aligned and fails closed."
    exit 0
else
    echo "RESULT: ❌ FAILURES DETECTED."
    exit 1
fi
