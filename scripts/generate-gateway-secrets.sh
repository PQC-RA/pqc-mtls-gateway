#!/usr/bin/env bash
# generate-gateway-secrets.sh
# One-time script to create the cryptographic secrets required by the PQC
# gateway stack.  Run this before the first `docker compose up`.
#
# Outputs (written to pqc-gw-docker/secrets/, gitignored):
#   gateway-signing.key             RSA-2048 private key for Token 1
#                                   (backend-attestation JWT, aud=pqc-backend,
#                                   kid=backend-v1), gateway only.
#   gateway-signing-key-admin.key   RSA-2048 private key for the /admin/ JWT
#                                   (aud=pqc-mtls-management-api, kid=admin-v1).
#                                   Deliberately a SEPARATE key from the
#                                   backend-attestation key above (three
#                                   separate signing keys, not one shared
#                                   key across purposes), a leaked
#                                   key here should not let an attacker forge
#                                   backend-attestation tokens too.
#   gateway-signing-key-admin-v2.key  ML-DSA-65 private key for the /admin/
#                                   JWT under kid=admin-v2 (ADR-022), used when
#                                   the gateway runs with ADMIN_JWT_KID=admin-v2.
#                                   Needs OpenSSL 3.5+ (scripts/lib/pq-openssl.sh).
#                                   Prints the SHA-256 of its raw public key: that
#                                   value is management-api's ADMIN_V2_PUB_SHA256.
#   gateway-signing-key-lookup.key  RSA-2048 private key for Token 2
#                                   (cert-lookup JWT, aud=pqc-cert-lookup,
#                                   kid=lookup-v1). Closer in sensitivity to
#                                   the admin key than the backend key (grants
#                                   access to cert data), so it earns its own
#                                   key rather than sharing either.
#   control-plane-hmac.key  256-bit hex HMAC secret shared between gateway
#                           and management-api for /update-routes authentication
#   custodian-hmac.key         256-bit hex HMAC secret shared between management-api
#                           and pqc-ca-custodian for sign/revoke/index/issued auth.
#                           Deliberately a SEPARATE secret from control-plane-hmac:
#                           a leaked HMAC here would let an attacker mint/revoke
#                           certs, not just push routes, keep the blast radii apart.
#   enroll-hmac.key         256-bit hex HMAC secret shared between gateway and
#                           management-api, authenticating the /enroll ->
#                           /api/admin/certs/sign proxy hop.
#                           Deliberately a SEPARATE secret from control-plane-hmac
#                           and custodian-hmac, a leaked HMAC here should only let
#                           an attacker sign CSRs through the public enrollment
#                           endpoint, not push routes or mint/revoke certs directly.
#
# After running this script, rebuild the gateway image so the new public key
# is embedded in the JWKS:
#   scripts/build-all.sh   (or: set -a; . docker/base/versions.env; set +a; docker compose build gateway)
#   docker compose up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="$SCRIPT_DIR/../secrets"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# ── RSA-2048 JWT signing key ─────────────────────────────────────────────────
KEY_FILE="$SECRETS_DIR/gateway-signing.key"
if [ -f "$KEY_FILE" ]; then
    echo "SKIP: $KEY_FILE already exists (delete it first to regenerate)"
else
    echo "Generating RSA-2048 signing key..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "  Written: $KEY_FILE"
fi

# ── RSA-2048 admin JWT signing key (Key A, aud=pqc-mtls-management-api) ──
ADMIN_KEY_FILE="$SECRETS_DIR/gateway-signing-key-admin.key"
if [ -f "$ADMIN_KEY_FILE" ]; then
    echo "SKIP: $ADMIN_KEY_FILE already exists (delete it first to regenerate)"
else
    echo "Generating RSA-2048 admin JWT signing key..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$ADMIN_KEY_FILE"
    chmod 600 "$ADMIN_KEY_FILE"
    echo "  Written: $ADMIN_KEY_FILE"
fi

# ── ML-DSA-65 admin JWT signing key (Key A, kid admin-v2, ADR-022) ───────────
# docker-compose.yml names it as a Docker secret, so the stack does not start
# without it, whether or not the gateway signs with it yet. Failing here, with
# the reason, is clearer than compose's "secret file not found" later.
ADMIN_V2_KEY_FILE="$SECRETS_DIR/gateway-signing-key-admin-v2.key"
ADMIN_V2_FAILED=0
# Run in a subshell: pq-openssl.sh exits when it finds no OpenSSL 3.5+, and that
# must stop only this key, with a clear message, not the RSA/HMAC secrets.
if ! (
    # shellcheck source=lib/pq-openssl.sh
    . "$SCRIPT_DIR/lib/pq-openssl.sh"
    if [ -f "$ADMIN_V2_KEY_FILE" ]; then
        echo "SKIP: $ADMIN_V2_KEY_FILE already exists (delete it first to regenerate)"
    else
        echo "Generating ML-DSA-65 admin JWT signing key (kid admin-v2)..."
        ( umask 077; "$O" genpkey -algorithm ML-DSA-65 -out "$ADMIN_V2_KEY_FILE" ) || exit 1
        chmod 600 "$ADMIN_V2_KEY_FILE"
        echo "  Written: $ADMIN_V2_KEY_FILE"
    fi
    pin=$("$O" pkey -in "$ADMIN_V2_KEY_FILE" -pubout -outform DER | tail -c 1952 | sha256sum | cut -d' ' -f1)
    echo "  admin-v2 public key SHA-256 (management-api ADMIN_V2_PUB_SHA256): $pin"
); then
    ADMIN_V2_FAILED=1
fi

# ── RSA-2048 lookup JWT signing key (Key C, aud=pqc-cert-lookup) ────
LOOKUP_KEY_FILE="$SECRETS_DIR/gateway-signing-key-lookup.key"
if [ -f "$LOOKUP_KEY_FILE" ]; then
    echo "SKIP: $LOOKUP_KEY_FILE already exists (delete it first to regenerate)"
else
    echo "Generating RSA-2048 lookup JWT signing key..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$LOOKUP_KEY_FILE"
    chmod 600 "$LOOKUP_KEY_FILE"
    echo "  Written: $LOOKUP_KEY_FILE"
fi

# ── 256-bit HMAC shared secret ───────────────────────────────────────────────
HMAC_FILE="$SECRETS_DIR/control-plane-hmac.key"
if [ -f "$HMAC_FILE" ]; then
    echo "SKIP: $HMAC_FILE already exists (delete it first to regenerate)"
else
    echo "Generating 256-bit HMAC secret..."
    openssl rand -hex 32 > "$HMAC_FILE"
    # root:1001 mode 640, mirrors setup-pki.sh's handling of the CA signing
    # key. The management-api container (uid 1001, bind-mount) needs to READ
    # this file, but it must not be world-readable. NOTE: do NOT use 600/root
    # here, the management-api runs as uid 1001 (not root), so 600 would make
    # the key unreadable to it and break control-plane auth. The JWT signing
    # key above is a private key read only by the
    # gateway (root-owned container process), so it correctly stays at 600.
    APP_GID="${APP_GID:-1001}"
    if chown "root:$APP_GID" "$HMAC_FILE" 2>/dev/null && chmod 640 "$HMAC_FILE" 2>/dev/null; then
        echo "  Written: $HMAC_FILE (root:$APP_GID mode 640)"
    else
        echo "  WARN: could not set ownership to root:$APP_GID on $HMAC_FILE (gid $APP_GID may not exist on this host)." >&2
        echo "        Ensure uid 1001 can READ $HMAC_FILE (mode 640, group $APP_GID) before starting management-api." >&2
        chmod 640 "$HMAC_FILE" 2>/dev/null || true
        echo "  Written: $HMAC_FILE"
    fi
fi

# ── 256-bit HMAC shared secret (management-api <-> pqc-ca-custodian) ────────────
CUSTODIAN_HMAC_FILE="$SECRETS_DIR/custodian-hmac.key"
if [ -f "$CUSTODIAN_HMAC_FILE" ]; then
    echo "SKIP: $CUSTODIAN_HMAC_FILE already exists (delete it first to regenerate)"
else
    echo "Generating 256-bit custodian HMAC secret..."
    openssl rand -hex 32 > "$CUSTODIAN_HMAC_FILE"
    # root:1001 mode 640, both management-api and pqc-ca-custodian run as uid
    # 1001, so group-read is sufficient; same rationale as control-plane-hmac
    # above (do NOT use 600/root, neither reader is root).
    APP_GID="${APP_GID:-1001}"
    if chown "root:$APP_GID" "$CUSTODIAN_HMAC_FILE" 2>/dev/null && chmod 640 "$CUSTODIAN_HMAC_FILE" 2>/dev/null; then
        echo "  Written: $CUSTODIAN_HMAC_FILE (root:$APP_GID mode 640)"
    else
        echo "  WARN: could not set ownership to root:$APP_GID on $CUSTODIAN_HMAC_FILE (gid $APP_GID may not exist on this host)." >&2
        echo "        Ensure uid 1001 can READ $CUSTODIAN_HMAC_FILE (mode 640, group $APP_GID) before starting management-api/pqc-ca-custodian." >&2
        chmod 640 "$CUSTODIAN_HMAC_FILE" 2>/dev/null || true
        echo "  Written: $CUSTODIAN_HMAC_FILE"
    fi
fi

# ── 256-bit HMAC shared secret (gateway <-> management-api /enroll hop) ──────
# root:$APP_GID mode 640, matches control-plane-hmac and
# custodian-hmac above (NOT 644/world-readable). Both readers reach this file
# via owner or group, so 640 is sufficient and removes world-readability: the
# gateway master reads it at init (init_by_lua) as the root-owned nginx process
# (= owner root), and management-api reads it as uid 1001 (= group $APP_GID).
# Neither reader needs world-read, so it is dropped.
ENROLL_HMAC_FILE="$SECRETS_DIR/enroll-hmac.key"
if [ -f "$ENROLL_HMAC_FILE" ]; then
    echo "SKIP: $ENROLL_HMAC_FILE already exists (delete it first to regenerate)"
else
    echo "Generating 256-bit enroll HMAC secret..."
    openssl rand -hex 32 > "$ENROLL_HMAC_FILE"
    APP_GID="${APP_GID:-1001}"
    if chown "root:$APP_GID" "$ENROLL_HMAC_FILE" 2>/dev/null && chmod 640 "$ENROLL_HMAC_FILE" 2>/dev/null; then
        echo "  Written: $ENROLL_HMAC_FILE (root:$APP_GID mode 640)"
    else
        echo "  WARN: could not set ownership to root:$APP_GID on $ENROLL_HMAC_FILE (gid $APP_GID may not exist on this host)." >&2
        echo "        Ensure uid 1001 can READ $ENROLL_HMAC_FILE (mode 640, group $APP_GID) before starting gateway/management-api." >&2
        chmod 640 "$ENROLL_HMAC_FILE" 2>/dev/null || true
        echo "  Written: $ENROLL_HMAC_FILE"
    fi
fi

# Item 4: renew-hmac attests the mTLS client on the gateway -> management-api
# /renew hop. Same readers and mode as enroll-hmac above.
RENEW_HMAC_FILE="$SECRETS_DIR/renew-hmac.key"
if [ -f "$RENEW_HMAC_FILE" ]; then
    echo "SKIP: $RENEW_HMAC_FILE already exists (delete it first to regenerate)"
else
    echo "Generating 256-bit renew HMAC secret..."
    openssl rand -hex 32 > "$RENEW_HMAC_FILE"
    APP_GID="${APP_GID:-1001}"
    chown "root:$APP_GID" "$RENEW_HMAC_FILE" 2>/dev/null || echo "  WARN: could not chown $RENEW_HMAC_FILE to root:$APP_GID" >&2
    chmod 640 "$RENEW_HMAC_FILE" 2>/dev/null || true
    echo "  Written: $RENEW_HMAC_FILE"
fi

echo ""
echo "Secrets ready in $SECRETS_DIR/"
echo "These files are gitignored.  Store them in your secrets manager or"
echo "encrypted storage, DO NOT commit them to version control."
echo ""
echo "Private keys that belong in the encrypted keys set (ADR-018), never in a"
echo "state backup: every *.key above, and from scripts/setup-pki.sh the internal"
echo "TLS CA key(s) under <PKI_DIR>/internal-tls/ and the :8081 keys"
echo "<SSL_DIR>/internal-tls*.key. A new gateway-signing-key-admin-v2.key and a new"
echo "ML-DSA-65 internal CA join that set in the same update."
echo ""
if [ "$ADMIN_V2_FAILED" = 1 ]; then
    echo "ERROR: $ADMIN_V2_KEY_FILE was not created: no OpenSSL 3.5+ (ML-DSA-65) found." >&2
    echo "       docker-compose.yml names it as a Docker secret, so the stack will not start" >&2
    echo "       without it. Install one (scripts/install-host-openssl.sh, or set OSSL to an" >&2
    echo "       OpenSSL 3.5+ binary) and run this script again; existing keys are kept." >&2
    exit 1
fi
echo "Next steps:"
echo "  1. scripts/check-secrets.sh   # every file docker-compose.yml needs is present"
echo "  2. docker compose up -d"
