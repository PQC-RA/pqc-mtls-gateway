#!/usr/bin/env bash
# issue-cert.sh: Issue an ML-DSA-65 client certificate via the PQC gateway.
#
# Two modes, selected automatically:
#
#   Self-enrollment  (service operator, no admin credentials needed):
#     An admin pre-issues a CN-constrained token and hands it to you out-of-band.
#     You generate your own key pair locally and enroll with the token.
#
#       ENROLLMENT_TOKEN=enroll_abc123 ./issue-cert.sh <cn>
#
#   Admin-direct  (admin creates a short-lived token on-the-fly):
#     Requires admin cert/key to call the admin token-creation API.
#
#       ./issue-cert.sh <cn> [backend-url]
#
# Examples:
#   ENROLLMENT_TOKEN=enroll_abc ./issue-cert.sh <cn>
#   ./issue-cert.sh <cn>
#   ./issue-cert.sh <cn> <backend-url>
#
# Required env vars (or edit defaults below):
#   PQC_GATEWAY          Gateway base URL              (default: https://127.0.0.1)
#   PQC_CA_CHAIN         Path to CA chain cert         (default: ./ca-chain.crt)
#   PQC_ENROLL_CA        CA that signed the :8443 enrollment cert
#                        (default: /etc/pki/pqc-ca/enroll-classical-ca.crt;
#                         falls back to PQC_CA_CHAIN when that file is absent)
#   ENROLLMENT_TOKEN     Pre-issued enrollment token   (if set, skips admin step)
#   PQC_ADMIN_CERT       Admin client cert             (required only without ENROLLMENT_TOKEN)
#   PQC_ADMIN_KEY        Admin client key              (required only without ENROLLMENT_TOKEN)
#   PQC_OUT_DIR          Where to save artifacts       (default: ./certs/<cn>)
#   PQC_OPENSSL          Path to PQ openssl binary     (default: auto-detect)
#   PQC_BASE_IMAGE       PQ-OpenSSL base image for the Docker fallback
#                        (default: the digest pinned in this script)

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
GW="${PQC_GATEWAY:-https://127.0.0.1}"
CA_CHAIN="${PQC_CA_CHAIN:-./ca-chain.crt}"
ADMIN_CERT="${PQC_ADMIN_CERT:-./admin.crt}"
ADMIN_KEY="${PQC_ADMIN_KEY:-./admin.key}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-}"

# The :8443 enrollment listener presents a CLASSICAL ECDSA server cert (since
# 2026-07-01), issued by a SEPARATE self-signed CA, the ML-DSA chain in
# $CA_CHAIN cannot verify it. Trust the enrollment CA for :8443 calls.
# Override with PQC_ENROLL_CA. Fall back to $CA_CHAIN when the enrollment CA
# is absent (pre-2026-07-01 deployments where :8443 still served the ML-DSA
# leaf, or a remote client that has not copied the enrollment CA over).
ENROLL_CA="${PQC_ENROLL_CA:-/etc/pki/pqc-ca/enroll-classical-ca.crt}"
[[ -f "$ENROLL_CA" ]] || ENROLL_CA="$CA_CHAIN"

CN="${1:-}"
BACKEND="${2:-}"

if [[ -z "$CN" ]]; then
    echo "Usage: $0 <common-name> [backend-url]"
    echo ""
    echo "  cn           CN= for the new certificate (becomes the gateway routing key)"
    echo "  backend-url  Optional: route this CN to a backend (e.g. http://backend:8080)"
    echo ""
    echo "Self-enrollment (token pre-issued by admin):"
    echo "  ENROLLMENT_TOKEN=enroll_xxx $0 <cn>"
    echo ""
    echo "Admin-direct (token created automatically):"
    echo "  $0 <cn>"
    echo ""
    echo "Required files (place alongside script or set env vars):"
    echo "  ca-chain.crt   scp root@<server>:/etc/pki/pqc-ca/hybrid-ca-chain.crt ."
    echo "  Admin-direct only:"
    echo "  admin.crt      scp root@<server>:/tmp/client.crt ./admin.crt"
    echo "  admin.key      scp root@<server>:/tmp/client.key ./admin.key && chmod 600 admin.key"
    echo "  (macOS/Docker fallback pulls the PQ-OpenSSL base image; needs docker login ghcr.io)"
    exit 1
fi

# Validate CN early, before it is interpolated into the cert DN, the Docker
# re-exec command, file paths, or the JSON tooling below. The restricted charset
# blocks DN injection (CN containing '/') and shell/argument injection.
if [[ ! "$CN" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    echo "ERROR: invalid CN '$CN', allowed: letters, digits, '.', '_', '-' (max 64 chars)." >&2
    exit 1
fi
# Validate the optional backend URL. It is interpolated into the Docker re-exec
# command, so reject any character outside a safe URL subset (blocks quotes,
# spaces, ';', '&', '$', backticks, ... that could break out of the shell).
BACKEND_BADCHARS='[^A-Za-z0-9._~:/?#@%=-]'
if [[ -n "$BACKEND" && "$BACKEND" =~ $BACKEND_BADCHARS ]]; then
    echo "ERROR: backend URL '$BACKEND' contains disallowed characters." >&2
    exit 1
fi

OUT_DIR="${PQC_OUT_DIR:-./certs/$CN}"
KEY_ALG=ML-DSA-65

# Enrollment is served on port 8443 (no mTLS required).
# Derive the enrollment URL from GW by extracting the host and appending :8443.
GW_HOST=$(echo "$GW" | sed 's|https://||; s|[:/].*||')
ENROLL_URL="https://${GW_HOST}:8443/enroll"

# ── PQ capability detection ───────────────────────────────────────────────────

has_pq_openssl() {
    local candidate
    for candidate in "${PQC_OPENSSL:-}" /opt/openssl/bin/openssl "$(command -v openssl 2>/dev/null || true)"; do
        [[ -z "$candidate" ]] && continue
        if OPENSSL_CONF=/dev/null "$candidate" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa"; then
            return 0
        fi
    done
    return 1
}

has_pq_curl() {
    # curl must be linked against OpenSSL 3.5+ for ML-DSA-65 client certs
    curl --version 2>/dev/null | grep -qE "OpenSSL/3\.[5-9]|OpenSSL/3\.[1-9][0-9]"
}

# ── Docker fallback (no PQ OpenSSL on host) ───────────────────────────────────
# If PQ OpenSSL is absent from the host, re-exec inside an Ubuntu container
# with the pre-built tarball.  If PQ OpenSSL IS available but curl lacks it
# (e.g. macOS with homebrew openssl@3.5+), run natively and use _pq_https()
# (openssl s_client) in place of curl for HTTPS calls.

if [[ "${_PQC_IN_DOCKER:-0}" != "1" ]] && ! has_pq_openssl; then

    if ! command -v docker &>/dev/null; then
        echo "ERROR: PQ OpenSSL 3.6 (with ML-DSA-65) not found and Docker is not installed."
        echo ""
        echo "Option A, install Docker Desktop: https://docs.docker.com/get-docker/"
        echo "Option B, install PQ OpenSSL natively (Linux only):"
        echo "  or let the Docker fallback pull the PQ-OpenSSL base image (docker login ghcr.io)"
        echo "  echo '/opt/openssl/lib64' | sudo tee /etc/ld.so.conf.d/00-pqc-openssl.conf"
        echo "  sudo ldconfig"
        exit 1
    fi

    # The published PQ-OpenSSL base image, pinned by digest. This replaces a
    # scp'd openssl-compiled.tar.gz that had to be untarred into a bare
    # ubuntu:24.04, i.e. reconstructing this image by hand.
    #
    # It also removes the --platform pin. A tarball is single-arch (it was always
    # built x86_64 on the server), so arm64 Macs had to run the whole fallback
    # under Rosetta 2. The image is multi-arch, so Apple Silicon now runs native.
    #
    # The image is currently a PRIVATE package: Login Succeeded with a
    # token carrying read:packages is required until it is made public.
    PQC_BASE_IMAGE="${PQC_BASE_IMAGE:-ghcr.io/pqc-ra/pqc-mtls-openssl-base@sha256:c3f5439369fa9b49e4d28929708687338cbf21b0ac14acf18b916c15892646b1}"
    echo "[docker] No PQ OpenSSL found, re-running inside $PQC_BASE_IMAGE (native arch)..."
    echo "[docker] If you have PQ OpenSSL installed (e.g. homebrew openssl@3.5+), set PQC_OPENSSL=<path>."

    # Resolve all paths to absolute so Docker volumes work from any working dir
    ABS_CA="$(cd "$(dirname "$CA_CHAIN")" && pwd)/$(basename "$CA_CHAIN")"
    ABS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    mkdir -p "$OUT_DIR"
    ABS_OUT="$(cd "$OUT_DIR" && pwd)"

    # Build docker run args as an array to handle paths with spaces correctly.
    # Admin cert/key are only mounted (and needed) when creating a token on-the-fly.
    DOCKER_ARGS=(
        --rm
        -v "${ABS_CA}:/creds/ca-chain.crt:ro"
    )
    # Enrollment CA (:8443 classical cert): mount it too when it differs from the
    # ML-DSA chain, so in-container :8443 verification works. If ENROLL_CA fell
    # back to $CA_CHAIN it is already mounted as /creds/ca-chain.crt.
    ENROLL_ENV_BLOCK=""
    if [[ -f "$ENROLL_CA" && "$ENROLL_CA" != "$CA_CHAIN" ]]; then
        ABS_ENROLL_CA="$(cd "$(dirname "$ENROLL_CA")" && pwd)/$(basename "$ENROLL_CA")"
        DOCKER_ARGS+=(-v "${ABS_ENROLL_CA}:/creds/enroll-ca.crt:ro")
        ENROLL_ENV_BLOCK="export PQC_ENROLL_CA=/creds/enroll-ca.crt;"
    fi
    ADMIN_ENV_BLOCK=""
    if [[ -z "$ENROLLMENT_TOKEN" ]]; then
        ABS_CERT="$(cd "$(dirname "$ADMIN_CERT")" && pwd)/$(basename "$ADMIN_CERT")"
        ABS_KEY="$(cd "$(dirname "$ADMIN_KEY")" && pwd)/$(basename "$ADMIN_KEY")"
        DOCKER_ARGS+=(-v "${ABS_CERT}:/creds/admin.crt:ro" -v "${ABS_KEY}:/creds/admin.key:ro")
        ADMIN_ENV_BLOCK="export PQC_ADMIN_CERT=/creds/admin.crt; export PQC_ADMIN_KEY=/creds/admin.key;"
    fi
    DOCKER_ARGS+=(
        -v "${ABS_SCRIPT}:/issue-cert.sh:ro"
        -v "${ABS_OUT}:/out"
    )

    EXTRA_ARG=""
    [[ -n "$BACKEND" ]] && EXTRA_ARG="'$BACKEND'"

    exec docker run "${DOCKER_ARGS[@]}" "$PQC_BASE_IMAGE" bash -c "
        set -euo pipefail
        apt-get update -qq > /dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl python3 > /dev/null 2>&1
        # No untar, no ld.so.conf.d, no LD_LIBRARY_PATH export: the base image
        # already ships the tree, the 00- ldconfig entry and LD_LIBRARY_PATH.
        # Those six lines were reconstructing this image by hand.
        export _PQC_IN_DOCKER=1
        export PQC_GATEWAY='$GW'
        export PQC_CA_CHAIN=/creds/ca-chain.crt
        export ENROLLMENT_TOKEN='${ENROLLMENT_TOKEN}'
        ${ADMIN_ENV_BLOCK}
        ${ENROLL_ENV_BLOCK}
        export PQC_OUT_DIR=/out
        export _PQC_LOCAL_OUT='$ABS_OUT'
        export _PQC_LOCAL_CA='$ABS_CA'
        PQC_KEY_ALG='$KEY_ALG' bash /issue-cert.sh '$CN' $EXTRA_ARG
    "
    # exec replaces this process, nothing below runs on the host
fi

# ── From here: running natively or inside the Docker container ────────────────

mkdir -p "$OUT_DIR"
KEY_FILE="$OUT_DIR/$CN.key"
CSR_FILE="$OUT_DIR/$CN.csr"
CRT_FILE="$OUT_DIR/$CN.crt"

# Locate PQ openssl
OSSL=""
for candidate in "${PQC_OPENSSL:-}" /opt/openssl/bin/openssl "$(command -v openssl 2>/dev/null || true)"; do
    [[ -z "$candidate" ]] && continue
    if OPENSSL_CONF=/dev/null "$candidate" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa"; then
        OSSL="$candidate"
        break
    fi
done

if [[ -z "$OSSL" ]]; then
    echo "ERROR: No OpenSSL with ML-DSA-65 support found."
    exit 1
fi
export OPENSSL_CONF="${OPENSSL_CONF:-/etc/ssl/openssl.cnf}"

# curl for enrollment: server-auth only, no client cert, targets port 8443,
# which presents the classical ECDSA cert -> verify with $ENROLL_CA.
CURL_ENROLL="curl -sS --cacert $ENROLL_CA --max-time 15 --connect-timeout 8"
# curl for admin API: mTLS, admin cert required, targets port 443.
# X-PQC-CSRF:1 satisfies the management-api CSRF guard on mutating admin
# routes (e.g. POST/DELETE /admin/certs/enrollment-tokens). The guard requires
# this custom header; a cross-site browser cannot set it (CORS preflight is
# blocked), so a CLI that sets it explicitly is authorized without an Origin.
# No space after the colon so the token survives word-splitting of $CURL_ADMIN.
CURL_ADMIN="curl -sS --cacert $CA_CHAIN --cert $ADMIN_CERT --key $ADMIN_KEY -H X-PQC-CSRF:1 --max-time 15 --connect-timeout 8"

# ── PQ openssl HTTP helper (Docker mode only) ─────────────────────────────────
# Ubuntu 24.04 curl cannot load ML-DSA-65 client certs via LD_LIBRARY_PATH
# override.  When running inside Docker, use the PQ openssl binary directly as
# the HTTPS transport.  Output matches curl -w "\n%{http_code}": body lines
# first, then the three-digit HTTP status code as the final line.
_pq_https() {
    local method="$1" url="$2" body="${3:-}" with_admin="${4:-0}"
    local host port path
    host=$(echo "$url" | sed 's|https://||; s|[:/].*||')
    port=$(echo "$url" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
    port="${port:-443}"
    path=$(echo "$url" | sed "s|https://[^/]*||")
    [[ -z "$path" ]] && path="/"
    # :8443 (enrollment) presents the classical ECDSA cert -> verify with
    # $ENROLL_CA; :443 (admin/API) uses the ML-DSA chain.
    local cafile="$CA_CHAIN"
    [[ "$port" == "8443" ]] && cafile="$ENROLL_CA"
    # -verify_return_error is what makes -CAfile mean anything here: without it
    # s_client reports "verify error:num=21", completes the handshake anyway, and
    # this helper parses a 201 out of the response. On :8443 that hands the
    # enrollment token to whatever certificate was presented.
    local s_args=(-connect "${host}:${port}" -CAfile "$cafile" -tls1_3 -quiet
                  -verify_return_error)
    [[ "$with_admin" == "1" ]] && s_args+=(-cert "$ADMIN_CERT" -key "$ADMIN_KEY")
    {
        printf '%s %s HTTP/1.1\r\n' "$method" "$path"
        printf 'Host: %s\r\n' "$host"
        printf 'Connection: close\r\n'
        # Admin (mTLS) calls carry the CSRF header the management-api guard
        # requires on mutating admin routes (see CURL_ADMIN above).
        [[ "$with_admin" == "1" ]] && printf 'X-PQC-CSRF: 1\r\n'
        if [[ "$method" == "POST" || "$method" == "PUT" ]]; then
            printf 'Content-Length: %d\r\n' "${#body}"
            if [[ -n "$body" ]]; then printf 'Content-Type: application/json\r\n'; fi
        fi
        printf '\r\n'
        if [[ -n "$body" ]]; then printf '%s' "$body"; fi
    } | OPENSSL_CONF="${OPENSSL_CONF:-/etc/ssl/openssl.cnf}" "$OSSL" s_client \
        "${s_args[@]}" 2>/dev/null \
    | awk '
        BEGIN { in_body=0; code="000" }
        !in_body && /^HTTP\// { match($0,/[0-9]{3}/); code=substr($0,RSTART,RLENGTH) }
        !in_body && /^\r?$/ { in_body=1; next }
        in_body && /^[0-9a-fA-F]+\r?$/ { next }
        in_body { sub(/\r$/,""); print }
        END { print code }
    ' || true
}

# ── Pre-flight: verify gateway is reachable ───────────────────────────────────
# macOS system curl (LibreSSL) cannot negotiate the X25519MLKEM768 + ML-DSA-65
# handshake at all, so a plain `curl "$GW"` reachability probe always fails on
# macOS even when the host is perfectly reachable.  When curl lacks PQ support,
# probe with openssl s_client instead (just confirm the TCP+TLS port answers).
echo "[0] Checking gateway connectivity to $GW..."
if has_pq_curl; then
    REACHABLE=0
    curl -sk --max-time 8 --connect-timeout 5 "$GW" -o /dev/null 2>&1 && REACHABLE=1
else
    REACHABLE=0
    echo | OPENSSL_CONF=/etc/ssl/openssl.cnf "$OSSL" s_client \
        -connect "${GW_HOST}:443" -CAfile "$CA_CHAIN" 2>/dev/null \
        | grep -q "^CONNECTED" && REACHABLE=1
fi
if [[ "$REACHABLE" != "1" ]]; then
    echo "ERROR: Cannot reach $GW"
    echo "  Check the server IP/port and that the gateway is listening on 443."
    echo "  If you set PQC_GATEWAY, ensure it is the server's reachable address."
    exit 1
fi
echo "    OK"

# ── Step 1: generate key + CSR ────────────────────────────────────────────────
echo "[1] Generating $KEY_ALG key and CSR for CN=$CN..."

if [[ -f "$KEY_FILE" ]]; then
    echo "    Key already exists, reusing."
else
    "$OSSL" genpkey -algorithm "$KEY_ALG" -out "$KEY_FILE" 2>/dev/null
    chmod 600 "$KEY_FILE"
fi

"$OSSL" req -new -key "$KEY_FILE" -out "$CSR_FILE" \
    -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$CN" 2>/dev/null

# ── Step 2: obtain enrollment token ───────────────────────────────────────────
# If ENROLLMENT_TOKEN is already set (operator self-enrollment), skip token creation.
# Otherwise, create a short-lived CN-constrained token via the admin API (requires
# admin cert/key on port 443 with mTLS).

if [[ -n "$ENROLLMENT_TOKEN" ]]; then
    echo "[2] Using pre-issued enrollment token."
    TOKEN="$ENROLLMENT_TOKEN"
else
    echo "[2] Requesting CN-constrained enrollment token from admin API..."
    echo "    (requires admin cert/key, set ENROLLMENT_TOKEN=<token> to skip this step)"

    ENCODED_CN=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$CN'))")

    if ! has_pq_curl; then
        TOKEN_RESP=$(_pq_https POST \
            "$GW/admin/certs/enrollment-tokens?cn=${ENCODED_CN}&ttl=300" "" 1)
    elif ! TOKEN_RESP=$($CURL_ADMIN -X POST \
            "$GW/admin/certs/enrollment-tokens?cn=${ENCODED_CN}&ttl=300" \
            -w "\n%{http_code}" 2>&1); then
        echo "ERROR: curl failed connecting to $GW"
        echo "$TOKEN_RESP"
        exit 1
    fi
    HTTP_CODE=$(echo "$TOKEN_RESP" | tail -1)
    TOKEN_BODY=$(echo "$TOKEN_RESP" | sed '$d')

    if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
        echo "ERROR: Failed to get enrollment token (HTTP $HTTP_CODE)"
        echo "  Response: $TOKEN_BODY"
        echo ""
        echo "  If you have a pre-issued token, pass it as:"
        echo "    ENROLLMENT_TOKEN=enroll_xxx $0 $CN"
        exit 1
    fi

    TOKEN=$(echo "$TOKEN_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
    ALLOWED_CN=$(echo "$TOKEN_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin)['allowedCn'])")
    EXPIRES=$(echo "$TOKEN_BODY" | python3 -c "
import json,sys,datetime
d=json.load(sys.stdin)
print(datetime.datetime.fromtimestamp(d.get('expiresAt',0)/1000, datetime.timezone.utc).strftime('%H:%M:%S UTC'))
")
    echo "    Token for CN=$ALLOWED_CN valid until $EXPIRES"
fi

# ── Step 3: enroll, submit CSR + token to the enrollment endpoint ─────────────
# The enrollment endpoint (port 8443) does not require a client certificate.
# The enrollment token is the sole authorization.

echo "[3] Enrolling at $ENROLL_URL..."

# Pass file path + token via env (os.environ) so neither can inject into the
# Python source even if a value contains quotes or newlines.
PAYLOAD=$(CSR_FILE="$CSR_FILE" ENROLL_TOKEN="$TOKEN" python3 -c "
import json, os
print(json.dumps({'csr': open(os.environ['CSR_FILE']).read(), 'enrollmentToken': os.environ['ENROLL_TOKEN']}))
")

if ! has_pq_curl; then
    SIGN_RESP=$(_pq_https POST "$ENROLL_URL" "$PAYLOAD" 0)
elif ! SIGN_RESP=$($CURL_ENROLL -X POST "$ENROLL_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        -w "\n%{http_code}" 2>&1); then
    echo "ERROR: curl failed during enrollment"
    echo "  $(echo "$SIGN_RESP" | tail -1)"
    exit 1
fi
HTTP_CODE=$(echo "$SIGN_RESP" | tail -1)
SIGN_BODY=$(echo "$SIGN_RESP" | sed '$d')

if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
    echo "ERROR: Enrollment failed (HTTP $HTTP_CODE)"
    echo "  Response: $SIGN_BODY"
    if [[ "$HTTP_CODE" == "403" ]]; then
        echo ""
        echo "  403 means the token is invalid, expired, already used,"
        echo "  or the CSR CN ($CN) does not match the token's CN constraint."
        echo "  Ask an admin to issue a new token for CN=$CN."
    fi
    if [[ "$HTTP_CODE" == "000" ]]; then
        echo ""
        echo "  000 means no HTTP response arrived: the TLS connection to :8443 failed."
        echo "  That listener presents a CLASSICAL ECDSA certificate from a separate CA,"
        echo "  which the ML-DSA chain in PQC_CA_CHAIN cannot verify. From a client"
        echo "  machine, copy that CA over and point PQC_ENROLL_CA at it:"
        echo "    scp root@<server>:/etc/pki/pqc-ca/enroll-classical-ca.crt ./enroll-ca.crt"
        echo "    PQC_ENROLL_CA=./enroll-ca.crt $0 $CN"
    fi
    if [[ "$HTTP_CODE" == "409" ]]; then
        echo ""
        echo "  409 means CN=$CN already has an active certificate. The CA"
        echo "  keeps one per CN, so renewing means revoking the old one first:"
        echo "  POST /admin/certs/revoke with its serial, as scripts/test-issuance-e2e.sh does."
        echo "  If you only need the existing certificate, it is already under certs/$CN/."
    fi
    exit 1
fi

python3 -c "
import json,sys
d=json.load(sys.stdin)
open('$CRT_FILE','w').write(d['certificate'])
print(f'    Serial:  {d[\"serialNumber\"]}')
print(f'    Expires: {d[\"expiresAt\"]}')
" <<< "$SIGN_BODY"

# ── Step 4: fingerprint ───────────────────────────────────────────────────────
FINGERPRINT=$("$OSSL" x509 -in "$CRT_FILE" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
echo "[4] Certificate fingerprint (SHA-256): $FINGERPRINT"

# ── Step 5: routing policy ────────────────────────────────────────────────────
if [[ -n "$BACKEND" ]]; then
    echo "[5] Setting route: CN=$CN → $BACKEND"
    # 'org' is OPTIONAL on a route, it merely names an organization whose
    # default policy is merged into this route (see PUT /admin/policy/orgs/:id).
    # If you name one it MUST already exist, else the PUT is rejected 400
    # "Organization '<id>' not found". Default to NO org so a route is
    # self-contained and works out of the box; set ROUTE_ORG=<existing-org-id>
    # only if you want that org's defaults merged in.
    ROUTE_PAYLOAD=$(ROUTE_BACKEND="$BACKEND" ROUTE_ORG="${ROUTE_ORG:-}" python3 -c "
import json, os
payload = {
    'backend': os.environ['ROUTE_BACKEND'],
    'rate_limit': {'rps':100,'burst':200},
    'allowed_paths': ['/api/','/data/','/status/','/webhook/']
}
org = os.environ.get('ROUTE_ORG')
if org:
    payload['org'] = org
print(json.dumps(payload))
")
    if ! has_pq_curl; then
        ROUTE_RESP=$(_pq_https PUT "$GW/admin/policy/routes/$CN" "$ROUTE_PAYLOAD" 1)
    else
        ROUTE_RESP=$($CURL_ADMIN -X PUT "$GW/admin/policy/routes/$CN" \
            -H "Content-Type: application/json" -d "$ROUTE_PAYLOAD" \
            -w "\n%{http_code}" 2>&1) || true
    fi
    ROUTE_CODE=$(echo "$ROUTE_RESP" | tail -1)
    if [[ "$ROUTE_CODE" == "200" || "$ROUTE_CODE" == "201" ]]; then
        echo "    Route set."
    else
        echo "    WARNING: Route update returned HTTP $ROUTE_CODE"
        echo "    $(echo "$ROUTE_RESP" | sed '$d')"
    fi
else
    echo "[5] No backend URL, skipping route."
    echo "    Add later: PUT $GW/admin/policy/routes/$CN"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
# When running inside Docker the script paths are container-internal (/out/,
# /creds/...).  Use the host-side paths passed in via _PQC_LOCAL_OUT/_PQC_LOCAL_CA
# so the printed commands work directly on the caller's machine.
_DISPLAY_OUT="${_PQC_LOCAL_OUT:-$OUT_DIR}"
_DISPLAY_CA="${_PQC_LOCAL_CA:-$CA_CHAIN}"
# Absolute, because the commands printed below get copied and run from wherever
# the reader happens to be. A relative path fails there, and with `curl -s` or a
# grep filter on the openssl output it fails SILENTLY, which costs real time.
case "$_DISPLAY_OUT" in /*) ;; *) _DISPLAY_OUT="$(cd "$_DISPLAY_OUT" 2>/dev/null && pwd || echo "$_DISPLAY_OUT")" ;; esac
case "$_DISPLAY_CA" in /*) ;; *) _DISPLAY_CA="$(cd "$(dirname "$_DISPLAY_CA")" 2>/dev/null && pwd)/$(basename "$_DISPLAY_CA")" ;; esac

echo ""
echo "Done. Artifacts saved to: $_DISPLAY_OUT/"
echo "  Private key:  $_DISPLAY_OUT/$CN.key"
echo "  Certificate:  $_DISPLAY_OUT/$CN.crt"
echo "  Fingerprint:  $FINGERPRINT"
echo ""
_GW_HOST=$(echo "$GW" | sed 's|https://||; s|[:/].*||')
echo "Test your connection:"
if ! has_pq_curl; then
    # No PQ-capable curl (macOS LibreSSL curl, or Ubuntu 24.04 Docker),
    # use openssl s_client directly for both TLS verification and API requests.
    _OSSL_CMD="${OSSL:-openssl}"
    echo "  # Verify PQC handshake:"
    echo "  echo | OPENSSL_CONF=/etc/ssl/openssl.cnf $_OSSL_CMD s_client \\"
    echo "    -connect ${_GW_HOST}:443 -CAfile $_DISPLAY_CA \\"
    echo "    -cert $_DISPLAY_OUT/$CN.crt -key $_DISPLAY_OUT/$CN.key -tls1_3 2>&1 \\"
    echo "    | grep -E 'Negotiated|Peer signature'"
    echo ""
    echo "  # Full API request:"
    echo "  printf 'GET /api/v1/status HTTP/1.1\\r\\nHost: ${_GW_HOST}\\r\\nConnection: close\\r\\n\\r\\n' \\"
    echo "    | OPENSSL_CONF=/etc/ssl/openssl.cnf $_OSSL_CMD s_client \\"
    echo "    -connect ${_GW_HOST}:443 -CAfile $_DISPLAY_CA \\"
    echo "    -cert $_DISPLAY_OUT/$CN.crt -key $_DISPLAY_OUT/$CN.key -tls1_3 -quiet 2>/dev/null \\"
    echo "    | tail -1"
else
    echo "  # Verify PQC handshake:"
    echo "  echo | OPENSSL_CONF=/etc/ssl/openssl.cnf /opt/openssl/bin/openssl s_client \\"
    echo "    -connect ${_GW_HOST}:443 -CAfile $_DISPLAY_CA \\"
    echo "    -cert $_DISPLAY_OUT/$CN.crt -key $_DISPLAY_OUT/$CN.key -tls1_3 2>&1 \\"
    echo "    | grep -E 'Negotiated|Peer signature'"
    echo ""
    echo "  # Full API request:"
    echo "  curl -sk --cacert $_DISPLAY_CA --cert $_DISPLAY_OUT/$CN.crt --key $_DISPLAY_OUT/$CN.key $GW/api/v1/status"
fi
