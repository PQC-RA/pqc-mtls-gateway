#!/usr/bin/env bash
# deploy.sh: One-shot deployment of the PQC TLS gateway.
#
# Usage:
#   sudo ./scripts/deploy.sh [--server-ip IP] [--admin-cn CN] [--rebuild-artifacts]
#
# What it does (skips steps that are already done):
#   1. Build PQ OpenSSL + OpenResty source artifacts     (~30 min, one-time)
#   2. Install PQ OpenSSL to /opt on the host
#   3. Bootstrap ML-DSA PKI (root CA → intermediate → server + OCSP certs)
#   4. Issue a bootstrap admin certificate via the intermediate CA directly
#   5. Update ADMIN_CERT_FINGERPRINTS in docker-compose.yml
#   6. Install the CRL renewal script
#   7. Generate gateway JWT signing key + control-plane HMAC secret
#   8. Seed the routing config
#   9. Build Docker images
#  10. Start all services
#  11. Wait for gateway health
#  12. Print next steps
#
# The admin cert is saved to ./admin-cert/ for use with scripts/issue-cert.sh
# from a remote machine.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

# The version comes from the single source of truth, not a second copy of it.
# fetch-base-image.sh and check-version-consistency.sh already source this file;
# hardcoding it here meant a versions.env bump left this script docker-cp'ing a
# /opt/openssl-<old> that the new base image does not contain.
# shellcheck disable=SC1091
source "$ROOT_DIR/docker/base/versions.env"
OPENSSL_VER="$OPENSSL_VERSION"
ADMIN_CN="${ADMIN_CN:-gateway-admin}"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-ip)   SERVER_IP="$2"; shift 2 ;;
        --admin-cn)    ADMIN_CN="$2"; shift 2 ;;
        --rebuild-artifacts) export PQC_SKIP_BASE_PULL=1 PQC_SKIP_OPENRESTY_PULL=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must run as root (needs to write to /etc/pki, /etc/ssl, /opt)."
    echo "  sudo ./scripts/deploy.sh"
    exit 1
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────
echo "==> Checking prerequisites..."
if ! command -v docker &>/dev/null; then
    echo "==> Docker not found, installing via get.docker.com..."
    curl -fsSL https://get.docker.com | sh
    # Add current user to docker group if not root (best-effort; not needed when running as root)
    if [[ $EUID -ne 0 ]] && command -v usermod &>/dev/null; then
        usermod -aG docker "$USER" || true
    fi
fi
if ! docker compose version &>/dev/null; then
    echo "==> Docker Compose v2 plugin not found, installing..."
    apt-get install -y docker-compose-plugin
fi
BUILD_PKGS=(build-essential wget tar perl python3 libpcre3-dev zlib1g-dev libxml2-dev libxslt1-dev)
MISSING_PKGS=()
for pkg in "${BUILD_PKGS[@]}"; do
    dpkg -l "$pkg" &>/dev/null || MISSING_PKGS+=("$pkg")
done
if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo "==> Installing missing build packages: ${MISSING_PKGS[*]}"
    apt-get install -y "${MISSING_PKGS[@]}"
fi

# ── Server IP detection ───────────────────────────────────────────────────────
if [[ -z "${SERVER_IP:-}" ]]; then
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [[ -z "$SERVER_IP" ]]; then
    echo "ERROR: Could not auto-detect server IP. Pass it explicitly:"
    echo "  sudo ./scripts/deploy.sh --server-ip 10.0.0.5"
    exit 1
fi
echo "    Server IP: $SERVER_IP (used in server cert SAN)"

# ── Step 1: Ensure the PQ-OpenSSL base image ────────────────────────────────
# fetch-base-image.sh pulls the published base by digest, or builds
# docker/base/openssl/Dockerfile from source when it cannot. Nothing is staged into
# docker/base/ any more: docker/base/openssl/Dockerfile fetches the OpenSSL source
# itself, and docker/gateway/Dockerfile fetches the OpenResty source itself,
# both checksummed against versions.env.
echo "==> [1/9] Ensuring the PQ-OpenSSL base image..."
./scripts/fetch-base-image.sh

# ── Step 2: Install PQ OpenSSL to host ───────────────────────────────────────
# Everything host-side addresses the PQ OpenSSL as /opt/openssl. That is a
# symlink to the versioned tree, created below, the tree itself must keep the
# versioned path because OpenSSL compiles its own prefix into the binary.
#
# The probe therefore goes through the alias deliberately. A host installed by
# an older deploy has /opt/openssl-<ver> but NO symlink, so this fails, falls
# into the install branch, and the ln -sfn heals it. Probing the versioned path
# instead would report "already installed" and leave every script that now says
# /opt/openssl pointing at nothing.
OSSL="/opt/openssl/bin/openssl"
if [[ -x "$OSSL" ]] && OPENSSL_CONF=/dev/null "$OSSL" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa"; then
    echo "==> [2/9] PQ OpenSSL already at $OSSL (skip install)."
else
    # Copied straight out of the base image, with no tarball in between: going
    # via one would mean copying this tree OUT of the image, gzipping it, and
    # untarring it back, a round trip that only moves bytes from an image to a
    # host.
    echo "==> [2/9] Installing PQ OpenSSL to /opt (from the base image)..."
    _cid=$(docker create pqc-mtls-openssl-base:local /bin/true)
    docker cp "$_cid:/opt/openssl-${OPENSSL_VER}" /opt/
    docker rm -f "$_cid" >/dev/null
    # `docker cp` of the versioned directory does not carry its sibling symlink,
    # exactly as `COPY --from` does not. The base image publishes /opt/openssl;
    # this is the host-side equivalent, and without it every script and bench
    # harness that addresses /opt/openssl breaks on a real host while passing in
    # containers.
    ln -sfn "/opt/openssl-${OPENSSL_VER}" /opt/openssl
    echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/00-pqc-openssl.conf
    echo "/opt/openssl/lib"  >> /etc/ld.so.conf.d/00-pqc-openssl.conf
    ldconfig
    echo "    $(OPENSSL_CONF=/dev/null $OSSL version)  (/opt/openssl -> openssl-${OPENSSL_VER})"
fi

# ── Step 3: Bootstrap PKI ────────────────────────────────────────────────────
# Always invoke setup-pki.sh, it is itself idempotent (root/intermediate CA
# bootstrapped exactly once; individual artifacts added after that, like the
# internal-tls service-mesh CA, are caught up on their own). Do NOT gate this
# call on root-ca.crt existing: this script's job is to bring the host to the
# state this repo's current PKI artifacts describe, and a deployment that was
# first bootstrapped before some artifact existed must still pick it up on
# every re-run instead of staying behind. A host bootstrapped before an artifact
# existed would otherwise come up without it, and the gateway would not start.
echo "==> [3/9] Bootstrapping / catching up PQC PKI (ML-DSA-65)..."
PKI_DIR=/etc/pki/pqc-ca
OPENSSL_BIN="$OSSL" SERVER_IP="$SERVER_IP" ./scripts/setup-pki.sh

# ── Step 4: Bootstrap admin certificate ──────────────────────────────────────
ADMIN_DIR="$ROOT_DIR/admin-cert"
ADMIN_KEY="$ADMIN_DIR/$ADMIN_CN.key"
ADMIN_CRT="$ADMIN_DIR/$ADMIN_CN.crt"
INT_CNF="$PKI_DIR/intermediate/openssl-intermediate.cnf"
export OPENSSL_CONF=/etc/ssl/openssl.cnf

if [[ -f "$ADMIN_CRT" ]]; then
    echo "==> [4/9] Admin cert already exists at $ADMIN_CRT (skip)."
else
    echo "==> [4/9] Issuing bootstrap admin certificate (CN=$ADMIN_CN)..."
    mkdir -p "$ADMIN_DIR"
    chmod 700 "$ADMIN_DIR"
    "$OSSL" genpkey -algorithm ML-DSA-65 -out "$ADMIN_KEY" 2>/dev/null
    chmod 600 "$ADMIN_KEY"
    "$OSSL" req -new -key "$ADMIN_KEY" \
        -subj "/C=BG/O=QS-CAP/OU=Admin/CN=$ADMIN_CN" \
        -out "$ADMIN_DIR/$ADMIN_CN.csr" 2>/dev/null
    "$OSSL" ca -config "$INT_CNF" -batch -notext -days 365 \
        -extensions v3_client \
        -in  "$ADMIN_DIR/$ADMIN_CN.csr" \
        -out "$ADMIN_CRT" 2>/dev/null
    rm -f "$ADMIN_DIR/$ADMIN_CN.csr"
    echo "    Admin cert issued."
fi

ADMIN_FPR=$("$OSSL" x509 -in "$ADMIN_CRT" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
echo "    Admin fingerprint: $ADMIN_FPR"

# ── Step 5: Write ADMIN_CERT_FINGERPRINTS into the gitignored .env ───────────
# docker-compose.yml references this as ${ADMIN_CERT_FINGERPRINTS}; the real,
# deploy-specific value lives in .env (gitignored, never committed). Seed .env
# from the committed .env.example on first run, then set the fingerprint
# idempotently (replace the line if present, else append, no duplicates on
# re-run). Without this, a fresh clone+deploy comes up with an empty allowlist
# and locks out admin.
echo "==> [5/9] Writing ADMIN_CERT_FINGERPRINTS into .env..."
[[ -f .env ]] || cp .env.example .env
if grep -q '^ADMIN_CERT_FINGERPRINTS=' .env; then
    sed -i "s/^ADMIN_CERT_FINGERPRINTS=.*/ADMIN_CERT_FINGERPRINTS=$ADMIN_FPR/" .env
else
    printf 'ADMIN_CERT_FINGERPRINTS=%s\n' "$ADMIN_FPR" >> .env
fi
echo "    Set ADMIN_CERT_FINGERPRINTS in .env to: $ADMIN_FPR"

# CORS_ALLOWED_ORIGINS is also deploy-specific but cannot be guessed, leave it
# for the operator. Warn if it is unset/empty so it is not silently forgotten.
if ! grep -qE '^CORS_ALLOWED_ORIGINS=.+' .env; then
    echo "    NOTE: CORS_ALLOWED_ORIGINS is empty in .env. Set it to this"
    echo "          environment's allowed web origins (comma-separated) before"
    echo "          browsers call the management API, e.g. in .env:"
    echo "            CORS_ALLOWED_ORIGINS=https://admin.example.com"
fi

# ── Step 6: Install CRL renewal script ───────────────────────────────────────
echo "==> [6/9] Installing CRL renewal script..."
# Use cp (not install) to preserve the inode so live bind mounts in containers
# see the updated file without requiring a container restart.
cp scripts/pqc-crl-renew.sh /usr/local/bin/pqc-crl-renew.sh
chmod 0755 /usr/local/bin/pqc-crl-renew.sh

# ── Step 7: Gateway secrets ──────────────────────────────────────────────────
echo "==> [7/9] Generating gateway secrets (JWT key + HMAC)..."
# generate-gateway-secrets.sh uses system openssl (RSA only, no PQ needed)
./scripts/generate-gateway-secrets.sh


# ── Step 8: Build images ─────────────────────────────────────────────────────
echo "==> [8/9] Building Docker images..."
./scripts/build-all.sh

# ── Step 9: Init volumes + start services ───────────────────────────────────
echo "==> [9/9] Starting services..."
./scripts/init-volumes.sh
docker compose up -d

# ── Wait for gateway health ───────────────────────────────────────────────────
echo ""
echo "Waiting for gateway to become healthy..."
for i in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' pqc-gateway 2>/dev/null || echo "missing")
    if [[ "$STATUS" == "healthy" || "$STATUS" == "none" ]]; then
        echo "Gateway is up (status=$STATUS)."
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "WARNING: Gateway health check did not pass within 60s. Check: docker compose logs gateway"
    fi
    sleep 2
done

# ── Done ──────────────────────────────────────────────────────────────────────
CA_CHAIN="$PKI_DIR/ca-chain.crt"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo " PQC TLS Gateway deployed at https://$SERVER_IP"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Admin certificate:"
echo "  $ADMIN_CRT  (private key: $ADMIN_KEY)"
echo ""
echo "To issue certificates from a remote machine, copy these files:"
echo "  scp root@$SERVER_IP:$ADMIN_CRT ./admin.crt"
echo "  scp root@$SERVER_IP:$ADMIN_KEY ./admin.key && chmod 600 admin.key"
echo "  scp root@$SERVER_IP:$CA_CHAIN ./ca-chain.crt"
echo "  scp root@$SERVER_IP:$ROOT_DIR/scripts/issue-cert.sh ."
echo ""
echo "Then on the remote machine, issue a cert AND create its routing policy:"
echo "  PQC_GATEWAY=https://$SERVER_IP ./issue-cert.sh demo-service http://shadow-mock:80"
echo ""
echo "  The backend-URL argument IS the routing policy: it maps the cert's CN to"
echo "  a backend (CN 'demo-service' -> shadow-mock, the bundled test service)."
echo "  Without a policy for a client's CN, the gateway has nowhere to send the"
echo "  request and returns 404/502. 'shadow-mock' works out of the box; for a real"
echo "  service replace it with your backend host:port (must resolve on a gateway"
echo "  network). issue-cert.sh prints the exact command to test the request."
echo ""
echo "Manage routing policies directly (admin mTLS on port 443):"
echo "  Create/update:  PUT    https://$SERVER_IP/admin/policy/routes/<cn>   (JSON policy body)"
echo "  Inspect:        GET    https://$SERVER_IP/admin/policy/routes/<cn>"
echo "  Remove:         DELETE https://$SERVER_IP/admin/policy/routes/<cn>"
echo ""
echo "Verify PQC handshake:"
echo "  /opt/openssl-${OPENSSL_VER}/bin/openssl s_client \\"
echo "    -connect $SERVER_IP:443 -CAfile $CA_CHAIN \\"
echo "    -cert $ADMIN_CRT -key $ADMIN_KEY -tls1_3 2>&1 | grep -E 'Negotiated|Peer signature'"
echo ""
echo "Run smoke tests:  ./scripts/test-stack-smoke.sh"
echo ""
echo "When you're done testing:"
echo "  ./scripts/teardown.sh --test-only   # remove shadow-mock + test certs, keep the gateway"
echo "  ./scripts/teardown.sh --all         # full teardown (services, volumes, host PKI/OpenSSL)"
echo ""
