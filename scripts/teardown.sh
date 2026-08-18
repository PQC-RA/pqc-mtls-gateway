#!/usr/bin/env bash
# teardown.sh: Tear down the PQC TLS gateway, in two scopes.
#
# Usage:
#   ./scripts/teardown.sh --test-only [--yes]
#   ./scripts/teardown.sh --all       [--yes]
#
# Modes:
#   --test-only   Remove the demo/test pieces but KEEP the gateway, PKI, and
#                 management-api running for real use ("promote to production"):
#                   • stops + removes the shadow-mock test backend
#                   • removes issued test client certs under ./certs/
#                 The CA, server cert, admin cert, routes and all other services
#                 are left untouched.
#
#   --all         Full teardown, reclaim the host:
#                   • docker compose down -v  (all services + named volumes,
#                     INCLUDING the CA keys, routes, logs and audit data)
#                   • removes host-installed PQ OpenSSL (/opt/openssl),
#                     the PKI tree (/etc/pki/pqc-ca), the gateway-edge private-key
#                     mask dir (/etc/pki/pqc-empty), server/internal-TLS
#                     certs+keys (/etc/ssl/pqc), the ldconfig drop-in, the CRL
#                     renew script and the seeded routes file
#                   • removes local ./certs and ./admin-cert
#                 This is DESTRUCTIVE and irreversible. The CA cannot be
#                 recovered, every issued certificate becomes orphaned.
#
#   --yes         Skip the interactive confirmation (for scripted use).
#
# Host-path cleanup in --all needs root (sudo); the Docker steps do not.

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
MODE=""
ASSUME_YES=0

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --test-only) MODE="test-only"; shift ;;
        --all)       MODE="all"; shift ;;
        --yes|-y)    ASSUME_YES=1; shift ;;
        -h|--help)
            awk 'NR>1 && /^#/ { sub(/^# ?/,""); print; next } NR>1 { exit }' \
                "${BASH_SOURCE[0]}"
            exit 0 ;;
        *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
    esac
done

if [[ -z "$MODE" ]]; then
    echo "ERROR: choose a scope: --test-only or --all  (see --help)."
    exit 1
fi

confirm() {
    # $1 = prompt; returns 0 to proceed, 1 to abort.
    [[ "$ASSUME_YES" -eq 1 ]] && return 0
    local reply
    read -r -p "$1 [type 'yes' to proceed] " reply
    [[ "$reply" == "yes" ]]
}

# ── Mode: test-only ───────────────────────────────────────────────────────────
if [[ "$MODE" == "test-only" ]]; then
    echo "==> Removing test-only pieces (gateway/PKI/management-api are kept)..."

    echo "    • Removing the shadow-mock test backend..."
    docker compose rm -fs shadow-mock 2>/dev/null || true

    if compgen -G "./certs/*" > /dev/null; then
        if confirm "    • Delete issued TEST client certs under ./certs/ ?"; then
            rm -rf ./certs/*
            echo "      Removed ./certs/*"
        else
            echo "      Skipped ./certs/ cleanup."
        fi
    else
        echo "    • No ./certs/ artifacts to remove."
    fi

    echo ""
    echo "Done. The gateway, PKI and management-api are still running."
    echo "Notes:"
    echo "  • shadow-mock stays gone until the next 'docker compose up -d'."
    echo "    To keep it from coming back, remove its service block from"
    echo "    docker-compose.yml (or put it behind a compose 'profiles: [test]')."
    echo "  • Demo routes still point at the (now-absent) backend. To drop one:"
    echo "      DELETE \$GW/admin/policy/routes/<cn>   (admin mTLS, see README)"
    exit 0
fi

# ── Mode: all ─────────────────────────────────────────────────────────────────
if [[ "$MODE" == "all" ]]; then
    echo "WARNING: full teardown is DESTRUCTIVE and irreversible."
    echo "  This removes ALL services, ALL named volumes (including the CA keys),"
    echo "  and host-installed PQ OpenSSL + the /etc/pki/pqc-ca PKI tree."
    echo "  Every issued certificate becomes permanently orphaned."
    echo ""
    if ! confirm "Proceed with FULL teardown?"; then
        echo "Aborted."
        exit 0
    fi

    echo "==> [1/3] Stopping services and removing containers + named volumes..."
    docker compose down -v --remove-orphans 2>/dev/null || true

    echo "==> [2/3] Removing local artifacts..."
    rm -rf ./certs ./admin-cert
    echo "    Removed ./certs and ./admin-cert"

    echo "==> [3/3] Removing host-installed artifacts..."
    HOST_PATHS=(
        # The alias first, then the tree it points at. `rm -rf` on a symlink
        # removes the link and does not follow it, so this cannot delete the
        # tree twice or, worse, delete /opt/openssl's target from under a
        # half-removed install.
        "/opt/openssl"
        "/opt/openssl-${OPENSSL_VER}"
        "/etc/pki/pqc-ca"
        "/etc/pki/pqc-empty"
        "/etc/ssl/pqc"
        "/etc/ld.so.conf.d/00-pqc-openssl.conf"
        # Pre-rename name. Kept so hosts deployed before the 00- prefix
        # are still cleaned up rather than left with a stale conf.
        "/etc/ld.so.conf.d/pqc-openssl.conf"
        "/usr/local/bin/pqc-crl-renew.sh"
        # Routing policy lives in the management API, not this file. Listed so a
        # host that still has one left over is cleaned up too.
        "/etc/nginx/njs/routes.json"
    )
    if [[ $EUID -ne 0 ]]; then
        echo "    NOTE: not running as root, skipping host-path cleanup."
        echo "    Re-run as root to remove these:"
        printf '      %s\n' "${HOST_PATHS[@]}"
    else
        for p in "${HOST_PATHS[@]}"; do
            # -e follows symlinks and is FALSE for a dangling one, so a link
            # whose target a previous partial teardown already removed would be
            # skipped and left behind. -L catches that case.
            if [[ -e "$p" || -L "$p" ]]; then
                rm -rf "$p"
                echo "    Removed $p"
            fi
        done
        # Refresh the dynamic linker cache now that the PQ libs are gone.
        command -v ldconfig &>/dev/null && ldconfig || true
    fi

    echo ""
    echo "Full teardown complete. To redeploy from scratch: sudo ./scripts/deploy.sh"
    exit 0
fi
