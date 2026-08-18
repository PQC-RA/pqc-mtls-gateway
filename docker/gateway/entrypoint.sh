#!/bin/bash
set -euo pipefail

echo "Starting OpenResty PQ-TLS Gateway..."

# ── Runtime secret validation ────────────────────────────────────────────────
# The three RSA signing keys (three separate signing keys, one per
# JWT purpose) and the HMAC secret are injected as Docker secrets and are
# never baked into the image.  Abort early with a clear message if any is
# missing so misconfigured deployments are immediately visible.
KEY_SECRET_BACKEND=/run/secrets/gateway-signing-key
KEY_SECRET_ADMIN=/run/secrets/gateway-signing-key-admin
KEY_SECRET_LOOKUP=/run/secrets/gateway-signing-key-lookup
HMAC_SECRET=/run/secrets/control-plane-hmac

if [ ! -f "$KEY_SECRET_BACKEND" ]; then
    echo "FATAL: Gateway backend signing key not found at $KEY_SECRET_BACKEND" >&2
    echo "       Mount it as a Docker secret: secrets.gateway-signing-key" >&2
    exit 1
fi

if [ ! -f "$KEY_SECRET_ADMIN" ]; then
    echo "FATAL: Gateway admin signing key not found at $KEY_SECRET_ADMIN" >&2
    echo "       Mount it as a Docker secret: secrets.gateway-signing-key-admin" >&2
    exit 1
fi

if [ ! -f "$KEY_SECRET_LOOKUP" ]; then
    echo "FATAL: Gateway lookup signing key not found at $KEY_SECRET_LOOKUP" >&2
    echo "       Mount it as a Docker secret: secrets.gateway-signing-key-lookup" >&2
    exit 1
fi

if [ ! -f "$HMAC_SECRET" ]; then
    echo "FATAL: Control-plane HMAC secret not found at $HMAC_SECRET" >&2
    echo "       Mount it as a Docker secret: secrets.control-plane-hmac" >&2
    exit 1
fi

# ── Runtime JWKS generation ──────────────────────────────────────────────────
# Build the JWKS document from the three injected private keys and write it
# to /tmp/jwks.json (served by the nginx alias directive), one kid-distinguished
# entry per key so a verifier resolves the right public key by kid.
# /tmp is a tmpfs mount so this write does not touch the read-only rootfs.
if ! python3 /usr/local/bin/gen_jwks.py /tmp/jwks.json \
    "backend-v1:$KEY_SECRET_BACKEND" \
    "admin-v1:$KEY_SECRET_ADMIN" \
    "lookup-v1:$KEY_SECRET_LOOKUP"; then
    echo "FATAL: JWKS generation failed" >&2
    exit 1
fi
echo "JWKS generated at /tmp/jwks.json"

# ── Route persistence directory ──────────────────────────────────────────────
# control_plane.lua persists accepted route updates here so routing can be
# reloaded after a restart (init_by_lua_block reads it at startup). nginx
# workers run as 'nobody', but this path is a named volume that is owned by
# root, so make it writable by the worker user. Runs as root before nginx
# drops privileges; CHOWN capability is granted in docker-compose.
ROUTES_DIR=/var/cache/pqc-gw/routes
mkdir -p "$ROUTES_DIR"
chown -R nobody:nogroup "$ROUTES_DIR" 2>/dev/null || \
    echo "WARN: could not chown $ROUTES_DIR, route persistence may be disabled" >&2

# ── Reload watcher ────────────────────────────────────────────────────────────
# crl-renewer touches /signals/reload-nginx after regenerating the CRL so the
# gateway picks up the refresh at the TLS layer (ssl_crl is only re-read on
# reload). Poll its mtime rather than inotifywait (not installed in this image
# and not worth a new package dependency just for this). State lives under
# /tmp (tmpfs) since the rootfs is read-only. Runs in the background so nginx
# stays PID 1 for correct signal handling.
RELOAD_SIGNAL="${NGINX_RELOAD_SIGNAL:-/signals/reload-nginx}"
RELOAD_POLL_INTERVAL="${NGINX_RELOAD_POLL_INTERVAL:-5}"
RELOAD_STATE=/tmp/.reload-nginx-last-mtime

(
    # Wait for the master to write its pid before attempting any reload,
    # otherwise an early CRL-regen signal (e.g. crl-renewer's startup run)
    # could race nginx -s reload against the master not yet being up.
    while [ ! -f /run/nginx.pid ]; do sleep 1; done

    last_mtime=0
    if [ -f "$RELOAD_STATE" ]; then
        last_mtime=$(cat "$RELOAD_STATE" 2>/dev/null || echo 0)
    fi
    while true; do
        sleep "$RELOAD_POLL_INTERVAL"
        if [ -f "$RELOAD_SIGNAL" ]; then
            mtime=$(stat -c %Y "$RELOAD_SIGNAL" 2>/dev/null || echo "$last_mtime")
            if [ "$mtime" != "$last_mtime" ]; then
                last_mtime="$mtime"
                echo "$last_mtime" > "$RELOAD_STATE"
                echo "[reload-watcher] detected updated $RELOAD_SIGNAL, validating config..."
                if nginx -t 2>&1; then
                    if nginx -s reload 2>&1; then
                        echo "[reload-watcher] nginx reloaded successfully"
                    else
                        echo "[reload-watcher] ERROR: nginx -s reload failed" >&2
                    fi
                else
                    echo "[reload-watcher] ERROR: nginx -t failed, skipping reload" >&2
                fi
            fi
        fi
    done
) &

exec /usr/sbin/nginx -g "daemon off;"
