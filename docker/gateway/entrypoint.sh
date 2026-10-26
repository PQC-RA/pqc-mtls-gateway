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
                # The signal counts as handled only once the reload succeeded: a
                # failed test or reload is retried every poll (reported once), so
                # a new CRL cannot stay unloaded until the next signal.
                if nginx -t -q 2>/dev/null && nginx -s reload 2>/dev/null; then
                    last_mtime="$mtime"
                    echo "$last_mtime" > "$RELOAD_STATE"
                    reload_failed_for=
                    echo "[reload-watcher] $RELOAD_SIGNAL updated: nginx reloaded"
                elif [ "${reload_failed_for:-}" != "$mtime" ]; then
                    reload_failed_for="$mtime"
                    echo "[reload-watcher] ERROR: $RELOAD_SIGNAL updated but nginx did not reload; retrying every ${RELOAD_POLL_INTERVAL}s" >&2
                    nginx -t 2>&1 | tail -3 >&2 || true
                fi
            fi
        fi
    done
) &

# ── Log rotation ──────────────────────────────────────────────────────────────
# /var/log/nginx is a named volume (so logs survive container recreation), which
# means nothing else bounds its size. No logrotate in the image and no sidecar
# for it, so rotate here: every LOG_ROTATE_CHECK_S seconds, any *.log larger
# than LOG_ROTATE_MAX_BYTES is renamed to .1, the master reopens its log files
# (one `nginx -s reopen` per pass), and only then is .1 compressed, so gzip
# never reads a file nginx is still writing. LOG_ROTATE_KEEP compressed
# generations are kept. Worst case per log file ~ MAX_BYTES * (KEEP + 1)
# (compressed generations are usually far smaller).
LOG_DIR=/var/log/nginx
LOG_ROTATE_MAX_BYTES="${LOG_ROTATE_MAX_BYTES:-10485760}"   # 10 MiB
LOG_ROTATE_KEEP="${LOG_ROTATE_KEEP:-5}"
LOG_ROTATE_CHECK_S="${LOG_ROTATE_CHECK_S:-60}"
(
    # Each step handles its own failure; errexit inherited from the top of this
    # script would end the loop silently on the first unexpected status.
    set +e
    while [ ! -f /run/nginx.pid ]; do sleep 1; done
    while true; do
        sleep "$LOG_ROTATE_CHECK_S"
        # Finish an earlier pass whose reopen failed: nginx may still be writing
        # into the uncompressed .1, so reopen first and compress only after.
        pending=$(ls "$LOG_DIR"/*.log.1 2>/dev/null)
        if [ -n "$pending" ]; then
            if nginx -s reopen 2>&1; then
                for p in $pending; do gzip -f "$p" || echo "[log-rotate] WARN: gzip failed for $p" >&2; done
                echo "[log-rotate] completed pending rotation:" $pending
            else
                echo "[log-rotate] ERROR: nginx -s reopen still failing; pending:" $pending >&2
            fi
        fi
        rotated=""
        for f in "$LOG_DIR"/*.log; do
            [ -f "$f" ] || continue
            # Never overwrite an uncompressed .1 that is still pending.
            [ -f "$f.1" ] && continue
            size=$(stat -c %s "$f" 2>/dev/null || echo 0)
            [ "$size" -gt "$LOG_ROTATE_MAX_BYTES" ] || continue
            rm -f "$f.$LOG_ROTATE_KEEP.gz"
            i=$((LOG_ROTATE_KEEP - 1))
            while [ "$i" -ge 1 ]; do
                [ -f "$f.$i.gz" ] && mv -f "$f.$i.gz" "$f.$((i + 1)).gz"
                i=$((i - 1))
            done
            mv -f "$f" "$f.1"
            rotated="$rotated $f"
        done
        [ -n "$rotated" ] || continue
        if nginx -s reopen 2>&1; then
            for f in $rotated; do
                gzip -f "$f.1" || echo "[log-rotate] WARN: gzip failed for $f.1" >&2
            done
            echo "[log-rotate] rotated:$rotated"
        else
            # Without a reopen nginx keeps writing into the renamed .1 file;
            # leave it uncompressed so no log line is lost, and say so.
            echo "[log-rotate] ERROR: nginx -s reopen failed; rotated files left uncompressed:$rotated" >&2
        fi
    done
) &

exec /usr/sbin/nginx -g "daemon off;"
