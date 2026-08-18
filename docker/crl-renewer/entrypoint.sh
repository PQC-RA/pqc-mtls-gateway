#!/bin/bash
# Container-native CRL renewer.
#
#   * Regenerates the hybrid CRL on a daily cycle (eIDAS weekly-CRL margin).
#   * Reacts on-demand: when the management-api revokes a certificate it touches
#     $CRL_RENEW_SIGNAL_FILE on the shared /signals volume. We detect the newer
#     sentinel and regenerate promptly.
#
# This is the ONLY component that holds broad CA write access + the nginx-reload
# path, which is exactly what lets the web-facing management-api run unprivileged
# with a minimal (db/ + issued/) writable surface and a read-only signing key.

set -uo pipefail   # NB: no -e, a failed renewal must not kill the watch loop.

SIGNAL_FILE="${CRL_RENEW_SIGNAL_FILE:-/signals/renew-crl}"
RELOAD_SIGNAL="${NGINX_RELOAD_SIGNAL:-/signals/reload-nginx}"
POLL_INTERVAL="${CRL_POLL_INTERVAL:-15}"        # seconds between sentinel checks
DAILY_INTERVAL="${CRL_DAILY_INTERVAL:-86400}"   # seconds between unconditional runs
MARKER="/tmp/.crl-last-run"

mkdir -p "$(dirname "$SIGNAL_FILE")" "$(dirname "$RELOAD_SIGNAL")" 2>/dev/null || true

run_renew() {
  local reason="$1"
  echo "[crl-renewer] ($reason) running CRL renewal at $(date -Iseconds)"
  if /usr/local/bin/pqc-crl-renew.sh; then
    echo "[crl-renewer] CRL renewal succeeded"
  else
    echo "[crl-renewer] WARN: CRL renewal script exited non-zero" >&2
  fi
  # Signal the gateway container to reload nginx so the refreshed CRL takes
  # effect at the TLS layer (the Lua CRL poller also picks it up independently).
  # Non-fatal: the Lua CRL poller picks the new CRL up independently, so
  # revocation still takes effect per-request. But losing this signal silently
  # means the handshake-layer ssl_crl keeps serving the OLD CRL until the next
  # reload, and one of two "independent" revocation paths is quietly dead --
  # which is exactly how a revocation gap goes unnoticed.
  if ! touch "$RELOAD_SIGNAL" 2>/dev/null; then
    echo "[crl-renewer] WARN: could not write reload signal $RELOAD_SIGNAL," \
         "handshake-layer CRL will not refresh until the next gateway reload" >&2
  fi
  touch "$MARKER"
}

echo "[crl-renewer] starting; watching $SIGNAL_FILE (poll ${POLL_INTERVAL}s, daily ${DAILY_INTERVAL}s)"
run_renew "startup"
last_daily=$SECONDS

while true; do
  sleep "$POLL_INTERVAL"

  # On-demand: a revocation signal newer than our last renewal.
  if [ -f "$SIGNAL_FILE" ] && [ "$SIGNAL_FILE" -nt "$MARKER" ]; then
    run_renew "revocation-signal"
    last_daily=$SECONDS
    continue
  fi

  # Periodic: unconditional daily renewal.
  if [ $(( SECONDS - last_daily )) -ge "$DAILY_INTERVAL" ]; then
    run_renew "daily"
    last_daily=$SECONDS
  fi
done
