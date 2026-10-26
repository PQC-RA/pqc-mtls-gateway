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
# Seconds between sentinel checks. This interval is the largest single term in
# revoke-to-refusal time: at the previous 15 s, waiting for the next check was
# most of the time between a revocation and its enforcement. A check is one
# stat(2) of the sentinel, so 1 s costs about one wakeup per second.
# Revocations arriving within one interval coalesce into a single CRL
# regeneration, so a burst of revocations cannot cause more than one
# regeneration (and one gateway reload signal) per interval.
POLL_INTERVAL="${CRL_POLL_INTERVAL:-1}"
DAILY_INTERVAL="${CRL_DAILY_INTERVAL:-86400}"   # seconds between unconditional runs
# MARKER's mtime is the time the last SUCCESSFUL renewal STARTED. It is stamped
# before the run (as MARKER.next) and only promoted on success, so:
#   * a revocation that lands while a renewal is running is newer than the
#     marker and triggers another run (previously the marker was touched at
#     the END, so such a revocation was older than it and stayed unenforced
#     until the next revocation or the daily run);
#   * a failed renewal leaves the marker where it was, so the next check
#     retries instead of silently giving up on the pending revocation.
MARKER="/tmp/.crl-last-run"

mkdir -p "$(dirname "$SIGNAL_FILE")" "$(dirname "$RELOAD_SIGNAL")" 2>/dev/null || true

# Retry backoff after a failed run: 1 s doubling to 60 s. Without it a
# persistent failure (e.g. an unwritable distribution volume after the edge
# CRL was already published) would re-sign the CRL every POLL_INTERVAL forever.
RETRY_MIN=1
RETRY_MAX=60
retry_wait=0       # 0 = no retry pending
retry_at=0

# The CRL files the gateway reads (ssl_crl and the Lua pollers).
CRL_FILES="${CRL_PUBLISHED_FILES:-/etc/pki/pqc-ca/hybrid-combined-crl.pem /etc/pki/pqc-ca/combined-crl.pem}"
crl_state() { cat $CRL_FILES 2>/dev/null | cksum; }
signal_pending=0   # a changed CRL whose reload signal could not be written yet

send_reload_signal() {
  if touch "$RELOAD_SIGNAL" 2>/dev/null; then
    signal_pending=0
  else
    signal_pending=1
    echo "[crl-renewer] WARN: could not write reload signal $RELOAD_SIGNAL," \
         "handshake-layer CRL will not refresh until it can; retrying" >&2
  fi
}

run_renew() {
  local reason="$1" ok=1 before
  before=$(crl_state)
  touch "$MARKER.next"
  echo "[crl-renewer] ($reason) running CRL renewal at $(date -Iseconds)"
  if /usr/local/bin/pqc-crl-renew.sh; then
    echo "[crl-renewer] CRL renewal succeeded"
  else
    ok=0
    echo "[crl-renewer] WARN: CRL renewal script exited non-zero" >&2
  fi
  # Signal the gateway container to reload nginx so the refreshed CRL takes
  # effect at the TLS layer (the Lua CRL poller also picks it up independently).
  # Sent whenever a published CRL file changed, on failure too: the script
  # publishes each file atomically, so a partially failed run may still have
  # replaced the combined CRL. Losing this signal silently would leave the
  # handshake-layer ssl_crl on the OLD CRL until the next reload, and one of two
  # "independent" revocation paths quietly dead. NOT sent when nothing changed:
  # a reload is not free, old workers close what they hold after
  # worker_shutdown_timeout, so a renewer failing every minute would otherwise
  # cut every long-lived session (edge links) every minute.
  if [ "$(crl_state)" != "$before" ] || [ "$signal_pending" = 1 ]; then
    send_reload_signal
  else
    echo "[crl-renewer] published CRLs unchanged, no gateway reload"
  fi
  if [ "$ok" = 1 ]; then
    mv -f "$MARKER.next" "$MARKER"
    retry_wait=0
  else
    rm -f "$MARKER.next"
    if [ "$retry_wait" -eq 0 ]; then retry_wait=$RETRY_MIN
    else retry_wait=$(( retry_wait * 2 )); [ "$retry_wait" -gt "$RETRY_MAX" ] && retry_wait=$RETRY_MAX
    fi
    retry_at=$(( SECONDS + retry_wait ))
    echo "[crl-renewer] WARN: will retry in ${retry_wait}s" >&2
  fi
}

echo "[crl-renewer] starting; watching $SIGNAL_FILE (poll ${POLL_INTERVAL}s, daily ${DAILY_INTERVAL}s)"
run_renew "startup"
last_daily=$SECONDS

while true; do
  sleep "$POLL_INTERVAL"
  [ "$signal_pending" = 1 ] && send_reload_signal

  # A failed run is retried (with backoff) whatever triggered it.
  if [ "$retry_wait" -gt 0 ]; then
    if [ "$SECONDS" -ge "$retry_at" ]; then
      run_renew "retry"
      last_daily=$SECONDS
    fi
    continue
  fi

  # On-demand: a revocation signal newer than the start of the last successful
  # renewal (see MARKER above).
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
