#!/bin/bash
# =============================================================
# PQC-GW CRL Renewal Script, ML-DSA-65 PKI
# eIDAS Art. 24(2)(h) | ETSI EN 319 411-1 §6.2.4 | NIS2 Art. 21(2)(d)
# =============================================================
#
# Generates fresh CRLs for the ML-DSA-65 PKI chain (root + intermediate),
# combines them into a single file for Nginx, and reloads.
#
# Designed for cron execution:
#   0 3 * * * /usr/local/bin/pqc-crl-renew.sh
#
# eIDAS compliance:
#   - Intermediate CRL: renewed daily (validity = 7 days)
#   - Root CRL: renewed every 90 days (validity = 180 days)
#   - Combined CRL: always includes latest from both CAs (root + intermediate)
#
# Exit codes:
#   0 = success
#   1 = intermediate CRL generation failed
#   2 = root CRL generation failed (non-fatal if not due)
#   3 = nginx reload failed
#   4 = CRL verification failed
# =============================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────
PKI_BASE="/etc/pki/pqc-ca"
OPENSSL="/opt/openssl/bin/openssl"
NGINX="/usr/sbin/nginx"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"
LOG_FILE="${CRL_LOG_FILE:-/var/log/pqc-gw/crl-renewal.log}"
LOCK_FILE="/var/run/pqc-crl-renew.lock"

# PQ (ML-DSA-65) PKI paths
PQ_INT_DIR="${PKI_BASE}/intermediate"
PQ_INT_CNF="${PQ_INT_DIR}/openssl-intermediate.cnf"
PQ_INT_CRL="${PQ_INT_DIR}/crl/intermediate-ca.crl"
PQ_ROOT_DIR="${PKI_BASE}/root"
PQ_ROOT_CNF="${PQ_ROOT_DIR}/openssl-root.cnf"
PQ_ROOT_CRL="${PQ_ROOT_DIR}/crl/root-ca.crl"

# Combined output
HYBRID_CRL="${PKI_BASE}/hybrid-combined-crl.pem"

# Root CRL renewal interval (days)
ROOT_CRL_INTERVAL=90

# ── Logging ───────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
    local level="$1"; shift
    local msg
    msg="[$(date -Iseconds)] [$level] $*"
    echo "$msg"
    # stdout already carries this line (docker logs), so a failed file write is
    # not a total loss, but it silently makes crl-renewal.log diverge from what
    # actually happened. Warn once rather than never.
    if ! echo "$msg" >> "$LOG_FILE" 2>/dev/null; then
        if [ -z "${LOG_WRITE_WARNED:-}" ]; then
            LOG_WRITE_WARNED=1
            echo "[crl-renew] WARN: cannot write $LOG_FILE, file log will be incomplete" >&2
        fi
    fi
}

# ── Lock (prevent concurrent execution) ──────────────────────
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log "ERROR" "Another instance is running (PID $pid). Exiting."
        exit 0
    fi
    log "WARN" "Stale lock file found. Removing."
    rm -f "$LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"

# ── Helper: check if Root CRL needs renewal ──────────────────
root_crl_needs_renewal() {
    local crl_file="$1"
    if [ ! -f "$crl_file" ]; then
        return 0  # needs renewal (doesn't exist)
    fi
    local next_update
    next_update=$($OPENSSL crl -in "$crl_file" -noout -nextupdate 2>/dev/null | cut -d= -f2)
    if [ -z "$next_update" ]; then
        return 0  # can't parse, renew
    fi
    local next_epoch
    next_epoch=$(date -d "$next_update" +%s 2>/dev/null || echo 0)
    local now_epoch
    now_epoch=$(date +%s)
    local days_until=$(( (next_epoch - now_epoch) / 86400 ))
    # Renew if less than ROOT_CRL_INTERVAL days remaining (50% of validity)
    if [ "$days_until" -lt "$ROOT_CRL_INTERVAL" ]; then
        return 0
    fi
    return 1
}

# ── Helper: verify a CRL ─────────────────────────────────────
verify_crl() {
    local crl_file="$1"
    # $2 (the CA cert path) is accepted for call-site clarity but currently
    # unused: this check validates CRL format + nextUpdate, not the signature.
    local label="$3"

    if ! $OPENSSL crl -in "$crl_file" -noout 2>/dev/null; then
        log "ERROR" "CRL verification failed for $label: invalid CRL format"
        return 1
    fi

    local next_update
    next_update=$($OPENSSL crl -in "$crl_file" -noout -nextupdate 2>/dev/null | cut -d= -f2)
    if [ -z "$next_update" ]; then
        log "ERROR" "CRL verification failed for $label: cannot read nextUpdate"
        return 1
    fi

    log "INFO" "$label CRL valid until: $next_update"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
log "INFO" "=== CRL renewal started ==="
ERRORS=0

# ── Step 1: Intermediate CRLs (daily) ────────────────────────
log "INFO" "Generating PQ Intermediate CRL..."
if $OPENSSL ca -gencrl -config "$PQ_INT_CNF" -out "$PQ_INT_CRL" 2>>"$LOG_FILE"; then
    verify_crl "$PQ_INT_CRL" "$PQ_INT_DIR/certs/intermediate-ca.crt" "PQ-Intermediate" || ERRORS=$((ERRORS + 1))
else
    log "ERROR" "Failed to generate PQ Intermediate CRL"
    ERRORS=$((ERRORS + 1))
fi

# ── Step 2: Root CRLs (periodic, every ROOT_CRL_INTERVAL days)
if root_crl_needs_renewal "$PQ_ROOT_CRL"; then
    log "INFO" "Generating PQ Root CRL (periodic renewal)..."
    if $OPENSSL ca -gencrl -config "$PQ_ROOT_CNF" -out "$PQ_ROOT_CRL" 2>>"$LOG_FILE"; then
        verify_crl "$PQ_ROOT_CRL" "$PQ_ROOT_DIR/certs/root-ca.crt" "PQ-Root" || ERRORS=$((ERRORS + 1))
    else
        log "ERROR" "Failed to generate PQ Root CRL"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "INFO" "PQ Root CRL still valid, skipping renewal"
fi

# ── Step 3: Combine CRLs ─────────────────────────────────────
log "INFO" "Combining CRLs..."
TEMP_CRL=$(mktemp)
cat "$PQ_INT_CRL" "$PQ_ROOT_CRL" > "$TEMP_CRL" 2>>"$LOG_FILE"
CRL_COUNT=$(grep -c "BEGIN X509 CRL" "$TEMP_CRL" || true)

if [ "$CRL_COUNT" -lt 2 ]; then
    log "ERROR" "Combined CRL has only $CRL_COUNT entries, PQ CRLs required"
    rm -f "$TEMP_CRL"
    ERRORS=$((ERRORS + 1))
else
    mv "$TEMP_CRL" "$HYBRID_CRL"
    chmod 644 "$HYBRID_CRL"
    log "INFO" "Hybrid combined CRL updated: $CRL_COUNT CRL(s)"
fi

# ── Step 4: Also update legacy combined-crl.pem for PQ-only ──
cat "$PQ_INT_CRL" "$PQ_ROOT_CRL" > "${PKI_BASE}/combined-crl.pem" 2>>"$LOG_FILE"

# ── Step 4b: Sync PKI distribution for HTTP serving ──────────
PKI_DIST="/var/www/pki"
if [ -d "$PKI_DIST" ]; then
    log "INFO" "Syncing CRLs to PKI distribution directory..."
    cp "$PQ_INT_CRL" "$PKI_DIST/intermediate-ca.crl" 2>>"$LOG_FILE"
    cp "$PQ_ROOT_CRL" "$PKI_DIST/root-ca.crl" 2>>"$LOG_FILE"
    chmod 644 "$PKI_DIST"/*.crl
    log "INFO" "PKI distribution directory updated"
fi

# ── Step 5: Reload Nginx ──────────────────────────────────────
# Nginx may run in a separate container (gateway). If the binary isn't local,
# or no local nginx.conf is mounted (e.g. the crl-renewer container, which
# bundles the nginx binary from the shared base image but never mounts a
# config, it only ever runs this script), skip the reload here, the caller
# is responsible for triggering it externally.
if [ "$ERRORS" -eq 0 ]; then
    if ! command -v "$NGINX" >/dev/null 2>&1 && [ ! -x "$NGINX" ]; then
        log "INFO" "Nginx not found at $NGINX, skipping local reload (reload gateway container externally)"
    elif [ ! -f "$NGINX_CONF" ]; then
        log "INFO" "No local Nginx config at $NGINX_CONF, skipping local reload (reload gateway container externally)"
    else
        log "INFO" "Reloading Nginx to apply new CRLs..."
        if $NGINX -t 2>>"$LOG_FILE" && $NGINX -s reload 2>>"$LOG_FILE"; then
            log "INFO" "Nginx reloaded successfully"
        else
            log "ERROR" "Nginx reload failed!"
            ERRORS=$((ERRORS + 1))
        fi
    fi
else
    log "WARN" "Skipping Nginx reload due to $ERRORS error(s)"
fi

# ── Summary ───────────────────────────────────────────────────
if [ "$ERRORS" -eq 0 ]; then
    log "INFO" "=== CRL renewal completed successfully ==="
    exit 0
else
    log "ERROR" "=== CRL renewal completed with $ERRORS error(s) ==="
    exit 1
fi
