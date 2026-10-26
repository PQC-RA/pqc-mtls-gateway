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
PQ_ROOT_KEY="${PQ_ROOT_DIR}/private/root-ca.key"

# Combined output
HYBRID_CRL="${PKI_BASE}/hybrid-combined-crl.pem"

# Root CRL renewal interval (days)
ROOT_CRL_INTERVAL=90

# How close to expiry the root CRL may get before an unsignable root CRL stops
# being a notice and becomes an outage: an expired CRL inside the combined file
# makes nginx reject the chain at the handshake, so it has to be shouted about
# well before that. 14 days inside a 180-day CRL whose renewal triggers at 90
# means 76 days of ordinary notices went unactioned first.
ROOT_CRL_ALARM_DAYS=14

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
PENDING_TMP=""
cleanup() {
    rm -f "$LOCK_FILE"
    # Must be an `if`, not `[ ] && rm`: under set -e a false && list as the
    # trap's last command replaces the script's `exit 0` with status 1.
    if [ -n "$PENDING_TMP" ]; then rm -f "$PENDING_TMP"; fi
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

# ── Helper: can this process sign with the root CA key? ────
# Is the root CA key present and readable here? It is NOT, by design, in the
# crl-renewer container: docker-compose.yml masks root/private with an empty
# directory so a compromise of this container cannot reach the trust anchor.
# Root CRL generation is therefore an offline operation, performed where the key
# actually lives. Answered by attempting the read rather than inferred from a
# hostname or an env var, because the question is "can THIS process sign with
# the root key", and only the filesystem answers that.
root_key_available() {
    [ -s "$PQ_ROOT_KEY" ] && [ -r "$PQ_ROOT_KEY" ]
}

# Days until a CRL's nextUpdate; negative once it has expired. Prints nothing
# and fails if the file is missing or unparseable, so callers must handle that.
crl_days_left() {
    local crl_file="$1" next_update next_epoch
    [ -f "$crl_file" ] || return 1
    next_update=$($OPENSSL crl -in "$crl_file" -noout -nextupdate 2>/dev/null | cut -d= -f2)
    [ -n "$next_update" ] || return 1
    next_epoch=$(date -d "$next_update" +%s 2>/dev/null || echo 0)
    [ "$next_epoch" -gt 0 ] || return 1
    echo $(( (next_epoch - $(date +%s)) / 86400 ))
}

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

# ── Helper: publish a file atomically ────────────────────────
# publish_atomic <dest> <src>...: concatenate the sources into a temp file in
# the DESTINATION's directory, make it readable, then rename(2) it over dest.
# The gateway re-reads hybrid-combined-crl.pem every second and nginx reads it
# on every reload, so it must never be observable half-written, empty or 0600.
# The temp file has to live beside dest: mktemp's default /tmp is the
# container's overlayfs while /etc/pki/pqc-ca is a different filesystem, and a
# cross-filesystem mv is a copy into the published name, not a rename.
# The gateway mounts the directory (not the file), so the new inode is visible.
publish_atomic() {
    local dest="$1"; shift
    local tmp
    tmp=$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX") || {
        log "ERROR" "cannot create temp file beside $dest"; return 1; }
    PENDING_TMP="$tmp"
    if ! cat "$@" > "$tmp" 2>>"$LOG_FILE"; then
        log "ERROR" "failed to write $tmp"; rm -f "$tmp"; PENDING_TMP=""; return 1
    fi
    chmod 644 "$tmp"
    if ! mv -f "$tmp" "$dest"; then
        log "ERROR" "failed to rename $tmp over $dest"; rm -f "$tmp"; PENDING_TMP=""; return 1
    fi
    PENDING_TMP=""
}

# ── Helper: generate a CRL without touching the published file until it parses ──
# gen_crl_atomic <ca.cnf> <dest.crl> <ca.crt> <label>
gen_crl_atomic() {
    local cnf="$1" dest="$2" cacrt="$3" label="$4" tmp
    tmp=$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX") || {
        log "ERROR" "cannot create temp file beside $dest"; return 1; }
    PENDING_TMP="$tmp"
    if ! $OPENSSL ca -gencrl -config "$cnf" -out "$tmp" 2>>"$LOG_FILE"; then
        log "ERROR" "Failed to generate $label CRL"; rm -f "$tmp"; PENDING_TMP=""; return 1
    fi
    if ! verify_crl "$tmp" "$cacrt" "$label"; then
        rm -f "$tmp"; PENDING_TMP=""; return 1
    fi
    chmod 644 "$tmp"
    mv -f "$tmp" "$dest" || { log "ERROR" "failed to rename $tmp over $dest"; rm -f "$tmp"; PENDING_TMP=""; return 1; }
    PENDING_TMP=""
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
log "INFO" "=== CRL renewal started ==="
ERRORS=0

# ── Step 1: Intermediate CRLs (daily) ────────────────────────
log "INFO" "Generating PQ Intermediate CRL..."
gen_crl_atomic "$PQ_INT_CNF" "$PQ_INT_CRL" "$PQ_INT_DIR/certs/intermediate-ca.crt" "PQ-Intermediate" \
    || ERRORS=$((ERRORS + 1))

# ── Step 2: Root CRLs (periodic, every ROOT_CRL_INTERVAL days)
if root_crl_needs_renewal "$PQ_ROOT_CRL"; then
    if root_key_available; then
        log "INFO" "Generating PQ Root CRL (periodic renewal)..."
        gen_crl_atomic "$PQ_ROOT_CNF" "$PQ_ROOT_CRL" "$PQ_ROOT_DIR/certs/root-ca.crt" "PQ-Root" \
            || ERRORS=$((ERRORS + 1))
    else
        # Expected in the crl-renewer container: root/private is masked, so
        # signing a root CRL is impossible here and that is the whole point.
        # Deliberately does NOT increment ERRORS. ERRORS gates the nginx reload
        # in Step 5 and makes the entrypoint log a failed run, so counting a
        # key this container is not allowed to hold would stop the INTERMEDIATE
        # CRL, which was generated successfully above, from reaching the data
        # plane. The root key being absent is the design working; a silent skip
        # would not be.
        ROOT_DAYS=$(crl_days_left "$PQ_ROOT_CRL" || echo "")
        log "WARN" "PQ Root CRL is due for renewal but the root CA key is not readable here" \
                   "(root/private is masked in this container by design)." \
                   "Regenerate it where the key lives:" \
                   "$OPENSSL ca -gencrl -config $PQ_ROOT_CNF -out $PQ_ROOT_CRL"
        if [ -n "$ROOT_DAYS" ]; then
            log "WARN" "PQ Root CRL expires in ${ROOT_DAYS} day(s)"
            if [ "$ROOT_DAYS" -lt "$ROOT_CRL_ALARM_DAYS" ]; then
                # Past this point it stops being an operational to-do: an
                # expired root CRL in the combined file fails chain validation
                # at the TLS handshake, i.e. every client is refused.
                log "ERROR" "PQ Root CRL expires in ${ROOT_DAYS} day(s) and cannot be renewed from this container." \
                            "Once it expires the combined CRL fails chain validation and client authentication stops."
            fi
        else
            log "ERROR" "PQ Root CRL at $PQ_ROOT_CRL is missing or unparseable and cannot be renewed from this container"
        fi
    fi
else
    log "INFO" "PQ Root CRL still valid, skipping renewal"
fi

# ── Step 3: Combine CRLs ─────────────────────────────────────
log "INFO" "Combining CRLs..."
# Both inputs were parsed when they were generated (or on a previous run), but
# re-check here: the combined file is what the edge enforces, and a component
# that no longer parses must stop publication rather than ship inside it.
if verify_crl "$PQ_INT_CRL" "" "PQ-Intermediate (combine input)" \
   && verify_crl "$PQ_ROOT_CRL" "" "PQ-Root (combine input)"; then
    publish_atomic "$HYBRID_CRL" "$PQ_INT_CRL" "$PQ_ROOT_CRL" || ERRORS=$((ERRORS + 1))
    CRL_COUNT=$(grep -c "BEGIN X509 CRL" "$HYBRID_CRL" || true)
    if [ "$CRL_COUNT" -lt 2 ]; then
        log "ERROR" "Combined CRL has only $CRL_COUNT entries, PQ CRLs required"
        ERRORS=$((ERRORS + 1))
    else
        log "INFO" "Hybrid combined CRL updated: $CRL_COUNT CRL(s)"
    fi
else
    log "ERROR" "A CRL component does not parse; combined CRL NOT replaced"
    ERRORS=$((ERRORS + 1))
fi

# ── Step 4: Also update legacy combined-crl.pem for PQ-only ──
publish_atomic "${PKI_BASE}/combined-crl.pem" "$PQ_INT_CRL" "$PQ_ROOT_CRL" || ERRORS=$((ERRORS + 1))

# ── Step 4b: Sync PKI distribution for HTTP serving ──────────
PKI_DIST="/var/www/pki"
if [ -d "$PKI_DIST" ]; then
    log "INFO" "Syncing CRLs to PKI distribution directory..."
    publish_atomic "$PKI_DIST/intermediate-ca.crl" "$PQ_INT_CRL" || ERRORS=$((ERRORS + 1))
    publish_atomic "$PKI_DIST/root-ca.crl" "$PQ_ROOT_CRL" || ERRORS=$((ERRORS + 1))
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
