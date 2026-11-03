#!/usr/bin/env bash
# migrate-ca-state.sh: move a running deployment's intermediate CA from the
# shared CA tree into the custodian's own layout, and back (ADR-024).
#
#   migrate-ca-state.sh forward [--from DIR]   copy key, state, root CRL and the
#                                              OCSP key into the layout of
#                                              scripts/lib/ca-layout.sh, verify
#                                              every copy against a SHA-256
#                                              manifest. Copies, never moves.
#   migrate-ca-state.sh verify                 re-check the copies against the
#                                              manifest
#   migrate-ca-state.sh retire [--from DIR]    after the readers have moved:
#                                              rename the old intermediate/, ocsp/
#                                              and top-level CRL and chain files
#                                              so a tool still pointed at them
#                                              fails instead of using stale data
#   migrate-ca-state.sh reverse [--from DIR]   rollback: copy the state back
#                                              (index, serial, crlnumber, issued/,
#                                              the custodian's JSON state) and the
#                                              latest published CRLs, check that
#                                              nothing was un-revoked, then set
#                                              the new layout aside
#
# DIR defaults to /etc/pki/pqc-ca. Run as root on the host, with the custodian
# and the CRL renewer stopped: forward and reverse refuse otherwise, and every
# subcommand that touches the new state takes the custodian's writer lock.
# Nothing is deleted. What is replaced is renamed with a timestamp.
#
# The ADR-024 runbook: stop management-api, the renewer and the custodian;
# forward; start the new custodian (it issues CRL N+1); check N+1; move the
# readers; retire. Rollback at any point after forward: stop the new
# containers; reverse; start the old ones.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/lib/ca-layout.sh
. "$HERE/lib/ca-layout.sh"

OPENSSL="${OPENSSL_BIN:-/opt/openssl/bin/openssl}"
[ -x "$OPENSSL" ] || OPENSSL=$(command -v openssl)
export OPENSSL_CONF=/dev/null
CUSTODIAN_CONTAINER="${CUSTODIAN_CONTAINER:-pqc-ca-custodian}"
RENEWER_CONTAINER="${RENEWER_CONTAINER:-pqc-crl-renewer}"
APP_UID="${APP_UID:-1001}"   # owner of db/ and issued/ in the old tree (setup-pki.sh)
APP_GID="${APP_GID:-1001}"
MANIFEST="$CA_ROOT/migration.manifest"
TS=$(date -u +%Y%m%dT%H%M%SZ)

die() { echo "ERROR: $*" >&2; exit 1; }
say() { echo "==> $*"; }

cmd=${1:-}; shift || true
FROM=/etc/pki/pqc-ca
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM=${2:?--from needs a directory}; shift 2 ;;
        *) die "unknown argument $1" ;;
    esac
done
INT="$FROM/intermediate"

[ "$(id -u)" = 0 ] || die "run as root"

# --- guards -------------------------------------------------------------------
container_running() {
    command -v docker >/dev/null 2>&1 || return 1
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]
}
refuse_if_writers_run() {
    local c
    for c in "$CUSTODIAN_CONTAINER" "$RENEWER_CONTAINER"; do
        container_running "$c" && die "$c is running; stop it first (it writes CA state)"
    done
    return 0
}
# The custodian holds this lock while it runs; holding it here keeps it out.
take_writer_lock() {
    [ -d "$CA_STATE_DIR" ] || return 0
    exec 9>>"$CA_WRITER_LOCK"
    flock -n 9 || die "the custodian holds $CA_WRITER_LOCK: it is running against $CA_STATE_DIR"
}

# --- helpers ------------------------------------------------------------------
# The public key of a private key (pkey) or of a certificate (x509), base64.
pub_of() {
    if [ "$1" = pkey ]; then "$OPENSSL" pkey -in "$2" -pubout 2>/dev/null
    else "$OPENSSL" x509 -in "$2" -noout -pubkey 2>/dev/null; fi | sed '/^-----/d' | tr -d '\n'
}
crl_number() { "$OPENSSL" crl -in "$1" -noout -crlnumber | sed 's/^crlNumber=0x//'; }
crl_serials() { "$OPENSSL" crl -in "$1" -noout -text | sed -n 's/^ *Serial Number: *//p' | sort -u; }
crl_verify() { "$OPENSSL" crl -in "$1" -noout -CAfile "$2" 2>&1 | grep -q 'verify OK'; }
hex_gt() { [ $((16#$1)) -gt $((16#$2)) ]; }

# copy <src> <dst>, and record it in the manifest
copy() {
    install -D -m 0600 "$1" "$2"
    printf '%s  %s  %s\n' "$(sha256sum < "$1" | cut -d' ' -f1)" "$2" "$1" >> "$MANIFEST.new"
}

verify_manifest() {
    local want dst src bad=0 n=0
    [ -f "$MANIFEST" ] || die "no manifest at $MANIFEST; run forward first"
    while read -r want dst src; do
        n=$((n + 1))
        if [ ! -f "$dst" ]; then echo "  MISSING $dst"; bad=1; continue; fi
        [ "$(sha256sum < "$dst" | cut -d' ' -f1)" = "$want" ] || { echo "  CHANGED $dst (copy of $src)"; bad=1; }
    done < "$MANIFEST"
    [ "$bad" = 0 ] || return 1
    echo "    $n file(s) match the manifest"
}

# --- forward ------------------------------------------------------------------
forward() {
    refuse_if_writers_run
    say "checking the source tree $FROM"
    local f
    for f in "$INT/openssl-intermediate.cnf" "$INT/db/index.txt" "$INT/db/index.txt.attr" \
             "$INT/db/serial" "$INT/db/crlnumber" "$INT/certs/intermediate-ca.crt" \
             "$INT/private/intermediate-ca.key" "$INT/crl/intermediate-ca.crl" \
             "$FROM/root/certs/root-ca.crt" "$FROM/root/crl/root-ca.crl"; do
        [ -f "$f" ] || die "missing $f"
    done
    [ "$(pub_of pkey "$INT/private/intermediate-ca.key")" = "$(pub_of x509 "$INT/certs/intermediate-ca.crt")" ] \
        || die "the intermediate key does not match its certificate"
    crl_verify "$INT/crl/intermediate-ca.crl" "$INT/certs/intermediate-ca.crt" || die "intermediate CRL does not verify"
    crl_verify "$FROM/root/crl/root-ca.crl" "$FROM/root/certs/root-ca.crt" || die "root CRL does not verify"
    for f in "$CA_KEY_DIR" "$CA_STATE_DIR" "$CA_INBOX_DIR" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$OCSP_KEY_DIR"; do
        [ ! -d "$f" ] || [ -z "$(ls -A "$f")" ] || die "$f is not empty; a forward has been done already (reverse first)"
    done

    say "creating the layout"
    ca_layout_create
    : > "$MANIFEST.new"

    say "copying (nothing in $FROM changes)"
    copy "$INT/private/intermediate-ca.key" "$CA_KEY_FILE"
    for f in index.txt index.txt.attr serial crlnumber fingerprint-index.json idempotency.json lineage.json; do
        [ -f "$INT/db/$f" ] && copy "$INT/db/$f" "$CA_STATE_DIR/db/$f"
    done
    local n_issued=0
    for f in "$INT"/issued/*; do
        [ -f "$f" ] || continue
        copy "$f" "$CA_STATE_DIR/issued/$(basename "$f")"; n_issued=$((n_issued + 1))
    done
    copy "$INT/certs/intermediate-ca.crt" "$CA_STATE_DIR/certs/intermediate-ca.crt"
    copy "$FROM/root/certs/root-ca.crt" "$CA_STATE_DIR/certs/root-ca.crt"
    copy "$INT/crl/intermediate-ca.crl" "$CA_STATE_DIR/crl/intermediate-ca.crl"
    copy "$FROM/root/crl/root-ca.crl" "$CA_STATE_DIR/crl/root-ca.crl"
    copy "$FROM/root/crl/root-ca.crl" "$CA_INBOX_DIR/root-ca.crl"
    for f in ocsp-pq.key ocsp-pq.crt; do
        [ -f "$FROM/ocsp/$f" ] && copy "$FROM/ocsp/$f" "$OCSP_KEY_DIR/$f"
    done

    # The configuration names its own paths: point them at the new layout, and
    # check that both lines really changed (a sed that matches nothing succeeds).
    sed -e "s#^dir[[:space:]]*=.*#dir               = $CA_STATE_DIR#" \
        -e "s#^private_key[[:space:]]*=.*#private_key       = $CA_KEY_FILE#" \
        "$INT/openssl-intermediate.cnf" > "$CA_CNF_FILE"
    grep -qx "dir               = $CA_STATE_DIR" "$CA_CNF_FILE" || die "dir did not render into $CA_CNF_FILE"
    grep -qx "private_key       = $CA_KEY_FILE" "$CA_CNF_FILE" || die "private_key did not render into $CA_CNF_FILE"
    printf '%s  %s  %s\n' "$(sha256sum < "$CA_CNF_FILE" | cut -d' ' -f1)" "$CA_CNF_FILE" "$INT/openssl-intermediate.cnf (paths rewritten)" >> "$MANIFEST.new"

    ca_layout_file_perms
    mv "$MANIFEST.new" "$MANIFEST"; chmod 0600 "$MANIFEST"

    say "verifying"
    verify_manifest || die "a copy does not match its source"
    local a b
    for f in index.txt serial crlnumber; do
        a=$(wc -l < "$INT/db/$f"); b=$(wc -l < "$CA_STATE_DIR/db/$f")
        [ "$a" = "$b" ] || die "$f: $a lines in the source, $b in the copy"
    done
    [ "$(ls "$CA_STATE_DIR/issued" | wc -l)" = "$n_issued" ] || die "issued/ count differs"
    [ "$(pub_of pkey "$CA_KEY_FILE")" = "$(pub_of x509 "$CA_STATE_DIR/certs/intermediate-ca.crt")" ] || die "copied key does not match"
    ca_layout_check || die "layout owners or modes are wrong"
    echo "    index: $(wc -l < "$CA_STATE_DIR/db/index.txt") rows, $(grep -c '^R' "$CA_STATE_DIR/db/index.txt") revoked;" \
         "serial $(cat "$CA_STATE_DIR/db/serial"); next CRL number $(cat "$CA_STATE_DIR/db/crlnumber");" \
         "last published intermediate CRL $(crl_number "$INT/crl/intermediate-ca.crl")"
    say "forward done; $FROM is unchanged. Next: start the custodian on the new layout and check CRL N+1."
}

# --- retire -------------------------------------------------------------------
retire() {
    [ -f "$MANIFEST" ] || die "no forward has been done (no $MANIFEST)"
    [ -d "$INT" ] || die "$INT is already retired"
    say "retiring the old copies in $FROM (renamed, not deleted)"
    mv "$INT" "$INT.migrated-$TS"
    [ -d "$FROM/ocsp" ] && mv "$FROM/ocsp" "$FROM/ocsp.migrated-$TS"
    mkdir -p "$FROM/public.migrated-$TS"
    local f
    for f in ca-chain.crt hybrid-ca-chain.crt hybrid-combined-crl.pem combined-crl.pem; do
        [ -f "$FROM/$f" ] && mv "$FROM/$f" "$FROM/public.migrated-$TS/"
    done
    echo "    $INT.migrated-$TS holds the old copy of the intermediate key: destroy it when the rollback window ends, and record that."
}

# --- reverse ------------------------------------------------------------------
reverse() {
    refuse_if_writers_run
    take_writer_lock
    [ -d "$CA_STATE_DIR" ] || die "no new layout at $CA_STATE_DIR"
    say "un-retiring $FROM if it was retired"
    local d
    if [ ! -d "$INT" ]; then
        d=$(ls -d "$INT".migrated-* 2>/dev/null | sort | tail -1); [ -n "$d" ] || die "$INT is missing and no retired copy exists"
        mv "$d" "$INT"
        d=$(ls -d "$FROM"/ocsp.migrated-* 2>/dev/null | sort | tail -1); [ -n "$d" ] && [ ! -d "$FROM/ocsp" ] && mv "$d" "$FROM/ocsp"
        d=$(ls -d "$FROM"/public.migrated-* 2>/dev/null | sort | tail -1)
        if [ -n "$d" ]; then
            for f in "$d"/*; do [ -f "$FROM/$(basename "$f")" ] || mv "$f" "$FROM/"; done
            rmdir "$d" 2>/dev/null || true
        fi
    fi

    say "copying the state back into $INT (the previous files are kept as *.pre-reverse-$TS)"
    local f
    for f in index.txt index.txt.attr serial crlnumber fingerprint-index.json idempotency.json lineage.json; do
        [ -f "$CA_STATE_DIR/db/$f" ] || continue
        [ -f "$INT/db/$f" ] && cp -p "$INT/db/$f" "$INT/db/$f.pre-reverse-$TS"
        install -m 0644 -o "$APP_UID" -g "$APP_GID" "$CA_STATE_DIR/db/$f" "$INT/db/$f"
    done
    chmod 0640 "$INT"/db/*.json 2>/dev/null || true
    for f in "$CA_STATE_DIR"/issued/*; do
        [ -f "$f" ] && install -m 0644 -o "$APP_UID" -g "$APP_GID" "$f" "$INT/issued/$(basename "$f")"
    done
    install -m 0644 -o 0 -g 0 "$CA_STATE_DIR/crl/intermediate-ca.crl" "$INT/crl/intermediate-ca.crl"
    # The root CRL the custodian published may be newer than the tree's (the
    # inbox); keep whichever has the higher number.
    if hex_gt "$(crl_number "$CA_STATE_DIR/crl/root-ca.crl")" "$(crl_number "$FROM/root/crl/root-ca.crl")"; then
        cp -p "$FROM/root/crl/root-ca.crl" "$FROM/root/crl/root-ca.crl.pre-reverse-$TS"
        install -m 0644 -o 0 -g 0 "$CA_STATE_DIR/crl/root-ca.crl" "$FROM/root/crl/root-ca.crl"
    fi
    # The gateway's CRL files: the latest the custodian published, so a
    # gateway started on the old tree has every revocation from its first read.
    for f in hybrid-combined-crl.pem combined-crl.pem ca-chain.crt hybrid-ca-chain.crt; do
        [ -f "$CA_PUBLIC_DIR/$f" ] || continue
        [ -f "$FROM/$f" ] && cp -p "$FROM/$f" "$FROM/$f.pre-reverse-$TS"
        install -m 0644 -o 0 -g 0 "$CA_PUBLIC_DIR/$f" "$FROM/$f"
    done

    say "checking the old tree"
    [ "$(pub_of x509 "$INT/certs/intermediate-ca.crt")" = "$(pub_of pkey "$INT/private/intermediate-ca.key")" ] \
        || die "the old tree's key does not match its certificate"
    local published next missing
    published=$(crl_number "$CA_STATE_DIR/crl/intermediate-ca.crl")
    next=$(tr -d '\n' < "$INT/db/crlnumber")
    hex_gt "$next" "$published" || die "crlnumber $next is not above the last published $published: the next CRL would reuse a number"
    missing=$(comm -23 <(crl_serials "$CA_STATE_DIR/crl/intermediate-ca.crl") <(crl_serials "$FROM/hybrid-combined-crl.pem"))
    [ -z "$missing" ] || die "revoked serials missing from $FROM/hybrid-combined-crl.pem: $missing"
    "$OPENSSL" crl -in "$FROM/hybrid-combined-crl.pem" -noout -issuer | grep -q "Intermediate" \
        || die "$FROM/hybrid-combined-crl.pem does not start with the intermediate CRL"
    echo "    last published CRL $published, next $next; every revoked serial is in $FROM/hybrid-combined-crl.pem"

    say "setting the new layout aside (renamed, not deleted)"
    exec 9>&-
    for d in "$CA_ROOT" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$OCSP_KEY_DIR"; do
        [ -d "$d" ] && mv "$d" "$d.reversed-$TS"
    done
    echo "    $CA_ROOT.reversed-$TS holds a copy of the intermediate key: destroy it when no longer needed, and record that."
    say "reverse done. Start the old containers; the renewer's next CRL is number $next."
}

case "$cmd" in
    forward) forward ;;
    verify)  take_writer_lock; say "verifying the copies"; verify_manifest || die "the copies do not match the manifest" ;;
    retire)  take_writer_lock; retire ;;
    reverse) reverse ;;
    *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
