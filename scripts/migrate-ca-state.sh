#!/usr/bin/env bash
# migrate-ca-state.sh: move a running deployment's intermediate CA from the
# shared CA tree into the custodian's own layout, and back (ADR-024).
#
#   migrate-ca-state.sh forward [--from DIR]   copy key, state, root CRL, the
#                                              OCSP key and the internal TLS
#                                              trust files (into TRUST_DIR) into
#                                              the layout of
#                                              scripts/lib/ca-layout.sh, verify
#                                              every copy against a SHA-256
#                                              manifest. Copies, never moves.
#   migrate-ca-state.sh verify                 re-check the copies against the
#                                              manifest
#   migrate-ca-state.sh check-next [--from DIR]
#                                              after the new custodian's first
#                                              CRL and BEFORE any reader moves
#                                              (ADR-024 switch step 4): CRL N+1
#                                              verifies, is numbered N+1, carries
#                                              every serial of N, is first in
#                                              the combined CRL and runs 6+ days.
#                                              Read-only; exits 1 on any failure.
#   migrate-ca-state.sh retire [--from DIR]    after the readers have moved:
#                                              rename the old intermediate/, ocsp/
#                                              and top-level CRL and chain files
#                                              so a tool still pointed at them
#                                              fails instead of using stale data
#   migrate-ca-state.sh reverse [--from DIR]   rollback: stage the old tree with
#                                              the state copied back (index,
#                                              serial, crlnumber, issued/, the
#                                              custodian's JSON state) and the
#                                              latest published CRLs, check that
#                                              nothing is un-revoked and no CRL
#                                              number reused, and only then
#                                              rename it into place and set the
#                                              new layout aside. Refused if the
#                                              old tree changed since forward
#                                              (then: abort)
#   migrate-ca-state.sh abort [--from DIR]     before the readers moved: set the
#                                              new layout aside, $FROM untouched,
#                                              and go on with the old system
#
# DIR defaults to /etc/pki/pqc-ca. Run as root on the host, with the custodian
# and the CRL renewer stopped: forward, reverse and abort refuse otherwise (and
# when docker cannot be asked), and hold the old system's db/.ca-db.lock and
# the custodian's writer lock. retire only renames under DIR and takes neither.
# No symbolic link is followed out of a tree an unprivileged writer owns.
# Nothing is deleted. What is replaced is renamed with a timestamp.
#
# The ADR-024 runbook: issue a fresh CRL N with the old system; stop
# management-api, the renewer and the custodian; forward; start ONLY the new
# custodian (it issues CRL N+1); check-next; only then move the readers;
# retire. If check-next fails: stop the custodian; abort; start the old
# system. Rollback after the readers moved: stop the new containers; reverse;
# start the old ones.
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

cmd=${1:-}; [ $# -eq 0 ] || shift
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
# Fails closed: a docker that cannot be asked (daemon down, no permission) is
# not "not running". Only a host with no docker client at all has no
# containers to ask about.
container_running() {
    local out
    command -v docker >/dev/null 2>&1 || return 1
    if out=$(docker inspect -f '{{.State.Running}}' "$1" 2>&1); then
        [ "$out" = true ]
    elif printf '%s' "$out" | grep -qi 'no such object\|no such container'; then
        return 1
    else
        die "cannot ask docker whether $1 is running ($out); refusing"
    fi
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
    ca_take_writer_lock || die "the custodian holds $CA_WRITER_LOCK: it is running against $CA_STATE_DIR"
}
# The OLD system's lock (pre-ADR-024: the custodian and the CRL renewer flock
# db/.ca-db.lock around every openssl ca): held here, on fd 8, so nothing of
# the old system writes the old tree while it is copied or restored.
take_old_lock() { # take_old_lock DBDIR
    local f="$1/.ca-db.lock"
    [ -d "$1" ] || return 0
    [ ! -L "$f" ] || die "$f is a symbolic link; refusing"
    [ -e "$f" ] || install -m 0644 -o "$APP_UID" -g "$APP_GID" /dev/null "$f"
    exec 8>>"$f"
    flock -n 8 || die "the old system holds $f (a custodian or CRL renewer of the previous release is running)"
}
# Root reads trees an unprivileged custodian could write: links there are
# refused before anything is read (ca_regular_tree, scripts/lib/ca-layout.sh).
require_regular() {
    ca_regular_tree "$@" || die "refusing to copy across the trust boundary (see above)"
}
# After a forward: no private key anywhere in the new layout but where keys
# belong (the custodian's key directory, the OCSP key directory).
assert_no_stray_keys() {
    local hits
    hits=$(find "$CA_STATE_DIR" "$CA_INBOX_DIR" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$TRUST_DIR" -type f -print0 \
        | xargs -0 -r sh -c 'grep -lE "^-----BEGIN ([A-Z0-9-]+ )*PRIVATE KEY-----" -- "$@"; [ $? -le 1 ]' sh) \
        || die "could not scan the new layout for private keys"
    [ -z "$hits" ] || die "a private key outside $CA_KEY_DIR and $OCSP_KEY_DIR: $(echo "$hits" | tr '\n' ' ')(set this layout aside with abort, and find out how it got into $FROM)"
}

# --- helpers ------------------------------------------------------------------
# same_key KEY CERT: true when the private key belongs to the certificate. A
# file that cannot be read is an error, never two empty strings that match.
same_key() {
    local a b
    a=$("$OPENSSL" pkey -in "$1" -pubout) || die "cannot read the key $1"
    b=$("$OPENSSL" x509 -in "$2" -noout -pubkey) || die "cannot read the certificate $2"
    [ -n "$a" ] && [ "$a" = "$b" ]
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
    take_old_lock "$INT/db"
    say "checking the source tree $FROM"
    require_regular "$INT" "$FROM/root/certs" "$FROM/root/crl" "$FROM/ocsp" \
        "$FROM/internal-tls-ca.crt" "$FROM/internal-tls-ca-mldsa.crt" "$FROM/internal-tls-ca-rsa.crt"
    local f
    for f in "$INT/openssl-intermediate.cnf" "$INT/db/index.txt" "$INT/db/index.txt.attr" \
             "$INT/db/serial" "$INT/db/crlnumber" "$INT/certs/intermediate-ca.crt" \
             "$INT/private/intermediate-ca.key" "$INT/crl/intermediate-ca.crl" \
             "$FROM/root/certs/root-ca.crt" "$FROM/root/crl/root-ca.crl"; do
        [ -f "$f" ] || die "missing $f"
    done
    same_key "$INT/private/intermediate-ca.key" "$INT/certs/intermediate-ca.crt" \
        || die "the intermediate key does not match its certificate"
    crl_verify "$INT/crl/intermediate-ca.crl" "$INT/certs/intermediate-ca.crt" || die "intermediate CRL does not verify"
    crl_verify "$FROM/root/crl/root-ca.crl" "$FROM/root/certs/root-ca.crt" || die "root CRL does not verify"
    for f in "$CA_KEY_DIR" "$CA_STATE_DIR" "$CA_INBOX_DIR" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$OCSP_KEY_DIR"; do
        [ ! -d "$f" ] || [ -z "$(ls -A "$f")" ] || die "$f is not empty; a forward has been done already (reverse, or abort if the readers never moved)"
    done
    # The internal TLS trust file: in the old tree on a running deployment
    # (copied below), or already in $TRUST_DIR on a bootstrap by this release.
    local trust_from=""
    if [ -f "$FROM/internal-tls-ca.crt" ]; then
        [ ! -e "$TRUST_DIR/internal-tls-ca.crt" ] \
            || die "an internal TLS trust file is in both $FROM and $TRUST_DIR; which one management-api pins is unclear"
        trust_from=$FROM
    elif [ ! -f "$TRUST_DIR/internal-tls-ca.crt" ]; then
        die "no internal TLS trust file (internal-tls-ca.crt) in $FROM or $TRUST_DIR: management-api pins it"
    fi

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

    # The public trust anchors (ADR-024 §3): a directory of their own, mounted
    # whole and read-only; nothing is mounted from $FROM any more.
    install -d -o 0 -g 0 -m 0755 "$TRUST_DIR"
    for f in internal-tls-ca.crt internal-tls-ca-mldsa.crt internal-tls-ca-rsa.crt; do
        [ -n "$trust_from" ] && [ -f "$FROM/$f" ] || continue
        install -m 0644 -o 0 -g 0 "$FROM/$f" "$TRUST_DIR/$f"
        printf '%s  %s  %s\n' "$(sha256sum < "$FROM/$f" | cut -d' ' -f1)" "$TRUST_DIR/$f" "$FROM/$f" >> "$MANIFEST.new"
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
    assert_no_stray_keys
    local a b
    for f in index.txt serial crlnumber; do
        a=$(wc -l < "$INT/db/$f"); b=$(wc -l < "$CA_STATE_DIR/db/$f")
        [ "$a" = "$b" ] || die "$f: $a lines in the source, $b in the copy"
    done
    [ "$(ls "$CA_STATE_DIR/issued" | wc -l)" = "$n_issued" ] || die "issued/ count differs"
    same_key "$CA_KEY_FILE" "$CA_STATE_DIR/certs/intermediate-ca.crt" || die "copied key does not match"
    ca_layout_check || die "layout owners or modes are wrong"
    echo "    index: $(wc -l < "$CA_STATE_DIR/db/index.txt") rows, $(grep -c '^R' "$CA_STATE_DIR/db/index.txt") revoked;" \
         "serial $(cat "$CA_STATE_DIR/db/serial"); next CRL number $(cat "$CA_STATE_DIR/db/crlnumber");" \
         "last published intermediate CRL $(crl_number "$INT/crl/intermediate-ca.crl")"
    say "forward done; $FROM is unchanged. Next: start the custodian on the new layout and check CRL N+1."
}

# --- check-next ---------------------------------------------------------------
check_next() {
    local nfile="$INT/crl/intermediate-ca.crl" pub="$CA_PUBLIC_DIR/hybrid-combined-crl.pem"
    local cert="$CA_STATE_DIR/certs/intermediate-ca.crt" d n n1 bad=0 missing nu
    if [ ! -f "$nfile" ]; then   # already retired: the newest retired copy holds N
        d=$(find "$FROM" -maxdepth 1 -name "intermediate.migrated-*" -type d | sort | tail -1)
        nfile="$d/crl/intermediate-ca.crl"
    fi
    [ -f "$nfile" ] || die "no CRL N found under $INT or a retired copy of it"
    [ -f "$pub" ] || die "no CRL N+1 published at $pub; start the custodian first"
    say "CRL N   : $nfile"
    say "CRL N+1 : $pub (first block)"
    ok()  { echo "    PASS  $*"; }
    nok() { echo "    FAIL  $*"; bad=1; }
    if crl_verify "$pub" "$cert"; then ok "N+1 verifies against the intermediate certificate"
    else nok "N+1 does not verify against $cert"; fi
    if [ "$("$OPENSSL" crl -in "$pub" -noout -issuer | sed 's/^issuer=//')" = "$("$OPENSSL" x509 -in "$cert" -noout -subject | sed 's/^subject=//')" ]; then
        ok "the intermediate CRL is FIRST in the combined CRL"
    else nok "the first CRL in $pub is not the intermediate's"; fi
    [ "$(grep -c 'BEGIN X509 CRL' "$pub")" = 2 ] && ok "the combined CRL holds two CRLs" || nok "the combined CRL does not hold exactly two CRLs"
    n=$(crl_number "$nfile"); n1=$(crl_number "$pub")
    if [ $((16#$n1)) -eq $((16#$n + 1)) ]; then ok "numbered N+1 (0x$n -> 0x$n1)"
    else nok "numbered 0x$n1, expected 0x$n + 1"; fi
    missing=$(comm -23 <(crl_serials "$nfile") <(crl_serials "$pub"))
    if [ -z "$missing" ]; then ok "every serial revoked in N ($(crl_serials "$nfile" | wc -l)) is in N+1 ($(crl_serials "$pub" | wc -l))"
    else nok "revoked in N but missing from N+1: $(echo "$missing" | tr '\n' ' ')"; fi
    nu=$("$OPENSSL" crl -in "$pub" -noout -nextupdate -dateopt iso_8601 | sed 's/^nextUpdate=//; s/Z$//')
    if [ "$(date -u -d "$nu" +%s)" -gt $(( $(date -u +%s) + 6 * 86400 )) ]; then ok "nextUpdate $nu, more than 6 days ahead"
    else nok "nextUpdate $nu is not more than 6 days ahead"; fi
    [ "$bad" = 0 ] || die "CRL N+1 failed its checks: do NOT move the readers; roll back (reverse)"
    say "CRL N+1 is good: the readers may move."
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
    for f in ca-chain.crt hybrid-ca-chain.crt hybrid-combined-crl.pem combined-crl.pem \
             internal-tls-ca.crt internal-tls-ca-mldsa.crt internal-tls-ca-rsa.crt; do
        if [ -f "$FROM/$f" ]; then mv "$FROM/$f" "$FROM/public.migrated-$TS/"; fi
    done
    echo "    $INT.migrated-$TS holds the old copy of the intermediate key: destroy it when the rollback window ends, and record that."
}

# --- reverse ------------------------------------------------------------------
# The rollback is assembled and checked in a staging copy inside $FROM first.
# The old tree changes only after every check has passed, and then by rename on
# the same filesystem: a failed check leaves $FROM exactly as it was.
newest() { find "$FROM" -maxdepth 1 -name "$1" -type d | sort | tail -1; }
revoked_in_index() { awk -F'\t' '$1 == "R" { print $4 }' "$1" | sort -u; }
serials_in_index() { awk -F'\t' 'NF >= 4 { print $4 }' "$1" | sort -u; }
# hex_max HEX...: the largest, upper case, an even number of digits (the form
# openssl ca writes serial and crlnumber in). Compared as strings, so no limit
# on length.
hex_max() {
    local h best="" n
    for h in "$@"; do
        [ -n "$h" ] || continue
        n=$(printf '%s' "$h" | tr 'a-f' 'A-F' | sed 's/^0*//'); n=${n:-0}
        if [ -z "$best" ] || [ "${#n}" -gt "${#best}" ] || { [ "${#n}" -eq "${#best}" ] && [[ "$n" > "$best" ]]; }; then best=$n; fi
    done
    [ $(( ${#best} % 2 )) = 0 ] || best="0$best"
    printf '%s' "$best"
}
hex_inc() { printf '%X' $(( 16#$1 + 1 )); }
# sources_unchanged [RETIRED]: every file forward copied is, in the old tree,
# still the file it copied (looked for where retire renamed it, if it did).
# Only what the OLD SYSTEM writes counts (its CA state under intermediate/,
# its OCSP files): those change only if it ran on. The root CRL is renewed by
# the operator's offline procedure in the rollback window (README, at least
# every 90 days) and the higher-numbered one is kept below; the trust files
# are the operator's too.
sources_unchanged() {
    local want dst src f bad=0
    while read -r want dst src; do
        case "$src" in *"(paths rewritten)"*) continue ;; esac
        case "$src" in "$INT"/*|"$FROM"/ocsp/*) ;; *) continue ;; esac
        f=$src
        if [ ! -e "$f" ]; then
            case "$f" in
                "$INT"/*) [ -n "$1" ] && f="$1/${f#"$INT"/}" ;;
                "$FROM"/ocsp/*) f="$(newest "ocsp.migrated-*")/${f#"$FROM"/ocsp/}" ;;
                "$FROM"/*) f="$(newest "public.migrated-*")/${f#"$FROM"/}" ;;
            esac
        fi
        if [ ! -f "$f" ]; then echo "  GONE    $src"; bad=1
        elif [ "$(sha256sum < "$f" | cut -d' ' -f1)" != "$want" ]; then echo "  CHANGED $src"; bad=1; fi
    done < "$MANIFEST"
    [ "$bad" = 0 ]
}
reverse() {
    refuse_if_writers_run
    take_writer_lock
    [ -d "$CA_STATE_DIR" ] || die "no new layout at $CA_STATE_DIR"
    local src retired="" f b m published next missing comb
    if [ -d "$INT" ]; then
        src=$INT
    else
        retired=$(newest "intermediate.migrated-*")
        [ -n "$retired" ] || die "$INT is missing and no retired copy exists"
        src=$retired
    fi
    take_old_lock "$src/db"
    require_regular "$src" "$CA_STATE_DIR" "$CA_PUBLIC_DIR" "$TRUST_DIR" "$FROM/root/crl"
    # The old tree must be as forward left it. If the old system ran on after
    # forward (an abort that went back to it), this layout is stale: restoring
    # it would reuse a CRL number, move serial back and lose issued rows.
    sources_unchanged "$retired" || die "the old tree changed since forward (above): the old system has moved on, so this layout is stale. Set it aside with '$0 abort' (nothing in $FROM changes), not reverse"
    STAGE=$(mktemp -d "$FROM/.reverse-staging-XXXXXX")
    trap 'rm -rf -- "$STAGE"' EXIT
    local S="$STAGE/intermediate"
    say "staging the rollback in $STAGE (nothing in $FROM changes until every check passes)"
    cp -a "$src" "$S"
    for f in index.txt index.txt.attr serial crlnumber fingerprint-index.json idempotency.json lineage.json; do
        [ -f "$CA_STATE_DIR/db/$f" ] || continue
        case "$f" in *.json) m=0640 ;; *) m=0644 ;; esac
        install -m "$m" -o "$APP_UID" -g "$APP_GID" "$CA_STATE_DIR/db/$f" "$S/db/$f"
    done
    for f in "$CA_STATE_DIR"/issued/*; do
        [ -f "$f" ] || continue
        install -m 0644 -o "$APP_UID" -g "$APP_GID" "$f" "$S/issued/$(basename "$f")"
    done
    install -m 0644 -o 0 -g 0 "$CA_STATE_DIR/crl/intermediate-ca.crl" "$S/crl/intermediate-ca.crl"
    # No counter moves backwards: the larger of the custodian's and the old
    # tree's, and the CRL number above every CRL either side has published.
    printf '%s\n' "$(hex_max "$(tr -d '\n' < "$S/db/crlnumber")" "$(tr -d '\n' < "$src/db/crlnumber")" \
        "$(hex_inc "$(crl_number "$src/crl/intermediate-ca.crl")")" \
        "$(hex_inc "$(crl_number "$CA_STATE_DIR/crl/intermediate-ca.crl")")")" > "$S/db/crlnumber"
    printf '%s\n' "$(hex_max "$(tr -d '\n' < "$S/db/serial")" "$(tr -d '\n' < "$src/db/serial")")" > "$S/db/serial"
    # The gateway's CRL files: the latest the custodian published, so a
    # gateway started on the old tree has every revocation from its first read.
    mkdir "$STAGE/public"
    for f in hybrid-combined-crl.pem combined-crl.pem ca-chain.crt hybrid-ca-chain.crt; do
        [ -f "$CA_PUBLIC_DIR/$f" ] || continue
        install -m 0644 -o 0 -g 0 "$CA_PUBLIC_DIR/$f" "$STAGE/public/$f"
    done
    # The root CRL the custodian published may be newer than the tree's (the
    # inbox); keep whichever has the higher number.
    if hex_gt "$(crl_number "$CA_STATE_DIR/crl/root-ca.crl")" "$(crl_number "$FROM/root/crl/root-ca.crl")"; then
        install -m 0644 -o 0 -g 0 "$CA_STATE_DIR/crl/root-ca.crl" "$STAGE/root-ca.crl"
    elif hex_gt "$(crl_number "$FROM/root/crl/root-ca.crl")" "$(crl_number "$CA_STATE_DIR/crl/root-ca.crl")"; then
        # The operator renewed the root CRL in the old tree after forward: the
        # combined CRL the old gateway reads must carry THAT root CRL, not the
        # older one the custodian published. Intermediate first.
        for f in hybrid-combined-crl.pem combined-crl.pem; do
            cat "$S/crl/intermediate-ca.crl" "$FROM/root/crl/root-ca.crl" > "$STAGE/public/$f"
            chmod 0644 "$STAGE/public/$f"
        done
    fi
    # The trust anchors as they are now (an ADR-022 switch may have changed
    # them since forward), back where the previous release reads them.
    mkdir "$STAGE/trust"
    for f in internal-tls-ca.crt internal-tls-ca-mldsa.crt internal-tls-ca-rsa.crt; do
        [ -f "$TRUST_DIR/$f" ] || continue
        install -m 0644 -o 0 -g 0 "$TRUST_DIR/$f" "$STAGE/trust/$f"
    done

    say "checking the staged tree"
    same_key "$S/private/intermediate-ca.key" "$S/certs/intermediate-ca.crt" \
        || die "the old tree's key does not match its certificate"
    crl_verify "$S/crl/intermediate-ca.crl" "$S/certs/intermediate-ca.crt" \
        || die "the custodian's last intermediate CRL does not verify against the old tree's certificate"
    if [ -f "$STAGE/root-ca.crl" ]; then
        crl_verify "$STAGE/root-ca.crl" "$FROM/root/certs/root-ca.crt" || die "the custodian's root CRL does not verify"
    fi
    published=$(crl_number "$S/crl/intermediate-ca.crl")
    next=$(tr -d '\n' < "$S/db/crlnumber")
    hex_gt "$next" "$published" || die "crlnumber $next is not above the last published $published: the next CRL would reuse a number"
    missing=$(comm -23 <(revoked_in_index "$src/db/index.txt") <(revoked_in_index "$S/db/index.txt"))
    [ -z "$missing" ] || die "revoked in the old index but not in the custodian's: $missing (rolling back would un-revoke them)"
    missing=$(comm -23 <(serials_in_index "$src/db/index.txt") <(serials_in_index "$S/db/index.txt"))
    [ -z "$missing" ] || die "in the old index but not in the custodian's: $(echo "$missing" | tr '\n' ' ')(rolling back would lose them, and a serial could be issued twice)"
    # The combined CRL the gateway reads after the rollback.
    comb="$STAGE/public/hybrid-combined-crl.pem"
    [ -f "$comb" ] || comb="$FROM/hybrid-combined-crl.pem"
    [ -f "$comb" ] || comb="$(newest "public.migrated-*")/hybrid-combined-crl.pem"
    [ -f "$comb" ] || die "no combined CRL for the old tree"
    [ "$("$OPENSSL" crl -in "$comb" -noout -issuer | sed 's/^issuer=//')" = \
      "$("$OPENSSL" x509 -in "$S/certs/intermediate-ca.crt" -noout -subject | sed 's/^subject=//')" ] \
        || die "the combined CRL the gateway would read does not start with the intermediate CRL"
    missing=$(comm -23 <(crl_serials "$S/crl/intermediate-ca.crl") <(crl_serials "$comb"))
    [ -z "$missing" ] || die "revoked serials missing from the combined CRL the gateway would read: $missing"
    [ -f "$STAGE/trust/internal-tls-ca.crt" ] || [ -f "$FROM/internal-tls-ca.crt" ] \
        || [ -f "$(newest "public.migrated-*")/internal-tls-ca.crt" ] \
        || die "no internal TLS trust file in $TRUST_DIR or $FROM: management-api would start without one"
    for f in "$STAGE"/trust/*; do
        [ -f "$f" ] || continue
        "$OPENSSL" x509 -in "$f" -noout || die "$TRUST_DIR/$(basename "$f") is not a certificate"
    done
    echo "    last published CRL $published, next $next; nothing un-revoked; every revoked serial is in the combined CRL"

    say "every check passed: moving the staged tree into place (the previous one is kept as $INT.pre-reverse-$TS)"
    mv -T "$src" "$INT.pre-reverse-$TS"
    mv -T "$S" "$INT" || die "could not move $S into place: rename $INT.pre-reverse-$TS back to $INT"
    for f in "$STAGE"/public/*; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        if [ -f "$FROM/$b" ]; then cp -p "$FROM/$b" "$FROM/$b.pre-reverse-$TS"; fi
        mv -f "$f" "$FROM/$b"
    done
    if [ -f "$STAGE/root-ca.crl" ]; then
        cp -p "$FROM/root/crl/root-ca.crl" "$FROM/root/crl/root-ca.crl.pre-reverse-$TS"
        mv -f "$STAGE/root-ca.crl" "$FROM/root/crl/root-ca.crl"
    fi
    for f in "$STAGE"/trust/*; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        if [ -f "$FROM/$b" ]; then cp -p "$FROM/$b" "$FROM/$b.pre-reverse-$TS"; fi
        mv -f "$f" "$FROM/$b"
    done
    if [ -n "$retired" ]; then   # un-retire the rest of what retire renamed
        f=$(newest "ocsp.migrated-*")
        if [ -n "$f" ] && [ ! -d "$FROM/ocsp" ]; then mv -T "$f" "$FROM/ocsp"; fi
        f=$(newest "public.migrated-*")
        if [ -n "$f" ]; then
            for b in "$f"/*; do
                [ -f "$b" ] || continue
                [ -e "$FROM/$(basename "$b")" ] || mv "$b" "$FROM/"
            done
            if [ -z "$(ls -A "$f")" ]; then rmdir "$f"
            else echo "    kept $f: $FROM already has a newer copy of what it holds"; fi
        fi
    fi
    echo "    $INT.pre-reverse-$TS holds a copy of the intermediate key: destroy it when no longer needed, and record that."

    say "setting the new layout aside (renamed, not deleted)"
    exec 9>&-
    for f in "$CA_ROOT" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$OCSP_KEY_DIR" "$TRUST_DIR"; do
        if [ -d "$f" ]; then mv "$f" "$f.reversed-$TS"; fi
    done
    echo "    $CA_ROOT.reversed-$TS holds a copy of the intermediate key: destroy it when no longer needed, and record that."
    say "reverse done. Check out the previous release and recreate ALL its containers: docker compose up -d --force-recreate"
    echo "    (a plain up -d would restart the stopped crl-renewer on a network this release's compose down removed; and the old"
    echo "    containers mount the trust file by inode). The renewer's next CRL is number $next."
}

# --- abort --------------------------------------------------------------------
# Before the readers moved (switch step 5): go back to the old system and set
# the new layout aside, without touching $FROM. The old system then keeps
# operating; a later forward starts from scratch. Refused once the readers may
# have moved ($INT retired) or once the custodian has issued or revoked in the
# new layout (those rows exist nowhere else: reverse carries them back).
abort() {
    refuse_if_writers_run
    take_writer_lock
    [ -d "$CA_STATE_DIR" ] || die "no new layout at $CA_STATE_DIR"
    [ -d "$INT" ] || die "$INT is retired, so the readers may have moved: roll back with reverse, not abort"
    [ -f "$MANIFEST" ] || die "no manifest at $MANIFEST; this layout was not made by forward"
    local f want
    for f in index.txt serial; do
        want=$(awk -v d="$CA_STATE_DIR/db/$f" '$2 == d { print $1 }' "$MANIFEST")
        [ "$(sha256sum < "$CA_STATE_DIR/db/$f" | cut -d' ' -f1)" = "$want" ] \
            || die "the custodian has issued or revoked in the new layout ($CA_STATE_DIR/db/$f changed since forward): abort would lose that; roll back with reverse"
    done
    say "setting the unused new layout aside (renamed, not deleted); nothing in $FROM changes"
    if [ -f "$CA_STATE_DIR/crl/intermediate-ca.crl" ]; then
        echo "    its last intermediate CRL, number $(crl_number "$CA_STATE_DIR/crl/intermediate-ca.crl"), was never read by the gateway (it reads $FROM until the switch)"
    fi
    exec 9>&-
    for f in "$CA_ROOT" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR" "$OCSP_KEY_DIR"; do
        if [ -d "$f" ]; then mv "$f" "$f.aborted-$TS"; fi
    done
    # The trust directory only if forward filled it (on a bootstrap it was there already).
    if [ -d "$TRUST_DIR" ] && grep -q "  $TRUST_DIR/" "$CA_ROOT.aborted-$TS/migration.manifest"; then
        mv "$TRUST_DIR" "$TRUST_DIR.aborted-$TS"
    fi
    echo "    $CA_ROOT.aborted-$TS holds a copy of the intermediate key: destroy it when no longer needed, and record that."
    say "abort done. Check out the previous release and recreate ALL its containers: docker compose up -d --force-recreate"
    echo "    (this release's compose replaced the custodian's container). The old system goes on from where it is."
}

case "$cmd" in
    forward) forward ;;
    verify)  take_writer_lock; say "verifying the copies"; verify_manifest || die "the copies do not match the manifest" ;;
    # Only renames under $FROM, and runs while the custodian runs (it holds
    # the writer lock for its whole life), so it takes no lock.
    retire)  retire ;;
    check-next) check_next ;;
    reverse) reverse ;;
    abort)   abort ;;
    *) sed -n '2,47p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
