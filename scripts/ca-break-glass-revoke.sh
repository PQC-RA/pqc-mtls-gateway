#!/usr/bin/env bash
# ca-break-glass-revoke.sh: revoke a certificate while the CA custodian cannot
# run (ADR-024, owner decision 8). The normal path is the management API; use
# this only when the custodian is down and a revocation cannot wait.
#
#   ca-break-glass-revoke.sh SERIAL [REASON]
#
# REASON: keyCompromise, affiliationChanged, superseded, cessationOfOperation,
# privilegeWithdrawn, or unspecified (default; no reasonCode, RFC 5280 5.3.1).
#
# Runs as root on the host, on the custodian's own state, and only while the
# custodian is stopped: it takes the custodian's writer lock without waiting
# and refuses if it cannot (and refuses if the custodian container is
# running), so CA state still has one writer at any moment. It then does what
# the custodian does for a revocation: record it, run -updatedb, issue the
# next intermediate CRL, check its signature and that its number rises, and
# publish it the same way (temporary file + rename, DER at the URL names, the
# combined CRL intermediate first, the OCSP index snapshot). Files go back to
# the custodian's ownership. When the custodian starts again, its start-up
# pass issues the next CRL on top of this one.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/lib/ca-layout.sh
. "$HERE/lib/ca-layout.sh"
OPENSSL="${OPENSSL_BIN:-/opt/openssl/bin/openssl}"
[ -x "$OPENSSL" ] || OPENSSL=$(command -v openssl)
export OPENSSL_CONF=/dev/null
CUSTODIAN_CONTAINER="${CUSTODIAN_CONTAINER:-pqc-ca-custodian}"

die() { echo "ERROR: $*" >&2; exit 1; }
SERIAL=${1:?usage: ca-break-glass-revoke.sh SERIAL [REASON]}
REASON=${2:-unspecified}
SERIAL=$(echo "$SERIAL" | tr 'a-f' 'A-F')
[[ "$SERIAL" =~ ^[0-9A-F]+$ ]] || die "serial must be hexadecimal"
[ $(( ${#SERIAL} % 2 )) = 0 ] || SERIAL="0$SERIAL"
case "$REASON" in
    unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation|privilegeWithdrawn) ;;
    *) die "unknown reason $REASON" ;;
esac
[ "$(id -u)" = 0 ] || die "run as root"
CERT="$CA_STATE_DIR/issued/$SERIAL.pem"
[ -f "$CERT" ] || die "no issued certificate $CERT"

# One writer: the custodian must not run. A docker that cannot be asked
# (daemon down, no permission) is not "not running": refused, as in
# migrate-ca-state.sh. Only a host without a docker client has no containers.
if command -v docker >/dev/null 2>&1; then
    if running=$(docker inspect -f '{{.State.Running}}' "$CUSTODIAN_CONTAINER" 2>&1); then
        [ "$running" != true ] || die "$CUSTODIAN_CONTAINER is running: revoke through the management API instead"
    elif ! printf '%s' "$running" | grep -qi 'no such object\|no such container'; then
        die "cannot ask docker whether $CUSTODIAN_CONTAINER is running ($running); refusing"
    fi
fi
ca_take_writer_lock || die "the custodian holds $CA_WRITER_LOCK: revoke through the management API instead"
# Whatever happens from here (a failure included), the files openssl and this
# script write as root go back to the custodian: a root-owned crlnumber.new or
# index.txt left behind would make every later CRL pass of the custodian (uid
# 1003) fail with EACCES.
tmp=""
cleanup() { if [ -n "$tmp" ]; then rm -f "$tmp"; fi; ca_layout_file_perms; }
trap cleanup EXIT

ca() { "$OPENSSL" ca -config "$CA_CNF_FILE" -keyfile "file:$CA_KEY_FILE" "$@"; }
crlno() { "$OPENSSL" crl -in "$1" -noout -crlnumber | sed 's/^crlNumber=0x//'; }
publish() { # publish DIR NAME SRC MODE: temporary file in DIR, then rename
    local tmp
    tmp=$(mktemp "$1/.$2.tmp-XXXXXX")
    cat "$3" > "$tmp"; chmod "$4" "$tmp"; mv -f "$tmp" "$1/$2"
}

echo "==> revoking $SERIAL ($REASON)"
reason_args=(); [ "$REASON" = unspecified ] || reason_args=(-crl_reason "$REASON")
out=$(ca -revoke "$CERT" "${reason_args[@]}" 2>&1) || {
    echo "$out" | grep -qi "already revoked" && echo "    already revoked; issuing a CRL anyway" || die "revoke failed: $out"
}
# Every openssl failure stops here with openssl's own message, as in the
# custodian. The revocation is already recorded; running this again is safe.
out=$(ca -updatedb 2>&1) || die "-updatedb failed (the revocation is recorded, not yet published; fix the cause and run this again): $out"

echo "==> issuing the next intermediate CRL"
last=$(crlno "$CA_STATE_DIR/crl/intermediate-ca.crl")
tmp=$(mktemp "$CA_STATE_DIR/crl/.intermediate-ca.crl.tmp-XXXXXX")
out=$(ca -gencrl -out "$tmp" 2>&1) || die "-gencrl failed (the revocation is recorded, not yet published; fix the cause and run this again): $out"
"$OPENSSL" crl -in "$tmp" -noout -CAfile "$CA_STATE_DIR/certs/intermediate-ca.crt" 2>&1 | grep -q "verify OK" || die "the new CRL does not verify"
new=$(crlno "$tmp")
[ $((16#$new)) -gt $((16#$last)) ] || die "CRL number $new is not above the last published $last"
"$OPENSSL" crl -in "$tmp" -noout -text | grep -q "Serial Number: $SERIAL\$" || die "the new CRL does not list $SERIAL"
mv -f "$tmp" "$CA_STATE_DIR/crl/intermediate-ca.crl"; tmp=""

echo "==> publishing (as the custodian does)"
der=$(mktemp); comb=$(mktemp)
"$OPENSSL" crl -in "$CA_STATE_DIR/crl/intermediate-ca.crl" -outform DER -out "$der"
publish "$CA_PUBLIC_DIR" intermediate-ca.crl "$der" 0644
publish "$CA_STATUS_DIR" index.txt.attr "$CA_STATE_DIR/db/index.txt.attr" 0640
publish "$CA_STATUS_DIR" index.txt "$CA_STATE_DIR/db/index.txt" 0640
cat "$CA_STATE_DIR/crl/intermediate-ca.crl" "$CA_STATE_DIR/crl/root-ca.crl" > "$comb"
publish "$CA_PUBLIC_DIR" combined-crl.pem "$comb" 0644
publish "$CA_PUBLIC_DIR" hybrid-combined-crl.pem "$comb" 0644
rm -f "$der" "$comb"

echo "    intermediate CRL 0x$new published, $SERIAL revoked."
echo "    The gateway refuses $SERIAL within its usual window (Lua 1 s, ssl_crl on reload)."
echo "    Start the custodian when it can run; its start-up pass issues the next CRL."
