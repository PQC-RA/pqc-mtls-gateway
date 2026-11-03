#!/usr/bin/env bash
# check-key-isolation.sh: ADR-024 test 2. Only the custodian may hold any CA
# key, and only the intermediate's.
#
#   check-key-isolation.sh                    every running container of compose
#                                             project $COMPOSE_PROJECT (default
#                                             pqc-gw); run as root on the host
#   check-key-isolation.sh --root NAME=DIR ...
#                                             the same check on directory trees
#                                             (bench/adr024/key-isolation-unit.sh)
#
# The WHOLE filesystem of each container is scanned (/proc, /sys and /dev
# pruned): image layers, the writable layer, every mount and tmpfs, read from
# the host through /proc/<pid>/root, so a key baked into an image is found as
# well as one that arrives in a mount, and nothing depends on tools inside the
# image. Keys are compared by PUBLIC KEY with every CA certificate this
# deployment has, so a copied or renamed key is caught too. A private key whose
# public key cannot be derived counts as a failure, never as a pass, and so
# does a scan error. The canary: the scan must find the intermediate key in
# the custodian, or nothing was verified.
#
# Environment: CA_CERTS (CA certificates to compare with; default the host's),
# CA_INT_CERT (the intermediate's), CUSTODIAN_CONTAINER, OSSL.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${REPO:-$(cd "$HERE/.." && pwd)}
# shellcheck source=scripts/lib/ca-layout.sh
. "$REPO/scripts/lib/ca-layout.sh"
OSSL=${OSSL:-/opt/openssl/bin/openssl}
export OPENSSL_CONF=/dev/null
PKI=${PKI:-/etc/pki/pqc-ca}
PROJECT=${COMPOSE_PROJECT:-pqc-gw}
CUSTODIAN=${CUSTODIAN_CONTAINER:-pqc-ca-custodian}
CA_INT_CERT=${CA_INT_CERT:-$CA_STATE_DIR/certs/intermediate-ca.crt}
# Every certificate in these files is compared with, each on its own: the trust
# file is a bundle during an ADR-022 transition, and the RSA internal CA may
# exist only inside it. CA_REQUIRED must be there: a missing one fails the
# check instead of being skipped.
CA_CERTS=${CA_CERTS:-"$PKI/root/certs/root-ca.crt $CA_INT_CERT $TRUST_DIR/internal-tls-ca.crt $TRUST_DIR/internal-tls-ca-mldsa.crt $TRUST_DIR/internal-tls-ca-rsa.crt $PKI/enroll-classical-ca.crt"}
CA_REQUIRED=${CA_REQUIRED:-"$PKI/root/certs/root-ca.crt $CA_INT_CERT $TRUST_DIR/internal-tls-ca.crt"}
# A PEM private-key header line: PRIVATE KEY (PKCS#8), ENCRYPTED, RSA, EC,
# OPENSSH, ... Only a well-formed block counts (header, base64 body, matching
# END line): libraries such as libgnutls carry the header text itself.
KEY_RE='^-----BEGIN ([A-Z0-9-]+ )*PRIVATE KEY-----[[:space:]]*$'

RC=0
fail() { echo "  ==> *** $* ***"; RC=1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# sha256 of the DER SubjectPublicKeyInfo of a certificate; empty on failure.
spki_of_cert() {
    "$OSSL" x509 -in "$1" -noout -pubkey > "$T/cert.pub" && "$OSSL" pkey -pubin -in "$T/cert.pub" -outform DER -out "$T/cert.der" \
        && [ -s "$T/cert.der" ] && sha256sum < "$T/cert.der" | cut -c1-64
}

declare -A CA_SPKI=()
for req in $CA_REQUIRED; do
    [ -f "$req" ] || fail "expected CA certificate missing: $req (nothing to compare its key with)"
done
for crt in $CA_CERTS; do
    [ -f "$crt" ] || { echo "  (no $crt here)"; continue; }
    rm -rf "$T/c"; mkdir "$T/c"
    awk -v d="$T/c" '/-----BEGIN CERTIFICATE-----/ { k++ } k { print > (d "/" k ".pem") }' "$crt"
    k=$(find "$T/c" -name '*.pem' | wc -l | tr -d ' ')
    [ "$k" -gt 0 ] || { fail "$crt holds no certificate"; continue; }
    for c in "$T"/c/*.pem; do
        h=$(spki_of_cert "$c") || { fail "cannot read the public key of a certificate in $crt"; continue; }
        if [ "$k" = 1 ]; then CA_SPKI[$h]=$(basename "$crt" .crt)
        else CA_SPKI[$h]="$(basename "$crt" .crt)#$(basename "$c" .pem)"; fi
    done
done
INT_SPKI=$(spki_of_cert "$CA_INT_CERT") || fail "cannot read the intermediate certificate $CA_INT_CERT"
[ "${#CA_SPKI[@]}" -gt 0 ] || fail "no CA certificate to compare with"
echo "  CA certificates compared against: ${CA_SPKI[*]}"

# scan NAME ROOT: every PEM private key in the tree, each block on its own.
CUSTODIAN_SAW_KEY=0
scan() {
    local name=$1 r=${2%/} f b h n=0 held=""
    : > "$T/files"
    # grep exits 1 when a batch has no match, which is not an error; 2 is.
    # (r is "" for the root directory itself, so the prunes read /proc, ...)
    # -H: the starting point is followed when it is a symlink, as
    # /proc/<pid>/root is (without it find lists the link and stops); links
    # inside the tree are still not followed.
    if ! find -H "${r:-/}" \( -path "$r/proc" -o -path "$r/sys" -o -path "$r/dev" \) -prune -o -type f -print0 \
         | xargs -0 -r sh -c 'grep -lZE "$0" -- "$@"; [ $? -le 1 ]' "$KEY_RE" > "$T/files"; then
        fail "$name: the filesystem scan reported errors (above), key isolation UNVERIFIED"
    fi
    while IFS= read -r -d '' f; do
        rm -rf "$T/b"; mkdir "$T/b"
        awk -v d="$T/b" '
            /^-----BEGIN ([A-Z0-9-]+ )*PRIVATE KEY-----[[:space:]]*$/ { k++; buf = $0 "\n"; on = 1; body = 0; next }
            on && /^-----END ([A-Z0-9-]+ )*PRIVATE KEY-----[[:space:]]*$/ {
                if (body) { out = d "/" k ".pem"; printf "%s%s\n", buf, $0 > out; close(out) }
                on = 0; next }
            on && /^[A-Za-z0-9+\/=]+[[:space:]]*$/ { buf = buf $0 "\n"; body++; next }
            on && (/^[A-Za-z-]+: / || /^[[:space:]]*$/) { buf = buf $0 "\n"; next }   # legacy encryption headers
            on { on = 0 }                                                         # not a PEM block' "$f"
        for b in "$T"/b/*.pem; do
            [ -f "$b" ] || continue
            n=$((n + 1))
            if ! "$OSSL" pkey -in "$b" -passin pass: -pubout -outform DER -out "$T/key.der" 2> "$T/err" || [ ! -s "$T/key.der" ]; then
                fail "$name: ${f#"$r"} holds a private key whose public key cannot be derived ($(head -1 "$T/err"))"
                continue
            fi
            h=$(sha256sum < "$T/key.der" | cut -c1-64)
            [ -n "${CA_SPKI[$h]:-}" ] || continue
            if [ "$name" = "$CUSTODIAN" ] && [ "$h" = "$INT_SPKI" ]; then
                CUSTODIAN_SAW_KEY=1; held="$held ${CA_SPKI[$h]}"
            else
                fail "$name CAN READ THE ${CA_SPKI[$h]} PRIVATE KEY (${f#"$r"})"
            fi
        done
    done < "$T/files"
    # DER private keys (PKCS#8, PKCS#1, SEC1) have no header to grep for.
    # Candidates are files that start with a SEQUENCE whose first element is
    # INTEGER 0 or 1 (the version every one of those formats begins with);
    # openssl then decides, and a candidate it cannot read as a key is not one.
    if ! find -H "${r:-/}" \( -path "$r/proc" -o -path "$r/sys" -o -path "$r/dev" \) -prune -o -type f -print0 \
         | python3 -I -c '
import sys
paths = sys.stdin.buffer.read().split(b"\0")
out = sys.stdout.buffer
for p in paths:
    if not p:
        continue
    try:
        with open(p, "rb") as fh:
            b = fh.read(8)
    except OSError as e:
        sys.stderr.write(f"cannot read {p!r}: {e}\n")
        sys.exit(2)
    if len(b) < 5 or b[0] != 0x30:
        continue
    off = {0x81: 3, 0x82: 4, 0x83: 5}.get(b[1], 2 if b[1] < 0x80 else 0)
    if off and b[off:off + 3] in (b"\x02\x01\x00", b"\x02\x01\x01"):
        out.write(p + b"\0")
' > "$T/der"; then
        fail "$name: the scan for DER keys reported errors (above), key isolation UNVERIFIED"
    fi
    while IFS= read -r -d '' f; do
        "$OSSL" pkey -inform DER -in "$f" -pubout -outform DER -out "$T/key.der" 2> "$T/err" && [ -s "$T/key.der" ] || continue
        n=$((n + 1))
        h=$(sha256sum < "$T/key.der" | cut -c1-64)
        [ -n "${CA_SPKI[$h]:-}" ] || continue
        if [ "$name" = "$CUSTODIAN" ] && [ "$h" = "$INT_SPKI" ]; then
            CUSTODIAN_SAW_KEY=1; held="$held ${CA_SPKI[$h]}"
        else
            fail "$name CAN READ THE ${CA_SPKI[$h]} PRIVATE KEY (${f#"$r"}, DER)"
        fi
    done < "$T/der"
    printf '  %-26s private keys found: %-4s CA keys: %s\n' "$name" "$n" "${held:-none}"
}

if [ "${1:-}" = --root ]; then
    shift
    [ $# -gt 0 ] || { echo "usage: $0 --root NAME=DIR ..." >&2; exit 2; }
    for a in "$@"; do scan "${a%%=*}" "${a#*=}"; done
else
    [ "$(id -u)" = 0 ] || { echo "run as root: the scan reads every container's filesystem" >&2; exit 2; }
    CONTAINERS=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' | sort)
    [ -n "$CONTAINERS" ] || fail "no running container in compose project $PROJECT, key isolation verified nothing"
    for c in $CONTAINERS; do
        pid=$(docker inspect -f '{{.State.Pid}}' "$c")
        if [ -z "$pid" ] || [ "$pid" = 0 ] || [ ! -d "/proc/$pid/root/" ]; then
            fail "$c: no process to read its filesystem through, key isolation UNVERIFIED"; continue
        fi
        scan "$c" "/proc/$pid/root"
        # Mounts: the custodian's private directories belong to it alone, and no
        # container mounts anything from the CA tree.
        for src in $(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$c"); do
            case "$src" in
                "$CA_KEY_DIR"|"$CA_STATE_DIR"|"$CA_INBOX_DIR") [ "$c" = "$CUSTODIAN" ] || fail "$c mounts the custodian's $src" ;;
            esac
            # Nothing at all from the CA tree, not even one public certificate:
            # the public trust anchors are in $TRUST_DIR (ADR-024 §3).
            if [ "$src" = "$PKI" ] || [ "${src#"$PKI"/}" != "$src" ]; then
                fail "$c mounts from the CA tree: $src"
            fi
        done
    done
fi

if [ "$CUSTODIAN_SAW_KEY" = 1 ]; then
    echo "     ==> PASS: only $CUSTODIAN holds a CA key, and only the intermediate's"
else
    fail "the scan did not find the intermediate key in $CUSTODIAN, key isolation UNVERIFIED"
fi
exit "$RC"
