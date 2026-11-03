#!/usr/bin/env bash
# key-isolation-unit.sh: tests of bench/check-key-isolation.sh (ADR-024 test 2).
#
#   1. --root mode on directory trees: a CA key anywhere in a tree is found
#      (not only where mounts arrive), each PEM block on its own; prose that
#      mentions a private key is not a key; /proc, /sys and /dev are pruned and
#      symlinks are not followed; an encrypted key fails; the canary.
#   2. docker mode, for real, when run as root on a Linux host with Docker and
#      an image is given: a CA key in a container's writable layer and one in
#      a tmpfs are found through /proc/<pid>/root; the custodian's key in its
#      volume mount is the canary. Skipped otherwise (it says so).
#
# Usage: key-isolation-unit.sh [image]   (any image with `sleep`)
# Environment: OSSL (default /opt/openssl/bin/openssl, else openssl on PATH).
set -uo pipefail
IMG=${1:-}
repo=$(cd "$(dirname "$0")/../.." && pwd)
CHK="$repo/bench/check-key-isolation.sh"
OSSL=${OSSL:-/opt/openssl/bin/openssl}; [ -x "$OSSL" ] || OSSL=$(command -v openssl)
export OSSL OPENSSL_CONF=/dev/null
T=$(mktemp -d)
P="keyiso-$$"
cleanup() {
    if [ -n "${STARTED:-}" ]; then docker rm -f "$P-cust" "$P-app" > /dev/null; docker volume rm "$P-key" > /dev/null; fi
    rm -rf "$T"
}
trap cleanup EXIT
PASS=0; FAIL=0
check() { if eval "$2"; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1"; FAIL=$((FAIL+1)); return 1; fi; }
# After a failed check: what the scanner said, and its exit code.
show() { echo "      check-key-isolation.sh exited $(cat "$T/rc"); its output:"; sed 's/^/      | /' "$T/out"; }
q() { "$@" > "$T/q.log" 2>&1 || { echo "FAILED: $*"; cat "$T/q.log"; exit 1; }; }

# --- a root CA, an intermediate it signed, another CA, a leaf key -------------------
mkdir -p "$T/pki"; cd "$T/pki" || exit 1
q "$OSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Unit Root CA" -days 2 -keyout root.key -out root.crt
q "$OSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Unit Intermediate CA" -days 2 -keyout int.key -out int.crt
q "$OSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Unit Internal TLS CA" -days 2 -keyout tls.key -out tls.crt
q "$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
q "$OSSL" pkey -in int.key -aes256 -passout pass:secret -out int-enc.key
export CA_CERTS="$T/pki/root.crt $T/pki/int.crt $T/pki/tls.crt" CA_INT_CERT="$T/pki/int.crt" CUSTODIAN_CONTAINER=cust
run() { "$CHK" --root "$@" > "$T/out" 2>&1; echo $? > "$T/rc"; }
rc() { cat "$T/rc"; }
tree() { rm -rf "${T:?}/${1:?}"; mkdir -p "$T/$1"; }
put() { mkdir -p "$(dirname "$T/$1")"; cat > "$T/$1"; }

# --- 1. --root mode ------------------------------------------------------------------
tree cust; put cust/var/lib/pqc-ca/key/intermediate-ca.key < int.key
tree app
put app/run/secrets/signing.key < leaf.key
printf 'To make one: openssl genpkey ... > key.pem\n# -----BEGIN PRIVATE KEY----- appears in the file\n' | put app/usr/share/doc/README
put app/proc/1/root-ca.pem < root.key            # pruned: /proc
put app/sys/x/root-ca.pem < root.key             # pruned: /sys
ln -s "$T/pki/root.key" "$T/app/etc-root-link.pem"  # a symlink is not followed
# A library that carries the header text, as libgnutls does: not a key.
printf '\177ELF\0\0\n-----BEGIN RSA PRIVATE KEY-----\n\0\001\002not base64\n-----END RSA PRIVATE KEY-----\n' | put app/usr/lib/libfake.so
run cust="$T/cust" app="$T/app/"
check "clean: only the custodian holds a CA key, the intermediate's (exit 0)" "[ $(rc) = 0 ] && grep -q 'PASS: only cust holds' $T/out" || show
check "  ... the app's own (non-CA) key is found but is not a CA key" "grep -Eq 'app +private keys found: 1 ' $T/out" || show

tree baked; put baked/usr/lib/node_modules/x/test/fixture.pem < root.key
run cust="$T/cust" baked="$T/baked"
check "a CA key baked deep in an image tree is found and named" "[ $(rc) = 1 ] && grep -q 'baked CAN READ THE root PRIVATE KEY (/usr/lib/node_modules/x/test/fixture.pem)' $T/out" || show
# Docker mode reads each container through /proc/<pid>/root, which is a
# symlink: the scan must go through a root given as a link.
ln -s "$T/baked" "$T/baked-link"
run cust="$T/cust" baked="$T/baked-link"
check "a root given as a symlink (as /proc/<pid>/root is) is scanned through" "[ $(rc) = 1 ] && grep -q 'baked CAN READ THE root PRIVATE KEY (/usr/lib/node_modules/x/test/fixture.pem)' $T/out" || show

tree multi; cat leaf.key tls.key | put multi/etc/ssl/bundle.pem
run cust="$T/cust" multi="$T/multi"
check "a CA key as the SECOND block of a file is found" "[ $(rc) = 1 ] && grep -q 'multi CAN READ THE tls PRIVATE KEY (/etc/ssl/bundle.pem)' $T/out" || show

tree enc; put enc/opt/x/key.pem < int-enc.key
run cust="$T/cust" enc="$T/enc"
check "an encrypted private key counts as a failure, not a pass" "[ $(rc) = 1 ] && grep -q 'enc: /opt/x/key.pem holds a private key whose public key cannot be derived' $T/out" || show

tree wrong; put wrong/var/lib/pqc-ca/key/root.key < root.key
run cust="$T/wrong"
check "the custodian holding the ROOT key fails, and the canary is missing" "[ $(rc) = 1 ] && grep -q 'cust CAN READ THE root PRIVATE KEY' $T/out && grep -q 'UNVERIFIED' $T/out" || show

tree none
run cust="$T/none" app="$T/app"
check "no intermediate key in the custodian: UNVERIFIED (exit 1)" "[ $(rc) = 1 ] && grep -q 'did not find the intermediate key in cust' $T/out" || show

# --- 2. docker mode --------------------------------------------------------------------
if [ -z "$IMG" ] || [ "$(id -u)" != 0 ] || ! docker info > /dev/null 2>&1 || [ ! -d /proc/1/root/ ]; then
    echo "SKIP  docker mode (needs an image argument, root, Docker and a Linux /proc)"
else
    STARTED=1
    docker volume create "$P-key" > /dev/null
    docker run --rm -i -u 0 -v "$P-key:/k" --entrypoint sh "$IMG" -c 'cat > /k/intermediate-ca.key' < int.key
    docker run -d --name "$P-cust" --label com.docker.compose.project="$P" -v "$P-key:/var/lib/pqc-ca/key:ro" \
        --entrypoint sleep "$IMG" infinity > /dev/null
    docker run -d --name "$P-app" --label com.docker.compose.project="$P" --tmpfs /scratch \
        --entrypoint sleep "$IMG" infinity > /dev/null
    docker exec -u 0 -i "$P-app" sh -c 'mkdir -p /usr/share/baked && cat > /usr/share/baked/root.pem' < root.key
    dock() { COMPOSE_PROJECT="$P" CUSTODIAN_CONTAINER="$P-cust" "$CHK" > "$T/out" 2>&1; echo $? > "$T/rc"; }
    dock
    check "docker: a CA key in a container's writable layer (no mount) is found" "[ $(rc) = 1 ] && grep -q '$P-app CAN READ THE root PRIVATE KEY (/usr/share/baked/root.pem)' $T/out" || show
    check "  ... and the custodian's key in its volume mount is the canary" "grep -q 'PASS: only $P-cust holds' $T/out"
    docker exec -u 0 "$P-app" rm /usr/share/baked/root.pem
    docker exec -u 0 -i "$P-app" sh -c 'cat > /scratch/tls.pem' < tls.key
    dock
    check "docker: a CA key in a tmpfs is found" "[ $(rc) = 1 ] && grep -q '$P-app CAN READ THE tls PRIVATE KEY (/scratch/tls.pem)' $T/out" || show
    docker exec -u 0 "$P-app" rm /scratch/tls.pem
    dock
    check "docker: with both removed, the stack passes (exit 0)" "[ $(rc) = 0 ]" || show
fi

echo "$PASS/$((PASS + FAIL)) passed"
[ "$FAIL" = 0 ]
