#!/usr/bin/env bash
# compose-policy-unit.sh: tests of scripts/check-compose-policy.sh (ADR-024
# test 4) for the CA tree and the trust directory: the compose file of this
# tree passes, and each violation added on top of it by an override is refused
# and named. Needs docker compose (nothing is pulled or started) and python3.
set -uo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
CHK="$repo/scripts/check-compose-policy.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
check() { if eval "$2"; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1"; FAIL=$((FAIL+1)); return 1; fi; }
show() { echo "      check-compose-policy.sh exited $(cat "$T/rc"); its output:"; sed 's/^/      | /' "$T/out"; }
run() { "$CHK" "$@" > "$T/out" 2>&1; echo $? > "$T/rc"; }
rc() { cat "$T/rc"; }
override() { # override NAME SERVICE VOLUME: a compose override adding one volume
    printf 'services:\n  %s:\n    volumes:\n      - %s\n' "$2" "$3" > "$T/$1.yml"
}

run "$repo/docker-compose.yml"
check "this tree's compose file passes" "[ $(rc) = 0 ]" || show

override crt management-api "/etc/pki/pqc-ca/internal-tls-ca.crt:/etc/pki/internal-tls-ca.crt:ro"
run "$repo/docker-compose.yml" "$T/crt.yml"
check "a single public certificate from /etc/pki/pqc-ca is refused" "[ $(rc) = 1 ] && grep -q 'management-api: mounts from the CA tree: /etc/pki/pqc-ca/internal-tls-ca.crt' $T/out" || show

override tree gateway "/etc/pki/pqc-ca:/etc/pki/ca-tree:ro"
run "$repo/docker-compose.yml" "$T/tree.yml"
check "the CA tree as a directory is refused" "[ $(rc) = 1 ] && grep -q 'gateway: mounts from the CA tree: /etc/pki/pqc-ca\$' $T/out" || show

override one gateway "/etc/pki/pqc-trust/internal-tls-ca.crt:/etc/pki/one.crt:ro"
run "$repo/docker-compose.yml" "$T/one.yml"
check "a single file from the trust directory is refused" "[ $(rc) = 1 ] && grep -q 'gateway: mounts a single file from the trust directory' $T/out" || show

override rw management-api "/etc/pki/pqc-trust:/etc/pki/pqc-trust:rw"
run "$repo/docker-compose.yml" "$T/rw.yml"
check "the trust directory mounted writable is refused" "[ $(rc) = 1 ] && grep -q 'management-api: mounts the trust directory /etc/pki/pqc-trust writable' $T/out" || show

printf 'services:\n  extra:\n    build: docker/pki-dist\n' > "$T/untagged.yml"
run "$repo/docker-compose.yml" "$T/untagged.yml"
check "a built service without an image tag is refused" "[ $(rc) = 1 ] && grep -q 'extra: built without an explicit release tag' $T/out" || show

printf 'services:\n  pki-dist:\n    image: pqc-gw-pki-dist:latest\n' > "$T/latest.yml"
run "$repo/docker-compose.yml" "$T/latest.yml"
check "a built service tagged latest is refused" "[ $(rc) = 1 ] && grep -q 'pki-dist: built without an explicit release tag (image: pqc-gw-pki-dist:latest)' $T/out" || show

override parent gateway "/var/lib/pqc-ca:/x:ro"
run "$repo/docker-compose.yml" "$T/parent.yml"
check "9-4: a parent of the custodian key directory (/var/lib/pqc-ca) is refused" "[ $(rc) = 1 ] && grep -q 'gateway: mounts /var/lib/pqc-ca, a parent of /var/lib/pqc-ca/key' $T/out" || show

override etcpki gateway "/etc/pki:/y:ro"
run "$repo/docker-compose.yml" "$T/etcpki.yml"
check "9-4: a parent of the CA tree (/etc/pki) is refused" "[ $(rc) = 1 ] && grep -q 'gateway: mounts /etc/pki, a parent of /etc/pki/pqc-ca' $T/out" || show

override dslash gateway "/var/lib/pqc-ca//key:/z:ro"
run "$repo/docker-compose.yml" "$T/dslash.yml"
check "9-4: a non-normalised path to the key directory (/var/lib/pqc-ca//key) is refused" "[ $(rc) = 1 ] && grep -q 'gateway: mounts the custodian.s /var/lib/pqc-ca/key' $T/out" || show

override keyrw pqc-ca-custodian "/var/lib/pqc-ca/key:/var/lib/pqc-ca/key:rw"
run "$repo/docker-compose.yml" "$T/keyrw.yml"
check "9-4: the custodian key mount writable is refused" "[ $(rc) = 1 ] && grep -q 'pqc-ca-custodian: mounts the CA key directory /var/lib/pqc-ca/key writable' $T/out" || show

echo "$PASS/$((PASS + FAIL)) passed"
[ "$FAIL" = 0 ]
