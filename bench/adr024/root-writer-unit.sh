#!/usr/bin/env bash
# root-writer-unit.sh: ca_run_as_root_writer (scripts/lib/ca-layout.sh), the way
# deploy.sh signs the bootstrap admin certificate as root on the custodian's
# state. However the call ends (success, failure, or the script stopped by a
# signal while openssl runs), every file of the state must be the custodian's
# again afterwards, or its next CRL pass fails with EACCES (pre-merge review B4).
# One throwaway container, no network.
#
# Usage: root-writer-unit.sh <image>   (bash, find, setpriv: the custodian image)
set -euo pipefail
IMG=${1:?usage: root-writer-unit.sh <image>}
repo=$(cd "$(dirname "$0")/../.." && pwd)
docker run --rm --network none --user 0:0 -v "$repo:/repo:ro" --entrypoint bash "$IMG" -c '
set -uo pipefail
PASS=0; FAIL=0
check(){ if eval "$2"; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1"; FAIL=$((FAIL+1)); return 1; fi; }
. /repo/scripts/lib/ca-layout.sh
ca_layout_create
mkdir -p "$CA_STATE_DIR/db"; echo 1000 > "$CA_STATE_DIR/db/crlnumber"; : > "$CA_STATE_DIR/db/index.txt"
ca_layout_file_perms
# A stand-in for openssl ca run as root: it replaces index.txt and leaves a
# crlnumber.new, both root-owned, then takes a while (or fails).
cat > /tmp/fake-ca <<EOF
#!/bin/sh
echo "V	301231000000Z		1000	unknown	/CN=x" > $CA_STATE_DIR/db/index.txt.new
mv $CA_STATE_DIR/db/index.txt.new $CA_STATE_DIR/db/index.txt
echo 1001 > $CA_STATE_DIR/db/crlnumber.new
sleep "\${FAKE_SLEEP:-0}"
exit "\${FAKE_RC:-0}"
EOF
chmod +x /tmp/fake-ca
not_ours(){ find "$CA_STATE_DIR" -type f ! -uid "$CA_UID"; }
writer(){ bash -c ". /repo/scripts/lib/ca-layout.sh; ca_run_as_root_writer /tmp/fake-ca"; }

# (bash itself in the background, so the signal reaches the shell that set the traps)
FAKE_SLEEP=3 bash -c ". /repo/scripts/lib/ca-layout.sh; ca_run_as_root_writer /tmp/fake-ca" & pid=$!
sleep 1; kill -TERM "$pid"; wait "$pid"; rc=$?
check "stopped by SIGTERM while openssl runs: the script ends (130), every state file is the custodian again" "[ $rc = 130 ] && [ -z \"\$(not_ours)\" ]" || { echo "rc=$rc"; not_ours; }
ca_layout_file_perms

FAKE_RC=1 writer; rc=$?
check "openssl fails: its status is returned (1), every state file is the custodian again" "[ $rc = 1 ] && [ -z \"\$(not_ours)\" ]" || not_ours
ca_layout_file_perms

writer; rc=$?
check "openssl succeeds: 0, every state file is the custodian again" "[ $rc = 0 ] && [ -z \"\$(not_ours)\" ]" || not_ours

check "deploy.sh signs the bootstrap admin certificate through ca_run_as_root_writer" "grep -q \"ca_run_as_root_writer \\\"\\\$OSSL\\\" ca -config\" /repo/scripts/deploy.sh"

echo "$PASS/$((PASS+FAIL)) passed"
[ "$FAIL" = 0 ]'
