#!/usr/bin/env bash
# entrypoint-ca-unit.sh: the gateway entrypoint's wait for the CA files and its
# CRL reload watcher (docker/gateway/entrypoint.sh), sourced and driven with a
# fake nginx. Needs bash and GNU stat only: no Docker, no network, no root.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
EP="$repo/docker/gateway/entrypoint.sh"
W=$(mktemp -d)
cleanup() { jobs -pr | xargs -r kill; rm -rf "$W"; }
trap cleanup EXIT
PASS=0; FAIL=0
# shellcheck source=docker/gateway/entrypoint.sh
ep() { . "$EP"; }   # sourcing stops before anything runs (the guard in the file)
check() { if eval "$2"; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1"; FAIL=$((FAIL+1)); fi; }

# A fake nginx: records its calls; fails -t or -s reload while a flag file exists.
mkdir "$W/bin"
cat > "$W/bin/nginx" <<FAKE
#!/bin/sh
echo "\$*" >> "$W/calls"
if [ "\$1" = -t ] && [ -e "$W/t-broken" ]; then echo "nginx: [emerg] fake: cannot load the CRL" >&2; exit 1; fi
if [ "\$1" = -s ] && [ -e "$W/reload-broken" ]; then echo "nginx: [error] fake: invalid PID number" >&2; exit 1; fi
exit 0
FAKE
chmod +x "$W/bin/nginx"
export PATH="$W/bin:$PATH"
export NGINX_CRL_FILE="$W/crl.pem" NGINX_CA_CHAIN_FILE="$W/chain.crt" NGINX_PID_FILE="$W/nginx.pid" NGINX_RELOAD_POLL_INTERVAL=1

# --- the wait for the CA files -------------------------------------------------
t0=$(date +%s)
rc=0; ( ep; wait_for_ca_files "$NGINX_CRL_FILE" "$NGINX_CA_CHAIN_FILE" 2 ) > "$W/wait.out" 2> "$W/wait.err" || rc=$?
t1=$(date +%s)
check "no CA files: the wait fails after its time (exit 1, $((t1 - t0)) s)" "[ $rc = 1 ] && [ $((t1 - t0)) -ge 2 ] && [ $((t1 - t0)) -lt 6 ]"
check "  ... naming the files and the custodian" "grep -q 'FATAL: .*crl.pem' $W/wait.err && grep -q pqc-ca-custodian $W/wait.err"
check "the entrypoint stops when the wait fails" "grep -qx 'wait_for_ca_files \"\$CRL_FILE\" \"\$CA_CHAIN_FILE\" \"\$CA_WAIT_S\" || exit 1' $EP"
( sleep 1; echo crl > "$NGINX_CRL_FILE"; echo chain > "$NGINX_CA_CHAIN_FILE" ) &
rc=0; ( ep; wait_for_ca_files "$NGINX_CRL_FILE" "$NGINX_CA_CHAIN_FILE" 5 ) > /dev/null || rc=$?
check "files published while it waits: the wait succeeds" "[ $rc = 0 ]"
wait

# --- the reload watcher -----------------------------------------------------------
replace_crl() { echo "crl $1" > "$W/crl.new"; mv -f "$W/crl.new" "$NGINX_CRL_FILE"; }   # rename(2), as the custodian
: > "$W/calls"; touch "$NGINX_PID_FILE"
( ep; watch_crl ) > "$W/w.out" 2> "$W/w.err" &
sleep 1.5
touch "$W/t-broken"; replace_crl 1; sleep 3.5
check "a CRL nginx -t refuses: ERROR with nginx's own message" "grep -q 'did not reload' $W/w.err && grep -q '\[emerg\] fake: cannot load the CRL' $W/w.err"
check "  ... reported once, retried every poll" "[ \$(grep -c 'did not reload' $W/w.err) = 1 ] && [ \$(grep -c '^-t -q' $W/calls) -ge 2 ] && ! grep -q '^-s reload' $W/calls"
rm "$W/t-broken"; sleep 2
check "  ... reloaded once nginx accepts it" "grep -q 'nginx reloaded' $W/w.out && grep -q '^-s reload' $W/calls"
: > "$W/w.err"; touch "$W/reload-broken"; replace_crl 2; sleep 2.5
check "a reload that fails: ERROR with nginx's own message" "grep -q 'did not reload' $W/w.err && grep -q '\[error\] fake: invalid PID number' $W/w.err"
rm "$W/reload-broken"; sleep 2
check "  ... reloaded once it works" "[ \$(grep -c 'nginx reloaded' $W/w.out) = 2 ]"
check "the watcher is still running" "[ -n \"\$(jobs -pr)\" ]"

echo "$PASS/$((PASS + FAIL)) passed"
[ "$FAIL" = 0 ]
