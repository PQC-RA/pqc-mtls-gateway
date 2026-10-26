#!/usr/bin/env bash
# crl-fastpath.sh: assert that the Lua active-enforcement revocation check
# actually FIRES, on BOTH the /api/ and the /admin/ path.
#
# Why this test exists
# The gateway enforces revocation twice:
#
#   1. nginx's static `ssl_crl`, refreshed only when the entrypoint's
#      /signals/reload-nginx watcher reloads nginx (NGINX_RELOAD_POLL_INTERVAL,
#      default 5 s). Refuses at the TLS/HTTP boundary -> HTTP 400
#      ("The SSL certificate error"), before access_by_lua runs at all.
#   2. crl_worker.lua's shared-dict mirror, checked inline by policy_router.lua
#      and admin_jwt.lua -> ngx.exit(444): connection closed, no response.
#
# (2) exists to cover the window before (1) reloads. At a 10 s poll it always
# lost to the 5 s reload watcher, and because the poller restarts in
# init_worker_by_lua on every worker start, each reload reset its cycle: it was
# second by construction and never fired, and nothing noticed because no test
# asserted it. This test is the tripwire.
#
# Why it pauses the reload watcher
# Leaving both layers armed makes this a race, and a race makes the test flaky,
# which is the exact defect it is meant to catch. So it SIGSTOPs the watcher
# subshell for the duration: nginx's ssl_crl then cannot refresh, and the Lua
# fast path is the ONLY thing that can refuse the certificate. If it stays
# silent, the request succeeds and the test fails, deterministically. The
# watcher is resumed on every exit path, including Ctrl-C.
#
# This sends SIGSTOP/SIGCONT to a process inside a RUNNING gateway and leaves a
# revoked certificate in the CA index, so it refuses to run unless the operator
# sets CRLFAST_I_UNDERSTAND=1. It is deliberately not in CI.
set -uo pipefail
if [ "${CRLFAST_I_UNDERSTAND:-0}" != 1 ]; then
  echo "refusing to run: this pauses the reload watcher in a running gateway and"
  echo "leaves a revoked test certificate behind. Set CRLFAST_I_UNDERSTAND=1."
  exit 2
fi
export OPENSSL_CONF=/etc/ssl/openssl.cnf
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
# The repository this harness lives in: admin-cert/, scripts/ and certs/.
REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PKI=/etc/pki/pqc-ca
CA=$PKI/ca-chain.crt
C=$REPO/admin-cert/gateway-admin.crt
K=$REPO/admin-cert/gateway-admin.key
GW=pqc-gateway
ADM=(curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1")
WORK=$(mktemp -d)
cd "$REPO" || exit 1
RC=0

# -- freeze the reload watcher -------------------------------------------------
WPID=$(docker exec $GW sh -c \
  "ps -eo pid,args | awk '\$2==\"/bin/bash\" && \$3==\"/usr/local/bin/entrypoint.sh\" {print \$1}'" 2>/dev/null | head -1)
if [ -z "${WPID:-}" ]; then
  echo "FATAL: could not identify the reload-watcher subshell in $GW"; exit 1
fi
resume(){ docker exec $GW sh -c "kill -CONT $WPID" >/dev/null 2>&1 || true; }
trap 'resume' EXIT INT TERM
docker exec $GW sh -c "kill -STOP $WPID" >/dev/null 2>&1 \
  || { echo "FATAL: could not pause the reload watcher (pid $WPID)"; exit 1; }
echo "[*] reload watcher (pid $WPID) paused, nginx's static ssl_crl cannot refresh"
echo "    => only the Lua fast path can refuse anything below"

# -- issue a throwaway identity ------------------------------------------------
CN="crlfast-$RANDOM"
PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=$CA PQC_ADMIN_CERT=$C PQC_ADMIN_KEY=$K \
  ./scripts/issue-cert.sh "$CN" http://shadow-mock:80 >"$WORK/issue.log" 2>&1
CRT=$REPO/certs/$CN/$CN.crt; KEY=$REPO/certs/$CN/$CN.key
if [ ! -f "$CRT" ]; then
  echo "FATAL: issuance failed"; tail -5 "$WORK/issue.log"; exit 1
fi
SER=$("$OSSL" x509 -in "$CRT" -noout -serial | cut -d= -f2)
echo "[*] issued $CN, serial $SER"

# curl exits 52 ("empty reply") when nginx closes without a response: ngx.exit(444).
probe(){ # probe <path>
  local code rc
  code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" \
         --cert "$CRT" --key "$KEY" "https://127.0.0.1$1" 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 52 ] || [ "$code" = "000" ]; then echo "LUA-444"; else echo "$code"; fi
}

API_PRE=$(probe /api/v1/status)
ADM_PRE=$(probe /admin/health)
echo "[*] before revocation:  /api/v1/status -> $API_PRE   /admin/health -> $ADM_PRE"
if [ "$API_PRE" = "LUA-444" ] || [ "$ADM_PRE" = "LUA-444" ]; then
  echo "  ==> *** cannot run: the fresh certificate is already being dropped ***"; exit 1
fi

# -- revoke ----------------------------------------------------------------------
"${ADM[@]}" -X POST "https://127.0.0.1/admin/certs/revoke" -H "Content-Type: application/json" \
  -d "{\"serial\":\"$SER\",\"reason\":\"cessationOfOperation\"}" >"$WORK/revoke.log" 2>&1
if ! grep -q '"message"' "$WORK/revoke.log"; then
  echo "  ==> *** revocation call failed: $(head -c 150 "$WORK/revoke.log") ***"; exit 1
fi
echo "[*] revoked; polling both paths for the Lua drop"

# -- assert both paths drop it ---------------------------------------------------
# Budget generously: the wait is the renewer's sentinel poll plus CRL
# regeneration (ML-DSA signing) plus at most one crl_worker interval, not the
# reload path, which is frozen.
check(){ # check <label> <path>
  local label=$1 path=$2 t0 r ms
  t0=$(date +%s%N)
  for _ in $(seq 1 150); do
    sleep 0.2
    r=$(probe "$path")
    [ "$r" = "LUA-444" ] && {
      ms=$(( ($(date +%s%N) - t0) / 1000000 ))
      echo "  $label: dropped by the Lua fast path after ${ms}ms  ==> PASS"
      return 0
    }
  done
  echo "  $label: still answering after 30s  ==> *** FAIL: the fast path is silent ***"
  RC=1
}
check "/api/v1/status" /api/v1/status
check "/admin/health " /admin/health

# -- restore and confirm the slow path still works -------------------------------
resume; trap - EXIT INT TERM
echo "[*] reload watcher resumed"
HITS=$(docker exec $GW sh -c 'grep -h "CRITICAL PROTECTION" /var/log/nginx/*.log 2>/dev/null | wc -l' 2>/dev/null || echo 0)
echo "  CRITICAL PROTECTION log lines to date: ${HITS:-0}"
"${ADM[@]}" -X DELETE "https://127.0.0.1/admin/policy/routes/$CN" >/dev/null 2>&1
echo "  (test route removed; $CN left revoked, deliberately)"
rm -rf "$WORK"

[ "$RC" -eq 0 ] && echo "CRL FAST PATH OK" || echo "*** CRL FAST PATH FAILED ***"
exit "$RC"
