#!/usr/bin/env bash
# crl-fastpath.sh: assert that the Lua active-enforcement revocation check
# FIRES on every mTLS location (/api/, /admin/, /) and time it from the
# revocation call itself.
#
# Why this test exists
# The gateway enforces revocation twice:
#
#   1. nginx's static `ssl_crl`, refreshed only when the entrypoint's
#      /signals/reload-nginx watcher reloads nginx (NGINX_RELOAD_POLL_INTERVAL,
#      default 5 s). Refuses at the TLS/HTTP boundary -> HTTP 400.
#   2. crl_worker.lua's shared-dict mirror, checked inline by policy_router.lua,
#      admin_jwt.lua and revocation_check.lua -> ngx.exit(444): connection
#      closed, no response.
#
# (2) exists to cover the window before (1) reloads. At a 10 s poll it always
# lost to the 5 s reload watcher and never fired, and nothing noticed because
# no test asserted it. This test is the tripwire.
#
# How it times
# No signal is sent to the crl-renewer; the regeneration under test is the real
# one, triggered by the revoke API's sentinel exactly as in production. All
# three paths are probed in parallel from one T0 taken immediately BEFORE the
# revoke call, so the figure is revoke-to-refusal, not refusal after the call
# returned.
#
# Why it pauses the reload watcher
# Leaving both layers armed makes this a race, and a race makes the test flaky,
# which is the exact defect it is meant to catch. So it SIGSTOPs the watcher
# subshell for the duration: nginx's ssl_crl then cannot refresh, and the Lua
# fast path is the ONLY thing that can refuse the certificate. A refusal that is
# not a 444 fails the test. The watcher is resumed on every exit path.
#
# This sends SIGSTOP/SIGCONT to a process inside a RUNNING gateway and leaves a
# revoked certificate in the CA index, so it refuses to run unless the operator
# sets CRLFAST_I_UNDERSTAND=1. It is deliberately not in CI.
#
# Environment (defaults target the standard deployment on this host):
#   GW_URL            https://127.0.0.1         mTLS listener
#   GW_CONTAINER      pqc-gateway
#   RENEWER_CONTAINER pqc-crl-renewer
#   PKI               /etc/pki/pqc-ca
#   ADMIN_CERT/KEY    admin-cert/gateway-admin.{crt,key} (authenticates issue+revoke only)
#   CN_PREFIX         crlfast
#   BUDGET_MS         30000                     give up after this long
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
GW_URL=${GW_URL:-https://127.0.0.1}
GW=${GW_CONTAINER:-pqc-gateway}
RENEWER=${RENEWER_CONTAINER:-pqc-crl-renewer}
PKI=${PKI:-/etc/pki/pqc-ca}
CA=$PKI/ca-chain.crt
C=${ADMIN_CERT:-$REPO/admin-cert/gateway-admin.crt}
K=${ADMIN_KEY:-$REPO/admin-cert/gateway-admin.key}
BUDGET_MS=${BUDGET_MS:-30000}
ADM=(curl -sk --cacert "$CA" --cert "$C" --key "$K" -H "X-PQC-CSRF:1")
WORK=$(mktemp -d)
cd "$REPO" || exit 1
RC=0
ms(){ date +%s%3N; }

# -- freeze the reload watcher -----------------------------------------------
WPID=$(docker exec "$GW" sh -c \
  "ps -eo pid,args | awk '\$2==\"/bin/bash\" && \$3==\"/usr/local/bin/entrypoint.sh\" {print \$1}'" 2>/dev/null | head -1)
if [ -z "${WPID:-}" ]; then
  echo "FATAL: could not identify the reload-watcher subshell in $GW"; exit 1
fi
resume(){ docker exec "$GW" sh -c "kill -CONT $WPID" >/dev/null 2>&1 || true; }
trap 'resume' EXIT INT TERM
docker exec "$GW" sh -c "kill -STOP $WPID" >/dev/null 2>&1 \
  || { echo "FATAL: could not pause the reload watcher (pid $WPID)"; exit 1; }
echo "[*] reload watcher (pid $WPID) paused, nginx's static ssl_crl cannot refresh"
echo "    => only the Lua fast path can refuse anything below"

# -- issue a throwaway identity (no backend => no route is written) ----------
CN="${CN_PREFIX:-crlfast}-$RANDOM"
PQC_GATEWAY=$GW_URL PQC_CA_CHAIN=$CA PQC_ADMIN_CERT=$C PQC_ADMIN_KEY=$K \
  ./scripts/issue-cert.sh "$CN" >"$WORK/issue.log" 2>&1
CRT=$REPO/certs/$CN/$CN.crt; KEY=$REPO/certs/$CN/$CN.key
if [ ! -f "$CRT" ]; then
  echo "FATAL: issuance failed"; tail -5 "$WORK/issue.log"; exit 1
fi
SER=$("$OSSL" x509 -in "$CRT" -noout -serial | cut -d= -f2)
echo "[*] issued $CN, serial $SER"

# :443 negotiates HTTP/2, where a 444 close surfaces as curl rc 92; over
# HTTP/1.1 it is rc 52 ("empty reply"). Both mean: closed without a response.
probe(){ # probe <path>
  local code rc
  code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" \
         --cert "$CRT" --key "$KEY" "$GW_URL$1" 2>/dev/null)
  rc=$?
  if [ "$code" = "000" ] && { [ "$rc" -eq 52 ] || [ "$rc" -eq 92 ]; }; then echo "LUA-444"
  else echo "$code"; fi
}

for p in /api/v1/status /admin/health /; do
  r=$(probe "$p")
  echo "[*] before revocation: $p -> $r"
  case "$r" in
    LUA-444|400|000) echo "  ==> *** cannot run: the fresh certificate is already refused on $p ***"; exit 1 ;;
  esac
done

# -- watch every path in parallel, from one clock ----------------------------
watch_path(){ # watch_path <path> <outfile>; writes "<ms> <result>" for the first non-baseline result
  local path=$1 out=$2 deadline r
  deadline=$(( $(cat "$WORK/t0") + BUDGET_MS ))
  while [ "$(ms)" -lt "$deadline" ]; do
    local t; t=$(ms); r=$(probe "$path")
    case "$r" in LUA-444|400|000) echo "$t $r" > "$out"; return ;; esac
    sleep 0.1
  done
  echo "none timeout" > "$out"
}

T0=$(ms); echo "$T0" > "$WORK/t0"
for p in /api/v1/status /admin/health /; do watch_path "$p" "$WORK/res$(echo "$p" | tr '/' '_')" & done
"${ADM[@]}" -X POST "$GW_URL/admin/certs/revoke" -H "Content-Type: application/json" \
  -d "{\"serial\":\"$SER\",\"reason\":\"cessationOfOperation\"}" >"$WORK/revoke.log" 2>&1
if ! grep -q '"message"' "$WORK/revoke.log"; then
  echo "  ==> *** revocation call failed: $(head -c 150 "$WORK/revoke.log") ***"; wait; exit 1
fi
echo "[*] revoked at T0 (sentinel only, the renewer is not signalled); watching /api/, /admin/, /"
wait

for p in /api/v1/status /admin/health /; do
  read -r t r < "$WORK/res$(echo "$p" | tr '/' '_')"
  if [ "$r" = "LUA-444" ]; then
    echo "  $p: dropped by the Lua fast path at T0+$(( t - T0 )) ms  ==> PASS"
  elif [ "$r" = "timeout" ]; then
    echo "  $p: still answering after ${BUDGET_MS} ms  ==> *** FAIL: the fast path is silent ***"; RC=1
  else
    echo "  $p: refused with $r at T0+$(( t - T0 )) ms, not 444  ==> *** FAIL: not the Lua layer ***"; RC=1
  fi
done

# -- stage timestamps from the renewer (same host clock) ---------------------
since=$(date -u -d @$(( T0 / 1000 - 1 )) +%FT%TZ)
echo "  renewer: $(docker logs --timestamps --since "$since" "$RENEWER" 2>&1 | grep -m1 'running CRL renewal' | cut -d' ' -f1)"

# -- restore and confirm the slow path still works ---------------------------
resume; trap - EXIT INT TERM
echo "[*] reload watcher resumed"
HITS=$(docker exec "$GW" sh -c 'grep -h "CRITICAL PROTECTION" /var/log/nginx/*.log 2>/dev/null | wc -l' 2>/dev/null || echo 0)
echo "  CRITICAL PROTECTION log lines to date: ${HITS:-0}"
echo "  ($CN left revoked, deliberately; files in $REPO/certs/$CN)"
rm -rf "$WORK"

[ "$RC" -eq 0 ] && echo "CRL FAST PATH OK" || echo "*** CRL FAST PATH FAILED ***"
exit "$RC"
