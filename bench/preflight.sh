#!/usr/bin/env bash
# preflight.sh: run BEFORE every measurement campaign. Fails loud.
#
# WHY THIS EXISTS: two pieces of state do NOT survive a restart on this
# deployment, and both fail *silently* into invalid measurements:
#   1. pqc-shadow-mock does not auto-restart          -> every request 502s
#   2. the bench client may have no route -> every request 404/403
#      (a fresh deployment, or a policy store that was cleared)
# A run against either condition looks like "the gateway got slower", not like
# a broken testbed. Check, don't assume.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
GW=127.0.0.1
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
EXPORT="$EXPORT_DIR"
CA=/etc/pki/pqc-ca/ca-chain.crt
C=$REPO/admin-cert/gateway-admin.crt
K=$REPO/admin-cert/gateway-admin.key
CN=bench-client
fail=0
ok()  { printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
bad() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=1; }

echo "== preflight: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname) =="

# The tools README.md lists as requirements. Missing ones are installed here,
# not at deploy time: deploying the gateway should not pull in tcpdump. Without
# bc, throughput3.sh still prints per-window numbers but every derived field
# comes out 0.000, which looks like a measurement and is not. The load-average
# check below then catches any disturbance the install left behind.
declare -A PKG=( [bc]=bc [tc]=iproute2 [ss]=iproute2 [tcpdump]=tcpdump )
for t in bc tc tcpdump ss; do
  if ! command -v "$t" >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    echo "  ....  $t missing, installing ${PKG[$t]}"
    apt-get install -y "${PKG[$t]}" >/dev/null 2>&1 || true
  fi
  command -v "$t" >/dev/null 2>&1 && ok "$t present" || bad "$t MISSING (see README.md prerequisites)"
done
command -v docker >/dev/null 2>&1 && ok "docker present" || bad "docker MISSING"

for c in pqc-gateway pqc-mtls-management-api pqc-ca-custodian pqc-ocsp-pq pqc-crl-renewer pqc-shadow-mock; do
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  if [ "$st" = running ]; then ok "$c running"; else bad "$c is '$st'  (docker start $c)"; fi
done

routes=$(timeout 20 curl -sk --cacert "$CA" --cert "$C" --key "$K" "https://$GW/admin/policy/routes" 2>/dev/null \
         | python3 -c "import sys,json;print(','.join(json.load(sys.stdin).get('clients',{}).keys()))" 2>/dev/null)
case ",$routes," in
  *",$CN,"*) ok "route for $CN present" ;;
  *)         bad "route for $CN MISSING  (./re-apply-route.sh)" ;;
esac

body=$(timeout 20 curl -s --cacert "$EXPORT/ca-chain.crt" --cert "$EXPORT/client.crt" \
       --key "$EXPORT/client.key" "https://$GW/api/v1/status" 2>/dev/null)
if echo "$body" | grep -q "pqc-shadow-success"; then ok "end-to-end mTLS -> backend OK"
else bad "end-to-end FAILED (got: ${body:0:80})"; fi

grp=$(echo | timeout 20 /opt/openssl/bin/openssl s_client -connect $GW:443 \
      -CAfile "$EXPORT/ca-chain.crt" -cert "$EXPORT/client.crt" -key "$EXPORT/client.key" \
      -tls1_3 2>/dev/null | grep -E "Negotiated TLS1.3 group|Peer signature type" | tr '\n' ' ')
if echo "$grp" | grep -q X25519MLKEM768 && echo "$grp" | grep -q mldsa65; then
  ok "PQC handshake: X25519MLKEM768 + mldsa65"
else bad "handshake not PQC: $grp"; fi

sw=$(free -m | awk '/Swap:/{print $3}')
if [ "${sw:-0}" -eq 0 ]; then ok "swap unused (0 MiB)"
else bad "swap in use (${sw} MiB), latency tails contaminated; swapoff -a && swapon -a"; fi

la=$(awk '{print $1}' /proc/loadavg)
if awk -v l="$la" 'BEGIN{exit !(l<1.0)}'; then ok "load average $la (idle)"
else bad "load average $la, let the box settle"; fi

idx=/etc/pki/pqc-ca/intermediate/db/index.txt
echo "  INFO  CA index: $(grep -c '^R' $idx 2>/dev/null || echo 0) revoked, $(grep -c '^V' $idx 2>/dev/null || echo 0) valid"
echo "  INFO  cores=$(nproc)  mem=$(free -m | awk '/Mem:/{print $2}')MiB  openssl=$(/opt/openssl/bin/openssl version | awk '{print $2}')"

echo
if [ $fail -eq 0 ]; then echo "PREFLIGHT OK, safe to measure."; else echo "PREFLIGHT FAILED, do NOT measure."; exit 1; fi
