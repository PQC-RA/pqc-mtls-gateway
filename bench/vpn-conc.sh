#!/bin/bash
# Concurrency from a genuinely off-host client (this Mac, over the VPN) against the
# deployed gateway on .99:443. The earlier run drove load from .24, which shares a
# hypervisor with .99, so its rising latency was client-side contention.
# Directory holding the client identity for the VPN probes:
#   gateway-admin.crt/.key + ca-chain.crt, and classical/ and pqc/ subdirs
#   each with client.crt/.key/ca-chain.crt. See env.sh.example.
S=${VPN_BENCH_DIR:-$HOME/vpn-bench}
# curl MUST be linked against OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
# macOS system curl is LibreSSL and cannot do ML-DSA at all, hence the
# Homebrew default. Override with CURL=... on any other platform.
C=${CURL:-/opt/homebrew/opt/curl/bin/curl}
[ -x "$C" ] || { echo "ERROR: no PQ-capable curl at $C -- set CURL=..." >&2; exit 1; }
"$C" -V | head -1 | grep -qE "OpenSSL/3\.([5-9]|[1-9][0-9])" || \
  { echo "ERROR: $C is not linked against OpenSSL >= 3.5" >&2; exit 1; }
OUT=$S/vpn/vpn-conc.csv
echo "concurrency,worker,code,handshake_ms" > $OUT
PER=20
for CONC in 1 10 20 30 50; do
  rm -f $S/vpn/.w-*
  for w in $(seq 1 $CONC); do
    ( for i in $(seq 1 $PER); do
        $C -s -o /dev/null --cert "$S/vpn/gateway-admin.crt" --key "$S/vpn/gateway-admin.key" \
           --cacert "$S/vpn/ca-chain.crt" --resolve pqc-gw.local:443:${VPN_GW:?set VPN_GW to the gateway address over the tunnel} \
           -w "%{http_code} %{time_connect} %{time_appconnect}\n" https://pqc-gw.local/ 2>/dev/null
      done > $S/vpn/.w-$w ) &
  done
  wait
  for w in $(seq 1 $CONC); do
    awk -v c=$CONC -v w=$w '$3>0{printf "%d,%d,%s,%.4f\n", c, w, $1, ($3-$2)*1000}' $S/vpn/.w-$w >> $OUT
  done
  ok=$(awk -F, -v c=$CONC '$1==c && $3!="000"' $OUT | wc -l | tr -d ' ')
  echo "  concurrency $CONC: $ok / $((CONC*PER)) completed"
done
rm -f $S/vpn/.w-*
echo CONC-DONE
