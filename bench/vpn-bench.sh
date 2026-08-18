#!/bin/bash
# Remote client over a real VPN path -> the PQC gateway on .99.
# Client: this Mac, OpenSSL 3.6.2 via Homebrew curl 8.20.0, over utun4.
# Metric: time_appconnect - time_connect, ms. Same metric as every other latency figure.
# Arms are interleaved so a host-side perturbation cannot land on one arm.
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
H=${VPN_GW:?set VPN_GW to the gateway address over the tunnel}
REPEATS=${REPEATS:-5}; N=${N:-120}

# THIS MUST NOT RUN ON THE GATEWAY HOST. The entire point is a real routed path;
# measuring .99 from .99 yields loopback numbers that would then be labelled
# "over VPN". That mislabelling is the same class of error as the s_server
# -CAfile artifact, so fail closed rather than measure the wrong thing.
_rtt=$(ping -c 3 -i 0.3 -W 2 "$H" 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
if [ -z "$_rtt" ]; then
  echo "ERROR: $H is not reachable -- is the VPN up?" >&2; exit 1
fi
if awk -v r="$_rtt" 'BEGIN{exit !(r < 0.5)}'; then
  echo "ERROR: RTT to $H is ${_rtt} ms. That is loopback or same-host, not a VPN path." >&2
  echo "       Run this from a machine OFF the hypervisor. Measuring here would" >&2
  echo "       produce loopback figures labelled as remote." >&2
  exit 1
fi
echo "path RTT to $H: ${_rtt} ms"


OUT=$S/vpn/vpn-latency.csv
echo "seq,arm,repeat,connect_ms,handshake_ms" > $OUT
ARMS="classical:19443:X25519:classical
hybrid:19444:X25519MLKEM768:pqc
pure:19445:MLKEM768:pqc
deployed:443:X25519MLKEM768:admin"
sq=0
for rep in $(seq 1 $REPEATS); do
  while IFS=: read -r arm port grp id; do
    [ -z "$arm" ] && continue
    sq=$((sq+1))
    if [ "$id" = "admin" ]; then
      CERT="$S/vpn/gateway-admin.crt"; KEY="$S/vpn/gateway-admin.key"; CA="$S/vpn/ca-chain.crt"
    else
      CERT="$S/vpn/$id/client.crt"; KEY="$S/vpn/$id/client.key"; CA="$S/vpn/$id/ca-chain.crt"
    fi
    for i in $(seq 1 $N); do
      $C -s -o /dev/null --cert "$CERT" --key "$KEY" --cacert "$CA" --curves "$grp" --tlsv1.3 \
         --resolve "pqc-gw.local:$port:$H" -w "%{time_connect} %{time_appconnect}\n" \
         "https://pqc-gw.local:$port/" 2>/dev/null
    done | awk -v s=$sq -v a=$arm -v r=$rep 'NR>20 && $2>0 {printf "%d,%s,%d,%.4f,%.4f\n", s, a, r, $1*1000, ($2-$1)*1000}' >> $OUT
  done <<< "$ARMS"
  echo "  repeat $rep done"
done
echo VPN-DONE
