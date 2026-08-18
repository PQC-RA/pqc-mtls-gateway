#!/usr/bin/env bash
# fullchain-test.sh: does a client that sends its FULL CHAIN exceed IW10 and
# therefore pay one extra round trip, as the original campaign reported?
#
# s_client -cert only ever sends the leaf, so the chain case must be driven with
# curl (which uses SSL_CTX_use_certificate_chain_file) and measured on the wire
# with tcpdump, not from s_client's own byte counters.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
cd "$(dirname "$0")"
E="$EXPORT_DIR"
LEAF=$E/client.crt
CHAIN=/tmp/client-fullchain.pem
cat $E/client.crt /etc/pki/pqc-ca/ca-chain.crt > $CHAIN

ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
cleanup(){ tc qdisc del dev lo root 2>/dev/null || true; ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true; }
trap cleanup EXIT
ip link set dev lo mtu 1500

wirebytes() { # wirebytes <certfile> -> "c2s s2c" TCP payload bytes for one handshake
  local cc=$1 cap=/tmp/fc.pcap
  rm -f $cap
  timeout 20 tcpdump -ni lo -w $cap "tcp port 443" >/dev/null 2>&1 &
  local TPID=$!
  sleep 1.2
  curl -s -o /dev/null --cert "$cc" --key $E/client.key --cacert $E/ca-chain.crt \
    https://127.0.0.1/api/v1/status >/dev/null 2>&1
  sleep 1.2
  kill $TPID 2>/dev/null; wait $TPID 2>/dev/null
  # client->server = dst port 443 ; server->client = src port 443
  local c2s s2c
  c2s=$(tcpdump -nr $cap "tcp dst port 443" 2>/dev/null | grep -oE 'length [0-9]+' | awk '{s+=$2} END{print s+0}')
  s2c=$(tcpdump -nr $cap "tcp src port 443" 2>/dev/null | grep -oE 'length [0-9]+' | awk '{s+=$2} END{print s+0}')
  echo "$c2s $s2c"
}

echo "=== 1. What curl actually puts on the wire (TCP payload, one handshake) ==="
printf '  %-22s %12s %12s\n' "client cert file" "c2s bytes" "s2c bytes"
read -r L1 L2 <<<"$(wirebytes $LEAF)"
printf '  %-22s %12s %12s\n' "leaf only (1 cert)" "$L1" "$L2"
read -r C1 C2 <<<"$(wirebytes $CHAIN)"
printf '  %-22s %12s %12s\n' "full chain (3 certs)" "$C1" "$C2"
echo "  IW10 reference: ~14600 B per direction"
echo

if [ "${C1:-0}" -le "${L1:-0}" ]; then
  echo "  NOTE: curl did NOT send a larger client flight, the chain case is not"
  echo "        exercised, so the RTT test below cannot answer the question."
fi

echo "=== 2. netem 25ms (RTT ~50ms): leaf vs full-chain client ==="
med(){ sort -n | awk '{a[NR]=$1} END{if(NR==0){print "-";exit} m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }
run(){ local cc=$1 n=${2:-40}; for i in $(seq 1 $n); do
    curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
      --cert "$cc" --key $E/client.key --cacert $E/ca-chain.crt \
      https://127.0.0.1/api/v1/status 2>/dev/null
  done | awk '$2>0{printf "%.4f\n",($2-$1)*1000}' | med; }

tc qdisc del dev lo root 2>/dev/null || true
echo "  --- baseline (no delay)"
printf '    leaf  : %s ms\n' "$(run $LEAF)"
printf '    chain : %s ms\n' "$(run $CHAIN)"
tc qdisc add dev lo root netem delay 25ms; sleep 1
RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f",$5}')
echo "  --- netem 25ms one-way (measured RTT ${RTT} ms)"
LM=$(run $LEAF); CM=$(run $CHAIN)
printf '    leaf  : %s ms\n' "$LM"
printf '    chain : %s ms\n' "$CM"
awk -v l="$LM" -v c="$CM" -v r="${RTT:-0}" 'BEGIN{
  d=c-l; printf "    delta (chain-leaf) = %.2f ms;  one RTT = %.1f ms\n", d, r;
  if (r>0 && d > r*0.6) print "    ==> CHAIN CLIENT PAYS ~ONE EXTRA ROUND TRIP";
  else print "    ==> no extra round trip attributable to the chain";
}'
