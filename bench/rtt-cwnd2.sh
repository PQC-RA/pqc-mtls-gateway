#!/usr/bin/env bash
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
cd "$WORKDIR"
D=hermetic/pqc; PA=4443; PB=4444
OUT=$WORKDIR/rtt-cwnd.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }
ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
cleanup(){ tc qdisc del dev lo root 2>/dev/null||true; ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null||true
  ip route change table local local 127.0.0.1 dev lo proto kernel scope host src 127.0.0.1 initcwnd 10 2>/dev/null||true
  pkill -f "s_server -accept $PA" 2>/dev/null||true; pkill -f "s_server -accept $PB" 2>/dev/null||true; }
trap cleanup EXIT
pkill -f "s_server -accept $PA" 2>/dev/null||true; pkill -f "s_server -accept $PB" 2>/dev/null||true; sleep 1
ip link set dev lo mtu 1500
nohup $OSSL s_server -accept $PA -cert $D/server.crt -key $D/server.key -verifyCAfile $D/ca.crt -Verify 2 \
  -groups X25519MLKEM768 -tls1_3 -no_ticket -no_cache -www >/tmp/s_A.log 2>&1 &
nohup $OSSL s_server -accept $PB -cert $D/server.crt -key $D/server.key -CAfile $D/ca.crt -Verify 2 \
  -groups X25519MLKEM768 -tls1_3 -no_ticket -no_cache -www >/tmp/s_B.log 2>&1 &
sleep 2
cnt(){ echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$1 -cert $D/client.crt -key $D/client.key -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE"; }
fl(){ echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$1 -cert $D/client.crt -key $D/client.key 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}'; }
say "  A: $(cnt $PA) cert, flight $(fl $PA) B    B: $(cnt $PB) certs, flight $(fl $PB) B"
setcwnd(){ ip route change table local local 127.0.0.1 dev lo proto kernel scope host src 127.0.0.1 initcwnd "$1" 2>/dev/null
  local g; g=$(ip route show table local | awk '/^local 127.0.0.1 /{for(i=1;i<=NF;i++) if($i=="initcwnd") print $(i+1)}'); echo "${g:-10}"; }
med(){ sort -n | awk '{a[NR]=$1} END{m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }
sample(){ local p=$1 n=${2:-60} i; for i in $(seq 1 $n); do
    curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" --cert $D/client.crt --key $D/client.key \
      --cacert $D/ca.crt --curves X25519MLKEM768 --tlsv1.3 "https://127.0.0.1:$p/" 2>/dev/null
  done | awk '$2>0{printf "%.4f\n",($2-$1)*1000}' | med; }
tc qdisc del dev lo root 2>/dev/null||true; tc qdisc add dev lo root netem delay 25ms; sleep 1
RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f",$5}')
say "  RTT ${RTT} ms"; say
for iw in 10 20 30; do
  g=$(setcwnd $iw); sleep 1
  say "  initcwnd $g :  A(1 cert) $(sample $PA) ms    B(2 certs) $(sample $PB) ms"
done
setcwnd 10 >/dev/null
say "raw -> $OUT"
