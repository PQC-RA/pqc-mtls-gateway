#!/usr/bin/env bash
# rtt-proof.sh: prove the +1 RTT explanation by controlled A/B/C.
#
# CLAIM: the original's extra round trip came from the server sending TWO
# certificates (an `s_server -CAfile` artifact), pushing its first flight over
# TCP's initial congestion window (IW10 ~= 14.6 KB). The deployment sends one,
# fits under, and pays nothing.
#
# Three arms, IDENTICAL PKI, identical group, identical everything except:
#   A  1 cert (-verifyCAfile), initcwnd 10   -> should be ~1 RTT  (~54 ms)
#   B  2 certs (-CAfile),      initcwnd 10   -> should be ~2 RTT  (~104 ms)
#   C  2 certs (-CAfile),      initcwnd 20   -> back to ~1 RTT    (~54 ms)
#
# B vs A isolates the cause. C vs B is the control that proves the mechanism is
# the CONGESTION WINDOW and not something else about sending two certificates:
# widen the window, same two certificates, penalty disappears.
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
D=hermetic/pqc
PA=4443; PB=4444
OUT=$WORKDIR/rtt-proof.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }

ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
LOROUTE=$(ip route show table local | grep -m1 "^local 127.0.0.0/8")
cleanup(){
  tc qdisc del dev lo root 2>/dev/null || true
  ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true
  ip route change table local $LOROUTE initcwnd 10 2>/dev/null || true
  pkill -f "s_server -accept $PA" 2>/dev/null || true
  pkill -f "s_server -accept $PB" 2>/dev/null || true
}
trap cleanup EXIT
pkill -f "s_server -accept $PA" 2>/dev/null || true
pkill -f "s_server -accept $PB" 2>/dev/null || true
sleep 1
ip link set dev lo mtu 1500

# A: -verifyCAfile  => verification without chain-building => server sends LEAF ONLY
nohup $OSSL s_server -accept $PA -cert $D/server.crt -key $D/server.key \
  -verifyCAfile $D/ca.crt -Verify 2 -groups X25519MLKEM768 -tls1_3 \
  -no_ticket -no_cache -www >/tmp/s_A.log 2>&1 &
# B: -CAfile => OpenSSL also sends the CA => server sends TWO certificates
nohup $OSSL s_server -accept $PB -cert $D/server.crt -key $D/server.key \
  -CAfile $D/ca.crt -Verify 2 -groups X25519MLKEM768 -tls1_3 \
  -no_ticket -no_cache -www >/tmp/s_B.log 2>&1 &
sleep 2
for p in $PA $PB; do ss -ltn 2>/dev/null | grep -q ":$p" || { say "FATAL: :$p not up"; tail -3 /tmp/s_$( [ $p = $PA ] && echo A || echo B).log | tee -a "$OUT"; exit 1; }; done

count(){ echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$1 -cert $D/client.crt -key $D/client.key -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE"; }
flight(){ echo | timeout 20 $OSSL s_client -connect 127.0.0.1:$1 -cert $D/client.crt -key $D/client.key 2>/dev/null | grep -oE "read [0-9]+" | awk '{print $2}'; }

say "=============== the only thing that differs ==============="
CA_N=$(count $PA); CB_N=$(count $PB)
FA=$(flight $PA);  FB=$(flight $PB)
say "  | arm | flag | server certs | server flight | vs IW10 (14,600 B) |"
say "  |-----|------|-------------:|--------------:|--------------------|"
say "  | A | \`-verifyCAfile\` | **$CA_N** | **${FA} B** | $(awk -v f="${FA:-0}" 'BEGIN{print (f<14600)?"UNDER":"OVER"}') |"
say "  | B | \`-CAfile\`       | **$CB_N** | **${FB} B** | $(awk -v f="${FB:-0}" 'BEGIN{print (f<14600)?"UNDER":"OVER"}') |"
say "  difference: $(( ${FB:-0} - ${FA:-0} )) B  = one ML-DSA-65 CA certificate"

med(){ sort -n | awk '{a[NR]=$1} END{if(NR==0){print "-";exit} m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }
sample(){ local port=$1 n=${2:-40} i
  for i in $(seq 1 $n); do
    curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
      --cert $D/client.crt --key $D/client.key --cacert $D/ca.crt \
      --curves X25519MLKEM768 --tlsv1.3 "https://127.0.0.1:$port/" 2>/dev/null
  done | awk '$2>0{printf "%.4f\n",($2-$1)*1000}' | med; }

setcwnd(){ ip route change table local $LOROUTE initcwnd $1 2>/dev/null \
           && echo "  initcwnd set to $1" | tee -a "$OUT" \
           || echo "  WARN: could not set initcwnd $1" | tee -a "$OUT"; }

say
say "=============== baseline, no added delay ==============="
tc qdisc del dev lo root 2>/dev/null || true; setcwnd 10; sleep 1
say "  A (1 cert): $(sample $PA) ms      B (2 certs): $(sample $PB) ms"

say
say "=============== netem 25 ms one-way (RTT ~50 ms) ==============="
tc qdisc add dev lo root netem delay 25ms; sleep 1
RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f",$5}')
say "  measured RTT: ${RTT} ms"
setcwnd 10; sleep 1
A10=$(sample $PA 60); B10=$(sample $PB 60)
say "  A  1 cert,  initcwnd 10 : ${A10} ms"
say "  B  2 certs, initcwnd 10 : ${B10} ms"
setcwnd 20; sleep 1
B20=$(sample $PB 60); A20=$(sample $PA 60)
say "  C  2 certs, initcwnd 20 : ${B20} ms   <- same two certs, wider window"
say "     1 cert,  initcwnd 20 : ${A20} ms"
setcwnd 10

say
say "=============== verdict ==============="
awk -v a="$A10" -v b="$B10" -v c="$B20" -v r="${RTT:-0}" 'BEGIN{
  printf "  B - A = %+.2f ms   (one RTT = %.1f ms)\n", b-a, r;
  printf "  B - C = %+.2f ms   (removing the penalty by widening the window)\n", b-c;
  printf "  C - A = %+.2f ms   (two certs, wide window, vs one cert)\n", c-a;
  print "";
  if (r>0 && (b-a) > r*0.6) print "  ==> CONFIRMED: the SECOND CERTIFICATE costs ~one extra round trip";
  else print "  ==> NOT confirmed: the second certificate did not cost a round trip";
  if (r>0 && (b-c) > r*0.6) print "  ==> CONFIRMED: widening initcwnd REMOVES it, the cause is the congestion window";
  else print "  ==> initcwnd change did not remove the penalty, cause is NOT the congestion window";
}' | tee -a "$OUT"

say
say "=============== packet timeline, 2-cert arm at 25 ms ==============="
say "  If the flight is split across two windows, tcpdump shows a ~50 ms gap"
say "  in the server->client direction mid-handshake."
rm -f /tmp/rtt.pcap
timeout 20 tcpdump -ni lo -w /tmp/rtt.pcap "tcp port $PB" >/dev/null 2>&1 &
TP=$!; sleep 1.2
curl -s -o /dev/null --cert $D/client.crt --key $D/client.key --cacert $D/ca.crt \
  --curves X25519MLKEM768 --tlsv1.3 "https://127.0.0.1:$PB/" >/dev/null 2>&1
sleep 1.2; kill $TP 2>/dev/null; wait $TP 2>/dev/null
tcpdump -nr /tmp/rtt.pcap "tcp src port $PB" 2>/dev/null \
  | awk 'NR==1{t0=$1} {split($1,a,":"); }1' \
  | head -14 | sed 's/^/     /' | tee -a "$OUT"
say
say "raw -> $OUT"
