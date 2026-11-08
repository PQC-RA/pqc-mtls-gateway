#!/bin/bash
# 2026-11-07 re-run, test stand .27, nothing live. One stopwatch for every timing: the server-side capture.
# Arms alternate sample by sample. Delay: netem on lo for the two test ports only, 25 ms each way (RTT 50 ms).
set -uo pipefail
cd /root/rerun-20261107; export OPENSSL_CONF=/etc/ssl/openssl.cnf; O=/opt/openssl-3.6.5/bin/openssl
N=${N:-60}; ORIG_MTU=$(ip -o link show lo | grep -oE "mtu [0-9]+" | cut -d" " -f2)
clean() { tc qdisc del dev lo root 2>/dev/null; ip link set dev lo mtu $ORIG_MTU; pkill -f "tcpdump -i lo -s 200" 2>/dev/null; true; }
trap clean EXIT
setdelay() { tc qdisc del dev lo root 2>/dev/null; if [ "$1" != 0 ]; then
  tc qdisc add dev lo root handle 1: prio && tc qdisc add dev lo parent 1:3 handle 30: netem delay ${1}ms
  for p in 31443 31444; do for d in sport dport; do tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip $d $p 0xffff flowid 1:3; done; done; fi
  echo "# delay each way ${1} ms: $(tc qdisc show dev lo | tr "\n" " ")" >> env.txt; }
arm() { # arm <name> : prints read written verify sigtype group staple
  local a=$1 p d extra; case $a in pq*) p=31443; d=pki/pq ;; cl*) p=31444; d=pki/cl ;; esac
  case $a in
    *-leaf)        extra="-cert $d/device.crt -key $d/device.key -verifyCAfile $d/ca-chain.crt" ;;
    *-leaf-staple) extra="-cert $d/device.crt -key $d/device.key -verifyCAfile $d/ca-chain.crt -status" ;;
    *-trust)       extra="-cert $d/device.crt -key $d/device.key -CAfile $d/ca-chain.crt" ;;
    *-full)        extra="-cert $d/device.crt -key $d/device.key -cert_chain $d/ca-chain.crt -verifyCAfile $d/ca-chain.crt" ;;
  esac
  (printf "GET / HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: close\r\n\r\n"; sleep 0.25) | \
    $O s_client -connect 127.0.0.1:$p -servername pqc-gw.local -verify_return_error -ign_eof $extra 2>&1 | \
    awk -v a=$a "/SSL handshake has read/{r=\$5; w=\$9} /^Verification:/{v=\$2} /^Peer signature type/{s=\$4} /^Negotiated TLS1.3 group/{g=\$4} /Cert Status:/{st=\$3} /^HTTP\\/1.1/{h=\$2} END{printf \"%s\t%s\t%s\t%s\t%s\t%s\t%s\n\", r, w, v, s, g, (st==\"\"?\"-\":st), (h==\"\"?\"-\":h)}"
}
ARMS="pq-leaf pq-leaf-staple pq-trust pq-full cl-leaf cl-leaf-staple cl-trust cl-full"
{ echo "# $(date -u +%FT%TZ) $(hostname) $(uname -r) cc=$(sysctl -n net.ipv4.tcp_congestion_control) $($O version)"
  echo "# server: $(docker exec rerun-nginx nginx -v 2>&1) in clean1-gateway:11a5422; client: openssl s_client"; } > env.txt
ip link set dev lo mtu 1500
printf "delay_each_way_ms\ti\tarm\tstart\tend\tread\twritten\tverify\tpeer_sig\tgroup\tstaple\thttp\n" > samples.tsv
for dly in 0 25; do
  setdelay $dly
  tcpdump -i lo -s 200 -n -w cap-delay$dly.pcap "tcp port 31443 or tcp port 31444" >/dev/null 2>&1 & sleep 1
  for a in $ARMS; do arm $a >/dev/null; done                      # one warm-up connection per arm, not counted
  for i in $(seq 1 $N); do for a in $ARMS; do
    s=$(date +%s.%N); out=$(arm $a); e=$(date +%s.%N); printf "%s\t%s\t%s\t%s\t%s\t%s\n" $dly $i $a $s $e "$out" >> samples.tsv
  done; done
  sleep 1; pkill -f "tcpdump -i lo -s 200"; sleep 1
done
setdelay 0
echo "--- CPU, openssl s_time, client side, against the same servers, no delay (3 x 10 s per arm, alternating)" > cpu.txt
for w in 1 2 3; do for a in "pq 31443" "cl 31444"; do set -- $a
  echo "=== $1 window $w $(date -u +%FT%TZ)" >> cpu.txt
  $O s_time -connect 127.0.0.1:$2 -new -time 10 -cert pki/$1/device.crt -key pki/$1/device.key -CAfile pki/$1/ca-chain.crt >> cpu.txt 2>&1
done; done
clean; echo "# done $(date -u +%FT%TZ); lo mtu $(ip -o link show lo | grep -oE "mtu [0-9]+"); qdisc $(tc qdisc show dev lo)" >> env.txt
wc -l samples.tsv; grep -E "^===|connections/user" cpu.txt
