#!/usr/bin/env bash
# netem-sweep.sh: does the PQC handshake pay an extra round trip at realistic
# RTT? The test is whether its server flight overflows TCP's initial congestion
# window (IW10 = 14,480 B = 10 * 1448) while a classical flight does not.
#
# Measured answer for these arms: it does not. They serve an unstapled 11,071 B
# flight, which fits, and the delta over classical stays at 1-2 ms rather than
# growing with RTT. See EXPECTED-RESULTS.md.
#
# A stapled flight is 20,540 B and does cross the window, costing one round
# trip. That is a different configuration, not a different result.
#
# Method:
#   * tc netem delay <D>ms on lo  -> effective RTT = 2*D (loopback traverses lo twice)
#   * lo MTU forced to 1500 so flights segment as they would on a real link
#   * metric: curl time_appconnect - time_connect, MEDIAN of n samples per point
#   * arms: classical (:4434) vs hybrid (:4433), identical except algorithms
set -uo pipefail
cd "$(dirname "$0")"
N="${1:-60}"
OUT=netem_raw.txt; : > "$OUT"
ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
cleanup() { tc qdisc del dev lo root 2>/dev/null || true; ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true; }
trap cleanup EXIT
ip link set dev lo mtu 1500
echo "lo MTU 1500 (was $ORIG_MTU)"

median() { sort -n | awk '{a[NR]=$1} END{if(NR==0){print ", ";exit} m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }

sample() { # sample <port> <certdir> <group> <n>
  local port=$1 d=$2 g=$3 n=$4 i
  for i in $(seq 1 "$n"); do
    curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
      --cert "$d/client.crt" --key "$d/client.key" --cacert "$d/ca.crt" \
      --curves "$g" --tlsv1.3 "https://127.0.0.1:$port/" 2>/dev/null
  done | awk '$2>0 {printf "%.4f\n", ($2-$1)*1000}'
}

echo
echo "| one-way delay | effective RTT | classical median | hybrid median | hybrid/classical |"
echo "|--------------:|--------------:|-----------------:|--------------:|-----------------:|"
echo "delay_ms,rtt_ms,classical_ms,hybrid_ms,ratio" >> "$OUT"

for D in 0 5 25; do
  tc qdisc del dev lo root 2>/dev/null || true
  if [ "$D" != "0" ]; then tc qdisc add dev lo root netem delay ${D}ms; fi
  sleep 1
  RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f", $5}')
  c=$(sample 4434 hermetic/classical X25519          "$N" | median)
  h=$(sample 4433 hermetic/pqc       X25519MLKEM768  "$N" | median)
  r=$(awk -v a="$h" -v b="$c" 'BEGIN{if(b>0)printf "%.2fx", a/b; else print ", "}')
  printf "| %13s | %13s | %16s | %13s | %16s |\n" "${D} ms" "${RTT:-?} ms" "$c" "$h" "$r"
  echo "$D,${RTT:-},$c,$h,$r" >> "$OUT"
done

tc qdisc del dev lo root 2>/dev/null || true
echo
echo "Interpretation: if PQC pays one extra round trip, (hybrid - classical) at a"
echo "given delay should approximate ONE effective RTT."
echo "These arms are unstapled, so the expected result is a flat 1-2 ms delta"
echo "that does not grow with RTT."
echo "raw -> $OUT"
