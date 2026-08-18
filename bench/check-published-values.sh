#!/usr/bin/env bash
# check-published-values.sh: four checks against values the paper prints.
#   Pure arm at +25 ms netem            (expect ~54.8 ms; results/netem.csv)
#   Pure arm handshake size             (expect 21,213 B; results/handshake_bytes.csv)
#   OCSP signing cert DER, deployment PKI (expect 5,882 B. The matched-PKI
#     rig in results/cert-sizes.csv is a different PKI and reads 5,695 B)
#   §V-E idle steady-state CPU          (paper: <0.12% between bursts)
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
PURE=$(cat /tmp/pure_group 2>/dev/null || echo MLKEM768)
OUT=published-values.txt; : > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }

say "=============== OCSP signing certificate DER ==============="
for f in /etc/pki/pqc-ca/ocsp/ocsp-pq.crt; do
  n=$($OSSL x509 -in "$f" -outform DER 2>/dev/null | wc -c)
  say "  $(basename $f) = ${n} B   (paper Table II: 5,882 B)"
  $OSSL x509 -in "$f" -noout -subject -ext extendedKeyUsage 2>/dev/null | sed 's/^/    /' | tee -a "$OUT"
done

say
say "=============== idle steady-state CPU (10 samples, 2 s apart) ==============="
say "  (paper: <0.12% between handshake bursts)"
tot=0; n=0
for i in $(seq 1 10); do
  line=$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' pqc-gateway 2>/dev/null | head -1)
  cpu=$(echo "$line" | awk '{gsub(/%/,"",$1); print $1}')
  say "   sample $i: cpu=${cpu}%  mem=$(echo "$line" | cut -d' ' -f2-)"
  tot=$(echo "$tot + ${cpu:-0}" | bc -l); n=$((n+1))
  sleep 2
done
say "  MEAN idle CPU = $(echo "scale=4; $tot / $n" | bc -l)%"

say
say "=============== wire bytes, PURE arm (:4435, group $PURE) ==============="
ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
restore(){ ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true; tc qdisc del dev lo root 2>/dev/null || true; }
trap restore EXIT
ip link set dev lo mtu 1500
say "  lo MTU 1500 (was $ORIG_MTU)"
probe(){ # probe <mode>
  local mode=$1 args out rd wr
  case $mode in
    leaf)  args="-cert hermetic/pqc/client.crt -key hermetic/pqc/client.key" ;;
    chain) args="-cert hermetic/pqc/client.crt -key hermetic/pqc/client.key -CAfile hermetic/pqc/ca.crt" ;;
  esac
  out=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:4435 -groups "$PURE" $args 2>/dev/null \
        | grep -E "^SSL handshake has read")
  rd=$(echo "$out" | grep -oE 'read [0-9]+'    | awk '{print $2}')
  wr=$(echo "$out" | grep -oE 'written [0-9]+' | awk '{print $2}')
  say "  pure,$mode  read=${rd:-ERR}  written=${wr:-ERR}  total=$(( ${rd:-0} + ${wr:-0} ))"
  echo "pure,$mode,${rd:-},${wr:-},$(( ${rd:-0} + ${wr:-0} ))" >> wirebytes_pure.csv
}
: > wirebytes_pure.csv
probe leaf
probe chain
n=$(echo | timeout 20 $OSSL s_client -connect 127.0.0.1:4435 -groups "$PURE" \
    -cert hermetic/pqc/client.crt -key hermetic/pqc/client.key -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE")
say "  server sends $n certificate(s)  (must be 1)"

say
say "=============== netem sweep, PURE arm (:4435) ==============="
say "  (expect ~4.7 ms at 0 delay and ~54.8 ms at +25 ms; results/netem.csv backs both)"
med(){ sort -n | awk '{a[NR]=$1} END{if(NR==0){print "-";exit} m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }
sample(){ # sample <port> <dir> <group> <n>
  local port=$1 d=$2 g=$3 n=$4 i
  for i in $(seq 1 "$n"); do
    curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
      --cert "$d/client.crt" --key "$d/client.key" --cacert "$d/ca.crt" \
      --curves "$g" --tlsv1.3 "https://127.0.0.1:$port/" 2>/dev/null
  done | awk '$2>0 {printf "%.4f\n", ($2-$1)*1000}'
}
say "| one-way | eff RTT | classical | hybrid | PURE |"
say "|--------:|--------:|----------:|-------:|-----:|"
echo "delay_ms,rtt_ms,classical_ms,hybrid_ms,pure_ms" > netem_pure.csv
for D in 0 5 25; do
  tc qdisc del dev lo root 2>/dev/null || true
  [ "$D" != "0" ] && tc qdisc add dev lo root netem delay ${D}ms
  sleep 1
  RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f",$5}')
  c=$(sample 4434 hermetic/classical X25519         60 | med)
  h=$(sample 4433 hermetic/pqc       X25519MLKEM768 60 | med)
  p=$(sample 4435 hermetic/pqc       "$PURE"        60 | med)
  say "| ${D} ms | ${RTT:-?} ms | $c | $h | $p |"
  echo "$D,${RTT:-},$c,$h,$p" >> netem_pure.csv
done
tc qdisc del dev lo root 2>/dev/null || true
say
say "raw -> netem_pure.csv, wirebytes_pure.csv, $OUT"
