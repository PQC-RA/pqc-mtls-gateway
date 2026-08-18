#!/usr/bin/env bash
# measure-arms.sh: the clean campaign. Every metric is REPEATED and AVERAGED,
# and the spread across repeats is reported, so run-to-run variance is visible
# rather than hidden behind a single number.
#
# Repeats default to 3. Each repeat is fully independent.
#
# Re-asserts the arms first: if a group or certificate count is wrong, nothing
# is measured. That check exists because a "classical" arm silently keeping the
# post-quantum group is exactly how the published figures went wrong.
set -euo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this campaign builds its PKIs and writes its output. Defaults to the
# directory the scripts live in. Several of these REBUILD it from scratch, so
# point it somewhere disposable rather than at a directory you care about.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
BASE=$WORKDIR
PKI=$BASE/pki
OUT=$BASE/results
REPEATS="${REPEATS:-3}"
N="${N:-220}"          # latency samples per repeat, first 20 discarded
WINDOWS="${WINDOWS:-3}" # s_time windows per repeat
SECS="${SECS:-10}"
mkdir -p "$OUT"
LOG=$OUT/run.txt; : > "$LOG"
say(){ echo "$@" | tee -a "$LOG"; }

ARMS="classical:9443:X25519:classical
hybrid:9444:X25519MLKEM768:pqc
pure:9445:MLKEM768:pqc"

ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
cleanup(){ tc qdisc del dev lo root 2>/dev/null || true; ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true; }
trap cleanup EXIT
ip link set dev lo mtu 1500

say "=============================================================="
say " Clean re-measurement, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say " host $(hostname)  repeats=$REPEATS  N=$N  windows=${WINDOWS}x${SECS}s"
say " lo MTU 1500 (was $ORIG_MTU)   initcwnd $(ip route show table local | awk '/^local 127.0.0.1 /{for(i=1;i<=NF;i++) if($i=="initcwnd") print $(i+1)}' || echo default-10)"
say "=============================================================="

# ---------- helper: mean and spread over a list of numbers --------------------
stat(){ awk '{s+=$1; a[NR]=$1} END{ if(NR==0){print "-";exit}
  m=s/NR; for(i=1;i<=NR;i++){d=a[i]-m; v+=d*d}
  sd=(NR>1)?sqrt(v/(NR-1)):0
  printf "%.3f +/- %.3f", m, sd }'; }

# ---------- 1. certificate sizes (deterministic; verify stability) ------------
say
say "### 1. Certificate sizes (DER bytes), identical DNs, pinned serials"
say "| role | ML-DSA-65 | ECDSA P-256 | ratio |"
say "|---|---:|---:|---:|"
for role in root int server client; do
  p=$($OSSL x509 -in $PKI/pqc/$role.crt -outform DER | wc -c)
  c=$($OSSL x509 -in $PKI/classical/$role.crt -outform DER | wc -c)
  say "| $role | $p | $c | $(awk -v x=$p -v y=$c 'BEGIN{printf "%.2fx",x/y}') |"
done

# ---------- 2. handshake wire bytes, 3 transmit policies ----------------------
say
say "### 2a. Handshake bytes, leaf-only, s_client counters (handshake ONLY)"
say "| arm | read | written | total |"
say "|---|---:|---:|---:|"
: > "$OUT/handshake_bytes.csv"; echo "arm,repeat,read,written,total" >> "$OUT/handshake_bytes.csv"
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  rs=(); ws=()
  for r in $(seq 1 $REPEATS); do
    # -verifyCAfile, NOT -CAfile: verifies the server WITHOUT making s_client
    # send its own chain. -CAfile does double duty as trust store and chain
    # builder, and that conflation is what corrupted the published figures.
    o=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:$port -groups "$grp" \
        -verifyCAfile $PKI/$pki/ca-chain.crt \
        -cert $PKI/$pki/client.crt -key $PKI/$pki/client.key 2>&1 || true)
    rd=$(printf '%s' "$o" | grep -oE 'read [0-9]+' | head -1 | awk '{print $2}')
    wr=$(printf '%s' "$o" | grep -oE 'written [0-9]+' | head -1 | awk '{print $2}')
    [ -n "${rd:-}" ] && { rs+=("$rd"); ws+=("$wr"); echo "$arm,$r,$rd,$wr,$((rd+wr))" >> "$OUT/handshake_bytes.csv"; }
  done
  if [ ${#rs[@]} -gt 0 ]; then
    say "| $arm | $(printf '%s\n' "${rs[@]}" | stat) | $(printf '%s\n' "${ws[@]}" | stat) | $(( ${rs[0]} + ${ws[0]} )) |"
  else say "| $arm | FAILED | | |"; fi
done <<< "$ARMS"

say
say "### 2b. Transmit policy, driven with curl + tcpdump"
say "s_client -cert ALWAYS sends only the leaf regardless of file contents, so the"
say "policy must be driven with curl (SSL_CTX_use_certificate_chain_file) and counted"
say "on the wire. These totals include the constant HTTP request/response, so compare"
say "the DELTA against leaf-only, not the absolute."
say "| arm | policy | s->c | c->s | total | delta vs leaf |"
say "|---|---|---:|---:|---:|---:|"
: > "$OUT/wirebytes.csv"; echo "arm,policy,repeat,s2c,c2s,total" >> "$OUT/wirebytes.csv"
wire(){ # wire <port> <certfile> <keyfile> <cafile> <group>
  rm -f /tmp/wb.pcap
  timeout 25 tcpdump -ni lo -w /tmp/wb.pcap "tcp port $1" >/dev/null 2>&1 &
  local tp=$!; sleep 1.2
  curl -s -o /dev/null --cert "$2" --key "$3" --cacert "$4" --curves "$5" --tlsv1.3 \
    "https://127.0.0.1:$1/" >/dev/null 2>&1 || true
  sleep 1.2; kill $tp 2>/dev/null || true; wait $tp 2>/dev/null || true
  local s2c c2s
  s2c=$(tcpdump -nr /tmp/wb.pcap "tcp src port $1" 2>/dev/null | grep -oE 'length [0-9]+' | awk '{s+=$2} END{print s+0}')
  c2s=$(tcpdump -nr /tmp/wb.pcap "tcp dst port $1" 2>/dev/null | grep -oE 'length [0-9]+' | awk '{s+=$2} END{print s+0}')
  echo "$s2c $c2s"
}
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  base=0
  for pol in leaf int full; do
    cf=$PKI/$pki/client-$pol.pem
    tots=()
    for r in $(seq 1 $REPEATS); do
      read -r s2c c2s <<< "$(wire "$port" "$cf" "$PKI/$pki/client.key" "$PKI/$pki/ca-chain.crt" "$grp")"
      tots+=("$((s2c+c2s))"); echo "$arm,$pol,$r,$s2c,$c2s,$((s2c+c2s))" >> "$OUT/wirebytes.csv"
      lastS=$s2c; lastC=$c2s
    done
    mt=$(printf '%s\n' "${tots[@]}" | awk '{s+=$1;n++} END{printf "%.0f",s/n}')
    [ "$pol" = "leaf" ] && base=$mt
    say "| $arm | $pol | ${lastS:-?} | ${lastC:-?} | $(printf '%s\n' "${tots[@]}" | stat) | +$((mt-base)) |"
  done
done <<< "$ARMS"

# ---------- 3. handshake latency ---------------------------------------------
say
say "### 3. Handshake latency, $REPEATS independent runs of N=$N (first 20 discarded)"
say "| arm | run means (ms) | mean of means | spread |"
say "|---|---|---:|---:|"
: > "$OUT/latency.csv"; echo "arm,repeat,sample_ms" >> "$OUT/latency.csv"
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  means=()
  for r in $(seq 1 $REPEATS); do
    vals=$(for i in $(seq 1 $N); do
      curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
        --cert $PKI/$pki/client-leaf.pem --key $PKI/$pki/client.key \
        --cacert $PKI/$pki/ca-chain.crt --curves "$grp" --tlsv1.3 \
        --resolve pqc-gw.local:$port:127.0.0.1 "https://pqc-gw.local:$port/" 2>/dev/null
      done | awk '$2>0{printf "%.4f\n",($2-$1)*1000}' | tail -n +21)
    echo "$vals" | awk -v a="$arm" -v r="$r" '{print a","r","$1}' >> "$OUT/latency.csv"
    m=$(echo "$vals" | awk '{s+=$1;n++} END{if(n)printf "%.3f",s/n; else print "0"}')
    means+=("$m")
  done
  say "| $arm | $(printf '%s ' "${means[@]}") | $(printf '%s\n' "${means[@]}" | stat) | |"
done <<< "$ARMS"

# ---------- 4. throughput -----------------------------------------------------
# FOUR fixes over the version that kept aborting here:
#  1. `[ -n "$u" ] && {...}` as the last statement in a loop body evaluates false
#     when s_time returns nothing, and `set -e` treats that as fatal. Use if/else.
#  2. s_time has NO -groups option and OpenSSL's default client group list
#     contains no ML-KEM, so the pure arm never negotiates. Pin it via
#     OPENSSL_CONF, which s_time inherits.
#  3. Capture wall-clock as well as CPU-normalised. s_time's own real-seconds is
#     integer-rounded, so time the window with date +%s.%N.
#  4. No `^` anchors on text whose newlines have been squashed.
say
say "### 4. Throughput, $REPEATS repeats x $WINDOWS windows of ${SECS}s"
say "| arm | conn/CPU-s | conn/wall-s | ms CPU/HS | ms wall/HS | windows |"
say "|---|---:|---:|---:|---:|---:|"
cat > /tmp/pure-groups.cnf <<'CNF'
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Groups = MLKEM768
CNF
cfg_for(){ case "$1" in pure) echo /tmp/pure-groups.cnf ;; *) echo /etc/ssl/openssl.cnf ;; esac; }
: > "$OUT/throughput.csv"; echo "arm,repeat,window,conn_cpu_s,conn_wall_s" >> "$OUT/throughput.csv"
while IFS=: read -r arm port grp pki; do
  [ -z "$arm" ] && continue
  us=(); ws=()
  for r in $(seq 1 $REPEATS); do
    for w in $(seq 1 $WINDOWS); do
      t0=$(date +%s.%N)
      o=$(OPENSSL_CONF=$(cfg_for "$arm") $OSSL s_time -connect 127.0.0.1:$port -new -time $SECS \
          -cert $PKI/$pki/client.crt -key $PKI/$pki/client.key \
          -CAfile $PKI/$pki/ca-chain.crt 2>/dev/null) || o=""
      t1=$(date +%s.%N)
      u=$(printf '%s' "$o" | grep -oE '[0-9.]+ connections/user sec' | head -1 | awk '{print $1}')
      c=$(printf '%s' "$o" | grep -oE '[0-9]+ connections in' | head -1 | awk '{print $1}')
      if [ -n "${u:-}" ] && [ -n "${c:-}" ]; then
        wl=$(echo "$c / ($t1 - $t0)" | bc -l)
        us+=("$u"); ws+=("$wl")
        printf "%s,%s,%s,%s,%.1f\n" "$arm" "$r" "$w" "$u" "$wl" >> "$OUT/throughput.csv"
      else
        echo "$arm,$r,$w,FAILED,FAILED" >> "$OUT/throughput.csv"
      fi
    done
  done
  if [ ${#us[@]} -gt 0 ]; then
    mu=$(printf '%s\n' "${us[@]}" | awk '{s+=$1;n++} END{printf "%.1f",s/n}')
    mw=$(printf '%s\n' "${ws[@]}" | awk '{s+=$1;n++} END{printf "%.1f",s/n}')
    say "| $arm | $(printf '%s\n' "${us[@]}" | stat) | $(printf '%s\n' "${ws[@]}" | stat) | $(awk -v m=$mu 'BEGIN{printf "%.3f",1000/m}') | $(awk -v m=$mw 'BEGIN{printf "%.3f",1000/m}') | ${#us[@]} |"
  else
    say "| $arm | ALL WINDOWS FAILED | | | | 0 |"
  fi
done <<< "$ARMS"

# ---------- 5. WAN sweep ------------------------------------------------------
say
say "### 5. WAN sweep, median handshake, $REPEATS repeats per point"
say "| one-way | RTT | classical | hybrid | pure |"
say "|---:|---:|---:|---:|---:|"
: > "$OUT/netem.csv"; echo "delay_ms,rtt_ms,arm,repeat,median_ms" >> "$OUT/netem.csv"
med(){ sort -n | awk '{a[NR]=$1} END{if(NR==0){print "-";exit} m=int((NR+1)/2); if(NR%2) printf "%.3f",a[m]; else printf "%.3f",(a[m]+a[m+1])/2}'; }
for D in 0 5 25; do
  tc qdisc del dev lo root 2>/dev/null || true
  [ "$D" != "0" ] && tc qdisc add dev lo root netem delay ${D}ms
  sleep 1
  RTT=$(ping -c 3 -i 0.3 -W 2 127.0.0.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f",$5}')
  row=""
  while IFS=: read -r arm port grp pki; do
    [ -z "$arm" ] && continue
    ms=()
    for r in $(seq 1 $REPEATS); do
      v=$(for i in $(seq 1 40); do
            curl -s -o /dev/null -w "%{time_connect} %{time_appconnect}\n" \
              --cert $PKI/$pki/client-leaf.pem --key $PKI/$pki/client.key \
              --cacert $PKI/$pki/ca-chain.crt --curves "$grp" --tlsv1.3 \
              "https://127.0.0.1:$port/" 2>/dev/null
          done | awk '$2>0{printf "%.4f\n",($2-$1)*1000}' | med)
      ms+=("$v"); echo "$D,${RTT:-},$arm,$r,$v" >> "$OUT/netem.csv"
    done
    row="$row | $(printf '%s\n' "${ms[@]}" | stat)"
  done <<< "$ARMS"
  say "| ${D} ms | ${RTT:-?} ms$row |"
done
tc qdisc del dev lo root 2>/dev/null || true

say
say "raw CSVs -> $OUT/{wirebytes,latency,throughput,netem}.csv"
say "log      -> $LOG"
