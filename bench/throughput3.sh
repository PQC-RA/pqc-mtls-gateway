#!/usr/bin/env bash
# throughput3.sh: CPU-normalised throughput across all THREE arms
# (classical / hybrid / pure ML-KEM-768), matching the original comparison.
# Group is pinned SERVER-side; s_time has no -groups option. That is enough for
# classical and hybrid, whose groups are in the default client list, but NOT for
# pure ML-KEM-768: OpenSSL offers no standalone ML-KEM by default, so there was
# no overlap and every pure window failed. Pin it client-side via OPENSSL_CONF,
# which s_time inherits. Same mechanism as pure-tp.sh.
set -uo pipefail
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
export OPENSSL_CONF=/etc/ssl/openssl.cnf
PURE_CNF=$(mktemp /tmp/pure-groups.XXXXXX.cnf)
trap 'rm -f "$PURE_CNF"' EXIT
cat > "$PURE_CNF" <<'CNF'
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Groups = MLKEM768
CNF
cd "$(dirname "$0")"
D=hermetic
SECS="${1:-10}"; WINDOWS="${2:-3}"
OUT=throughput3_raw.txt; : > "$OUT"
declare -A MEAN

run_arm() { # run_arm <name> <port> <dir>
  local name=$1 port=$2 dir=$3 sum=0 k=0
  local cnf="$OPENSSL_CONF"
  [ "$name" = pure ] && cnf="$PURE_CNF"
  echo "=== $name (:$port) ===" | tee -a "$OUT"
  for w in $(seq 1 "$WINDOWS"); do
    local t0 t1 real out conns user
    t0=$(date +%s.%N)
    out=$(OPENSSL_CONF="$cnf" $OSSL s_time -connect 127.0.0.1:$port -new -time "$SECS" \
          -cert "$dir/client.crt" -key "$dir/client.key" -CAfile "$dir/ca.crt" 2>/dev/null | tr '\n' ' ')
    t1=$(date +%s.%N)
    real=$(echo "$t1 - $t0" | bc -l)
    conns=$(echo "$out" | grep -oE '[0-9]+ connections in [0-9.]+s' | head -1 | awk '{print $1}')
    user=$(echo "$out"  | grep -oE '[0-9.]+ connections/user sec' | head -1 | awk '{print $1}')
    [ -z "${conns:-}" ] && { echo "  window $w: FAILED" | tee -a "$OUT"; continue; }
    printf '  window %d: conns=%-6s conn/USER-s=%-9s conn/REAL-s=%-7.1f ms-CPU/HS=%.3f\n' \
      "$w" "$conns" "$user" "$(echo "$conns/$real"|bc -l)" "$(echo "1000/$user"|bc -l)" | tee -a "$OUT"
    sum=$(echo "$sum + $user" | bc -l); k=$((k+1))
  done
  if [ $k -gt 0 ]; then
    local m; m=$(echo "$sum / $k" | bc -l)
    MEAN[$name]=$m
    printf '  MEAN conn/USER-s = %.1f   (ms CPU/HS = %.3f)\n\n' "$m" "$(echo "1000/$m"|bc -l)" | tee -a "$OUT"
  fi
}

run_arm classical 4434 "$D/classical"
run_arm hybrid    4433 "$D/pqc"
run_arm pure      4435 "$D/pqc"

{
echo "=== SUMMARY ==="
printf '  %-10s %12s %14s\n' arm conn/USER-s ms-CPU/HS
for a in classical hybrid pure; do
  m=${MEAN[$a]:-}; [ -z "$m" ] && continue
  printf '  %-10s %12.1f %14.3f\n' "$a" "$m" "$(echo "1000/$m"|bc -l)"
done
c=${MEAN[classical]:-}; h=${MEAN[hybrid]:-}; p=${MEAN[pure]:-}
[ -n "$c" ] && [ -n "$h" ] && printf '  classical/hybrid = %.2fx  (PQC CPU cost)\n' "$(echo "$c/$h"|bc -l)"
[ -n "$p" ] && [ -n "$h" ] && printf '  pure/hybrid      = %.3fx  (cost of the X25519 hedge)\n' "$(echo "$p/$h"|bc -l)"
} | tee -a "$OUT"
echo "raw -> $OUT"
