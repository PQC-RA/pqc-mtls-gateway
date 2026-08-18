#!/usr/bin/env bash
# wirebytes.sh: handshake wire bytes, with the CHAIN CONFIGURATION recorded.
#
# THE TRAP THIS SCRIPT EXISTS TO AVOID:
#   `s_client -CAfile <chain>` makes the CLIENT auto-send its FULL chain
#   (leaf+intermediate+root). That inflates "written" by ~11 KB and is what
#   produced the historic 8.5x ratio. A real client sends its LEAF ONLY.
#   This script measures BOTH and labels them, so the number can never be
#   quoted without its configuration.
#
# Also forces loopback MTU to 1500 for the duration, so flights segment the way
# they would on a real link (default lo MTU is 65536 and hides segmentation).
set -uo pipefail
# PQ OpenSSL. /opt/openssl is the versionless alias the deploy creates; the
# versioned tree is the fallback for a host an older deploy set up. Override
# with OSSL=... to point at any OpenSSL >= 3.5 with native ML-KEM/ML-DSA.
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
export OPENSSL_CONF=/etc/ssl/openssl.cnf
HERE="$(cd "$(dirname "$0")" && pwd)"
# Same resolution as setup-classical-arm.sh, so producer and consumer agree.
WORKDIR="${WORKDIR:-$HERE}"
D="$WORKDIR/hermetic"
OUT="$HERE/wirebytes_raw.txt"

ORIG_MTU=$(ip link show lo | grep -oE 'mtu [0-9]+' | awk '{print $2}')
restore() { ip link set dev lo mtu "$ORIG_MTU" 2>/dev/null || true; }
trap restore EXIT
ip link set dev lo mtu 1500 2>/dev/null || echo "WARN: could not set lo MTU 1500"
echo "lo MTU set to 1500 (was $ORIG_MTU)"

probe() { # probe <label> <port> <dir> <mode>
  local label=$1 port=$2 dir=$3 mode=$4 args
  case "$mode" in
    leaf)  args="-cert $dir/client.crt -key $dir/client.key" ;;   # no -CAfile: leaf only
    chain) args="-cert $dir/client.crt -key $dir/client.key -CAfile $dir/ca.crt" ;;
  esac
  local out rd wr
  out=$(echo | timeout 25 $OSSL s_client -connect 127.0.0.1:$port $args 2>/dev/null \
        | grep -E "^SSL handshake has read")
  rd=$(echo "$out" | grep -oE 'read [0-9]+'    | awk '{print $2}')
  wr=$(echo "$out" | grep -oE 'written [0-9]+' | awk '{print $2}')
  [ -z "${rd:-}" ] && { printf '| %-22s | %-11s | %8s | %8s | %8s |\n' "$label" "$mode" "ERR" "ERR" "ERR"; return; }
  printf '| %-22s | %-11s | %8s | %8s | %8s |\n' "$label" "$mode" "$rd" "$wr" "$((rd+wr))"
  echo "$label,$mode,$rd,$wr,$((rd+wr))" >> "$OUT"
}

: > "$OUT"; echo "label,client_sends,read,written,total" >> "$OUT"
echo
echo "| arm                    | client sends|     read |  written |    TOTAL |"
echo "|------------------------|-------------|---------:|---------:|---------:|"
probe "PQC hermetic"       4433 "$D/pqc"       leaf
probe "PQC hermetic"       4433 "$D/pqc"       chain
probe "CLASSICAL hermetic"  4434 "$D/classical" leaf
probe "CLASSICAL hermetic"  4434 "$D/classical" chain
echo
echo "raw -> $OUT"
echo
echo "Cite the LEAF row for a realistic deployment. The CHAIN row is what"
echo "'s_client -CAfile' produces and is NOT what a real client sends."
