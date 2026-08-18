#!/usr/bin/env bash
# measure-latency.sh: TLS 1.3 mTLS handshake latency, paper methodology.
#
# METHOD (matches the CSCN-2026 measurement protocol):
#   * N=220 handshakes, FIRST 20 DISCARDED as warm-up -> N=200 analysed.
#   * One FRESH curl process per handshake. This is what guarantees no TLS
#     session resumption -- do not "optimise" it into a single curl call.
#   * Metric: time_appconnect - time_connect  (pure TLS, TCP setup excluded).
#     Both raw fields are recorded so either can be recomputed later.
#
# Usage:
#   ./measure-latency.sh <label> <url> <certdir> <group> [N]
#
#   live gateway : ./measure-latency.sh gw-pqc https://pqc-gw.local/api/v1/status \
#                     $EXPORT_DIR X25519MLKEM768 220 pqc-gw.local:443:127.0.0.1
#
# SNI: the 5th arg is an optional curl --resolve mapping. Connect BY HOSTNAME so
# the client sends SNI, as the original campaign did (--resolve pqc-gw.local:...).
# Without SNI the server omits the 4-byte empty server_name echo from
# EncryptedExtensions and the flight measures 4 B short.
#   hermetic PQC : ./measure-latency.sh herm-pqc https://127.0.0.1:4433/ \
#                     $WORKDIR/hermetic/pqc X25519MLKEM768
#   hermetic clas: ./measure-latency.sh herm-classical https://127.0.0.1:4434/ \
#                     $WORKDIR/hermetic/classical X25519
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
LABEL="${1:?usage: $0 <label> <url> <certdir> <group> [N]}"
URL="${2:?missing url}"
CERTDIR="${3:?missing certdir}"
GROUP="${4:?missing group}"
N="${5:-220}"
RESOLVE="${6:-}"
OUT="$(cd "$(dirname "$0")" && pwd)/${LABEL}.dat"

CURL=/usr/bin/curl
"$CURL" -V | head -1 | grep -q "OpenSSL/3.6" || { echo "ERROR: curl not linked against OpenSSL 3.6.x (not PQC-capable)"; exit 1; }

# ca-chain.crt for the live gateway export dir; ca.crt for hermetic dirs
CAF="$CERTDIR/ca-chain.crt"; [ -f "$CAF" ] || CAF="$CERTDIR/ca.crt"
for f in "$CERTDIR/client.crt" "$CERTDIR/client.key" "$CAF"; do
  [ -f "$f" ] || { echo "ERROR: missing $f"; exit 1; }
done

: > "$OUT"
echo "[$LABEL] $URL  group=$GROUP  N=$N  resolve=${RESOLVE:-none}  (resumption off, fresh process each)" >&2
fails=0
for _ in $(seq 1 "$N"); do
  line=$("$CURL" -s -o /dev/null \
    -w "%{time_connect} %{time_appconnect}" \
    --cert "$CERTDIR/client.crt" --key "$CERTDIR/client.key" --cacert "$CAF" \
    --curves "$GROUP" --tlsv1.3 \
    ${RESOLVE:+--resolve "$RESOLVE"} \
    "$URL" 2>/dev/null)
  if [ -z "$line" ]; then fails=$((fails+1)); continue; fi
  echo "$line" >> "$OUT"
done
echo "  wrote $(wc -l < "$OUT") samples, $fails failures -> $OUT" >&2
[ "$fails" -gt 0 ] && echo "  WARN: $fails handshake(s) failed, investigate before citing" >&2
exit 0
