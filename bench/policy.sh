#!/bin/bash
# The paper's V-E claim: "Zero-reload policy updates applied in ~4.7 ms".
# Pushes the CURRENT persisted policy back unchanged, so live routing is untouched
# while the full accepted path runs: HMAC verify -> atomic persist (tmp+rename)
# -> shared-dict set. 5 repeats x 50 pushes.
set -u
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this campaign builds its PKIs and writes its output. Defaults to the
# directory the scripts live in. Several of these REBUILD it from scratch, so
# point it somewhere disposable rather than at a directory you care about.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
IP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}" pqc-gateway | awk '{print $1}')
SEC=$(cat "$REPO"/secrets/control-plane-hmac.key)
docker exec pqc-gateway cat /var/cache/pqc-gw/routes/routes.json > /tmp/routes.json
OUT="$WORKDIR/results/policy.csv"
# Without this the sweep runs, every append fails, and the script still exits 0
# because it uses set -u without -e. Silent empty output is the worst outcome.
mkdir -p "$(dirname "$OUT")"
# curl's %{time_*} are SECONDS. Naming these columns _ms made every reader
# out by 1000x, including this campaign's own published median.
echo "repeat,i,code,connect_s,appconnect_s,starttransfer_s,total_s" > $OUT
for rep in $(seq 1 5); do
  for i in $(seq 1 50); do
    TS=$(date +%s)
    SIG=$( { printf "%s\n%s\n%s\n" "$TS" "POST" "/update-routes"; cat /tmp/routes.json; } \
           | openssl dgst -sha256 -hmac "$SEC" -r | cut -d' ' -f1)
    curl -sk -o /dev/null -X POST "https://$IP:8081/update-routes" \
      -H "X-Timestamp: $TS" -H "X-Hub-Signature-256: sha256=$SIG" -H "Content-Type: application/json" \
      --data-binary @/tmp/routes.json \
      -w "$rep,$i,%{http_code},%{time_connect},%{time_appconnect},%{time_starttransfer},%{time_total}\n" >> $OUT
  done
done
echo "reload count (must stay 0): $(docker inspect -f '{{.RestartCount}}' pqc-gateway)"
echo POLICY-DONE
