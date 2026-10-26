#!/usr/bin/env bash
# longrun-tick.sh DIR PORT [HOST]: one renewal check for a long-running test identity,
# meant for cron (every 30 minutes). It acts like a device: at 2/3 of the
# certificate's lifetime it renews with the reference client (renew-client.sh,
# next to this file); otherwise it only logs that it is waiting. Every attempt is
# logged in DIR/tick.log, so the log is the evidence of a 30-day lineage.
#
# DIR holds the identity as renew-client.sh expects it (client.crt, client.key,
# ca-chain.crt). HOST (default pqc-gw.local) must match the gateway certificate;
# it is resolved to 127.0.0.1.
#   */30 * * * * /path/to/bench/item4/longrun-tick.sh /var/lib/pqc-longrun/id-1 443
set -uo pipefail
D=${1:?DIR}; P=${2:?PORT}; H=${3:-pqc-gw.local}; B=$(cd "$(dirname "$0")" && pwd)
. "$B/../../scripts/lib/pq-openssl.sh"
S=$($O x509 -in "$D/client.crt" -noout -serial 2>/dev/null | cut -d= -f2)
NB=$(date -u -d "$($O x509 -in "$D/client.crt" -noout -startdate | cut -d= -f2)" +%s)
NA=$(date -u -d "$($O x509 -in "$D/client.crt" -noout -enddate | cut -d= -f2)" +%s)
NOW=$(date -u +%s); AT=$(( NB + 60 + (NA - NB - 60) * 2 / 3 ))
if [ "$NOW" -lt "$AT" ]; then echo "$(date -u +%FT%TZ) waiting serial=$S renew_at=$(date -u -d @$AT +%FT%TZ)" >> "$D/tick.log"; exit 0; fi
OPENSSL=$O bash "$B/renew-client.sh" --dir "$D" --url "https://$H:$P" --resolve "$H:$P:127.0.0.1" --once >> "$D/tick.log" 2>&1
echo "$(date -u +%FT%TZ) renew-client exit $? (was serial=$S)" >> "$D/tick.log"
