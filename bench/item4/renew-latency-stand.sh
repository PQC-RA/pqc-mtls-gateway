#!/usr/bin/env bash
# renew-latency-stand.sh: renewal latency over N DISTINCT CNs on the ISOLATED
# stand (ITEM4-Design §8: "renewal latency, client request to new certificate
# in hand, p50 / p95, n >= 25"; ADR-019 decision 14: 25 instead of 100).
#
# N demo-120s clients are enrolled one every 12 s (the enrollment rate limit);
# each renews ONCE with renew-client.sh --once just after half its lifetime
# (the server refuses earlier), so the renewals run one at a time, 12 s apart. Measured per CN:
#   client  wall time of renew-client.sh --once: new ML-DSA-65 key, CSR, proof
#           of possession, one mTLS POST /renew, verify and swap the files
#   server  the gateway's request time (rt) for that POST /renew (API plus custodian)
# Loopback, one client at a time: this is latency, not capacity.
#
# Usage: renew-latency-stand.sh WORKDIR [N]
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; N=${2:-25}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
die(){ echo "GUARD ABORT: $*"; exit 90; }
stand_guard "$W"

enroll(){ # enroll CN PROFILE DIR
	local d=$3 q="cn=$1&ttl=300" t body; [ -n "$2" ] && q="$q&profile=$2"; mkdir -p "$d"; cp $CA "$d/ca-chain.crt"
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$d/client.key" -out "$d/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$1" 2>/dev/null
	t=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")')
	body=$(CSR_FILE="$d/csr.pem" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$d/enroll.json"
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$d/enroll.json" "$d/client.crt"
}
TS=$(date -u +%H%M%S); ACC0=$(docker exec $GW sh -c 'wc -l < /var/log/nginx/pqc-mtls-access.log')
echo "cn serial_old serial_new client_s exit" > "$W/client.tsv"
renew_one(){ # renew_one i: wait until past half of the lifetime, then renew once and time it
	local d="$W/c$1" old new nb t0 t1 rc
	old=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2)
	nb=$(date -u -d "$($O x509 -in "$d/client.crt" -noout -startdate | cut -d= -f2)" +%s)
	# notBefore is backdated 60 s; half of 120 s after the real issue time is nb+60+60.
	while [ "$(date +%s)" -lt $(( nb + 60 + 63 )) ]; do sleep 1; done
	t0=$(date +%s.%N); bash "$HERE/renew-client.sh" --dir "$d" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --once > "$d/renew.out" 2>&1; rc=$?; t1=$(date +%s.%N)
	new=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2)
	echo "lat-$TS-$1 $old $new $(echo "$t1 - $t0" | bc) $rc" >> "$W/client.tsv"
}
# The enrollment endpoint allows 5 requests a minute per address (burst 3), so
# one CN is enrolled every 12 s; each renews about 63 s after it was issued,
# which keeps the renewals 12 s apart (the /renew limit is 30 a minute per address).
for i in $(seq -w 1 "$N"); do
	t=$(date +%s); enroll "lat-$TS-$i" demo-120s "$W/c$i"
	[ -s "$W/c$i/client.crt" ] || { echo "enrollment $i failed: $(head -c 200 "$W/c$i/enroll.json")"; continue; }
	renew_one "$i" & 
	while [ "$(date +%s)" -lt $(( t + 12 )) ]; do sleep 1; done
done
wait
docker exec $GW sh -c "tail -n +$((ACC0+1)) /var/log/nginx/pqc-mtls-access.log" | grep '"uri":"/renew"' | grep "CN=lat-$TS-" > "$W/access-renew.log"
python3 -I - "$W/client.tsv" "$W/access-renew.log" <<'PY'
import json, statistics, sys
rows = [l.split() for l in open(sys.argv[1]).read().splitlines()[1:]]
acc = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
def pct(v, p):
    v = sorted(v); k = (len(v) - 1) * p / 100; f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)
ok = [r for r in rows if r[4] == "0" and r[1] != r[2]]
cl = [float(r[3]) * 1000 for r in ok]
st = [a["rt"] * 1000 for a in acc if a["status"] == 201]
print(f"renewed {len(ok)} of {len(rows)} distinct CNs; gateway POST /renew statuses: " + str(sorted({a['status'] for a in acc})) + f", {len(acc)} requests")
for name, v in (("client wall time", cl), ("gateway rt (API+custodian)", st)):
    if v: print(f"{name:28s} n={len(v)} p50={pct(v,50):.0f} ms p95={pct(v,95):.0f} ms min={min(v):.0f} max={max(v):.0f} mean={statistics.mean(v):.0f}")
ok_all = len(ok) == len(rows) and len(rows) > 0 and sorted({a["status"] for a in acc}) == [201] and len(st) == len(rows)
print(("PASS  " if ok_all else "FAIL  ") + f"every CN renewed once, every POST /renew 201 ({len(ok)} of {len(rows)})")
print(f"== result: {int(ok_all)} passed, {int(not ok_all)} failed"); sys.exit(0 if ok_all else 1)
PY
