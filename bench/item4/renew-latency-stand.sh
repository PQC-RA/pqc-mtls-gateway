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
O=/opt/openssl-3.6.2/bin/openssl; export LD_LIBRARY_PATH=/opt/openssl-3.6.2/lib64 OPENSSL_CONF=/dev/null
W=${1:?workdir}; N=${2:-25}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
CA=/root/pqcfix/pki/ca-chain.crt; LIVE_CA=/etc/pki/pqc-ca/ca-chain.crt
ADM_C=/root/pqcfix/admin/fix-tmp-admin.crt; ADM_K=/root/pqcfix/admin/fix-tmp-admin.key
ADMIN=https://pqc-gw.local:19443; ENROLL=https://pqc-gw.local:18443/enroll
RES=(--resolve pqc-gw.local:19443:127.0.0.1 --resolve pqc-gw.local:18443:127.0.0.1)
die(){ echo "GUARD ABORT: $*"; exit 90; }
for p in 19443 18443; do
	echo | timeout 8 $O s_client -connect 127.0.0.1:$p -servername pqc-gw.local -showcerts 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > "$W/srv-$p.pem"
	$O verify -CAfile $CA -untrusted "$W/srv-$p.pem" "$W/srv-$p.pem" >/dev/null 2>&1 || die "$p does not chain to the throwaway CA"
	if $O verify -CAfile $LIVE_CA "$W/srv-$p.pem" >/dev/null 2>&1; then die "$p chains to LIVE"; fi
done
[ "$(docker port pqcfix-gateway 443/tcp)" = "127.0.0.1:19443" ] || die "ports are not pqcfix-gateway"
echo "GUARD OK"

enroll(){ # enroll CN PROFILE DIR
	local d=$3 q="cn=$1&ttl=300" t body; [ -n "$2" ] && q="$q&profile=$2"; mkdir -p "$d"; cp $CA "$d/ca-chain.crt"
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$d/client.key" -out "$d/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$1" 2>/dev/null
	t=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")')
	body=$(CSR_FILE="$d/csr.pem" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$d/enroll.json"
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$d/enroll.json" "$d/client.crt"
}
TS=$(date -u +%H%M%S); ACC0=$(docker exec pqcfix-gateway sh -c 'wc -l < /var/log/nginx/pqc-mtls-access.log')
echo "cn serial_old serial_new client_s exit" > "$W/client.tsv"
renew_one(){ # renew_one i: wait until past half of the lifetime, then renew once and time it
	local d="$W/c$1" old new nb t0 t1 rc
	old=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2)
	nb=$(date -u -d "$($O x509 -in "$d/client.crt" -noout -startdate | cut -d= -f2)" +%s)
	# notBefore is backdated 60 s; half of 120 s after the real issue time is nb+60+60.
	while [ "$(date +%s)" -lt $(( nb + 60 + 63 )) ]; do sleep 1; done
	t0=$(date +%s.%N); bash "$HERE/renew-client.sh" --dir "$d" --url https://pqc-gw.local:19443 --resolve pqc-gw.local:19443:127.0.0.1 --once > "$d/renew.out" 2>&1; rc=$?; t1=$(date +%s.%N)
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
docker exec pqcfix-gateway sh -c "tail -n +$((ACC0+1)) /var/log/nginx/pqc-mtls-access.log" | grep '"uri":"/renew"' | grep "CN=lat-$TS-" > "$W/access-renew.log"
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
PY
