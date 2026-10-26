#!/usr/bin/env bash
# keepalive-expiry-h2-stand.sh: on the ISOLATED stand, an expired client
# certificate on an open HTTP/2 connection (gateway client_cert_expiry.lua).
# One demo-120s client, no renewal; ONE curl process sends one request a second
# over one HTTP/2 connection (num_connects 0 = reused) across notAfter.
# Expected: 404 before notAfter, 400 for every stream after it, same connection.
#
# Usage: keepalive-expiry-h2-stand.sh WORKDIR [SECONDS]
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; DUR=${2:-200}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
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
TS=$(date -u +%H%M%S); CN="kh2-$TS"; K="$W/client"
enroll "$CN" demo-120s "$K"; cat "$K/client.key" "$K/client.crt" > "$K/identity.pem"
NA=$($O x509 -in "$K/client.crt" -noout -enddate | cut -d= -f2); NAE=$(date -u -d "$NA" +%s)
echo "client $CN serial $($O x509 -in "$K/client.crt" -noout -serial | cut -d= -f2) notAfter $NA"
stdbuf -oL curl -s --http2 "${RES[@]}" --cacert $CA --cert "$K/identity.pem" --rate 1/s -o /dev/null \
	-w '%{http_code} %{num_connects} %{http_version}\n' "$ADMIN/?n=[1-$DUR]" 2>/dev/null \
	| while read -r code nc ver; do echo "$(date -u +%s) $(date -u +%H:%M:%S) $code connects=$nc http/$ver"; done > "$W/h2.log"
python3 -I - "$W/h2.log" "$NAE" <<'PY'
import sys, collections
nae = int(sys.argv[2]); rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
c = collections.Counter(("before" if int(r[0]) < nae else "after", r[2], r[3], r[4]) for r in rows)
for k, v in sorted(c.items()): print(f"   {k[0]:6s} notAfter: status {k[1]} {k[2]} {k[3]}: {v}")
print(f"   new connections in total: {sum(1 for r in rows if r[3] != 'connects=0')}")
before = [r for r in rows if int(r[0]) < nae]; after = [r for r in rows if int(r[0]) >= nae + 1]
checks = [
    ("one HTTP/2 connection for the whole run", sum(1 for r in rows if r[3] != "connects=0") == 1 and all(r[4] == "http/2" for r in rows)),
    ("every request before notAfter answered 404", bool(before) and all(r[2] == "404" for r in before)),
    ("every request after notAfter refused 400 on that same connection", bool(after) and all(r[2] == "400" and r[3] == "connects=0" for r in after)),
]
fail = 0
for name, ok in checks:
    print(("PASS  " if ok else "FAIL  ") + name); fail += not ok
print(f"== result: {len(checks) - fail} passed, {fail} failed"); sys.exit(fail)
PY
