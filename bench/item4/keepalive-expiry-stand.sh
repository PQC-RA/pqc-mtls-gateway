#!/usr/bin/env bash
#!/usr/bin/env bash
# keepalive-expiry-stand.sh: on the ISOLATED stand, does a certificate keep
# working on an open keep-alive connection after its notAfter? (ADR-019
# decision 11 states that it does: there is no per-request expiry check.)
#
# One demo-120s client, NO renewal. A keep-alive client sends one request per
# second on one TLS connection for SECONDS; after notAfter a fresh connection
# with the same certificate is tried once a second as the control.
#
# Usage: keepalive-expiry-stand.sh WORKDIR [SECONDS]
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
TS=$(date -u +%H%M%S); CN="kx-$TS"; K="$W/client"
enroll "$CN" demo-120s "$K"; cat "$K/client.key" "$K/client.crt" > "$K/identity.pem"
NA=$($O x509 -in "$K/client.crt" -noout -enddate | cut -d= -f2); NAE=$(date -u -d "$NA" +%s)
echo "client $CN serial $($O x509 -in "$K/client.crt" -noout -serial | cut -d= -f2) notAfter $NA"
ACC0=$(docker exec $GW sh -c 'wc -l < /var/log/nginx/pqc-mtls-access.log')

python3 -I - "$K/identity.pem" "$CA" "$DUR" "$NAE" > "$W/keepalive.log" 2>&1 <<'PY' &
import http.client, os, socket, ssl, sys, time
ident, ca, dur, nae = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def connect():
    ctx = ssl.create_default_context(cafile=ca); ctx.load_cert_chain(ident)
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(os.environ["STAND_TLS_PORT"])), timeout=5), server_hostname="pqc-gw.local")
    c = http.client.HTTPConnection("pqc-gw.local", int(os.environ["STAND_TLS_PORT"]), timeout=5); c.sock = s; return c
end = time.time() + dur; before = after = 0; last_after = None
conn = connect(); print(time.strftime("%H:%M:%S"), "connected")
while time.time() < end:
    try:
        conn.request("GET", "/"); r = conn.getresponse(); r.read()
        if r.status != 404:
            print(time.strftime("%H:%M:%S"), "status", r.status, "Connection:", r.getheader("Connection"))
            if (r.getheader("Connection") or "").lower() == "close": break
        elif time.time() > nae:
            after += 1; last_after = time.strftime("%H:%M:%S")
        else: before += 1
    except Exception as e:
        print(time.strftime("%H:%M:%S"), "connection ended:", type(e).__name__, e); break
    time.sleep(1)
print(f"RESULT served_before_notAfter={before} served_after_notAfter={after} last_after={last_after}")
PY
KP=$!
while [ "$(date +%s)" -le "$NAE" ]; do sleep 1; done; sleep 2
for i in 1 2 3; do
	c=$(curl -s "${RES[@]}" --cacert $CA --cert "$K/identity.pem" --max-time 5 -o /dev/null -w '%{http_code}' $ADMIN/ 2>/dev/null) || true
	echo "$(date -u +%H:%M:%S) fresh connection after notAfter: ${c:-000}"; sleep 1
done | tee "$W/fresh-after.log"
wait $KP
docker exec $GW sh -c "tail -n +$((ACC0+1)) /var/log/nginx/pqc-mtls-access.log" | grep "CN=$CN," > "$W/access.log"
echo "== keep-alive client"; sed 's/^/   /' "$W/keepalive.log"
echo "== gateway access log for $CN: $(wc -l < "$W/access.log") lines, statuses $(python3 -I -c 'import json,sys,collections; print(dict(collections.Counter(json.loads(l)["status"] for l in open(sys.argv[1]))))' "$W/access.log")"
echo "   last 404 at $(grep '"status":404' "$W/access.log" | tail -1 | python3 -I -c 'import json,sys; print(json.loads(sys.stdin.read())["ts"])'), notAfter $NA"

# ── asserted ──────────────────────────────────────────────────────────────────
pass=0; fail=0; check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
check "nothing served on the open connection after notAfter" "grep -q 'served_after_notAfter=0 ' '$W/keepalive.log'"
check "the first request after notAfter got 400 and the server closed" "grep -q 'status 400 Connection: close' '$W/keepalive.log'"
check "fresh connections after notAfter refused (400, 3 of 3)" "[ \$(grep -c ': 400$' '$W/fresh-after.log') = 3 ]"
echo "== result: $pass passed, $fail failed"; exit $fail
