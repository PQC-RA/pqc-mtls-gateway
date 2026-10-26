#!/usr/bin/env bash
# keepalive-stand.sh: R-A3 on the ISOLATED stand: does renewal interrupt
# service? (item 4, ITEM4-Design R-A3; ADR-014: the predecessor is NOT revoked
# on renewal, so the production path differs from the demo only in lifetime.)
#
# One demo-120s client renews twice (renew-client.sh --loop) while
#   * a fresh-connection loop sends one request per second with identity.pem
#     (key and certificate switched by one rename), and
#   * a keep-alive client holds ONE TLS connection and sends one request per
#     second on it, reconnecting (and counting it) only when the server closes.
# Halfway, an unrelated certificate is revoked, which makes the crl-renewer
# reload the gateway: that is the event that closes idle keep-alive
# connections in production.
#
# Counted: failed requests in each loop, keep-alive reconnects, 444s and
# non-404 statuses for the CN in the gateway access log.
#
# Usage: keepalive-stand.sh WORKDIR [SECONDS] [norevoke]
#   norevoke: no revocation, so nothing reloads the gateway; with SECONDS over
#   two lifetimes this shows what a keep-alive client sees when the certificate
#   it connected with expires after a renewal (client_cert_expiry.lua).
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; DUR=${2:-200}; MODE=${3:-revoke}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
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
TS=$(date -u +%H%M%S); CN="ka-$TS"; K="$W/client"
enroll "$CN" demo-120s "$K"; enroll "ka-victim-$TS" "" "$W/victim"
VSER=$($O x509 -in "$W/victim/client.crt" -noout -serial | cut -d= -f2)
echo "client $CN serial $($O x509 -in "$K/client.crt" -noout -serial | cut -d= -f2); victim serial $VSER"
ACC0=$(docker exec $GW sh -c 'wc -l < /var/log/nginx/pqc-mtls-access.log'); ERR0=$(docker exec $GW sh -c 'wc -l < /var/log/nginx/error.log')

bash "$HERE/renew-client.sh" --dir "$K" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --loop > "$W/renew.out" 2>&1 &
RP=$!
sleep 1   # identity.pem exists once the client has started

# Fresh connection per request, identity read from the atomically switched file.
( end=$(( $(date +%s) + DUR )); while [ "$(date +%s)" -lt "$end" ]; do
	c=$(curl -s "${RES[@]}" --cacert $CA --cert "$K/identity.pem" --max-time 5 -o /dev/null -w '%{http_code}' $ADMIN/ 2>/dev/null) || true
	echo "$(date -u +%H:%M:%S) ${c:-000}"; sleep 1; done ) > "$W/fresh.log" &
FP=$!

# One keep-alive connection; reconnect only when the server closes it.
python3 -I - "$K/identity.pem" "$CA" "$DUR" > "$W/keepalive.log" 2>&1 <<'PY' &
import http.client, os, socket, ssl, sys, time
ident, ca, dur = sys.argv[1], sys.argv[2], int(sys.argv[3])
def connect():
    ctx = ssl.create_default_context(cafile=ca); ctx.load_cert_chain(ident)
    raw = socket.create_connection(("127.0.0.1", int(os.environ["STAND_TLS_PORT"])), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname="pqc-gw.local")
    c = http.client.HTTPConnection("pqc-gw.local", int(os.environ["STAND_TLS_PORT"]), timeout=5); c.sock = s
    return c, s.getpeercert(binary_form=False) is not None
end = time.time() + dur; ok = fail = reconnects = lost = 0
conn, _ = connect(); print(time.strftime("%H:%M:%S"), "connected")
while time.time() < end:
    try:
        conn.request("GET", "/", headers={"Connection": "keep-alive"}); r = conn.getresponse(); r.read()
        if r.status == 404: ok += 1
        else: fail += 1; print(time.strftime("%H:%M:%S"), "status", r.status)
        if r.getheader("Connection", "").lower() == "close":
            reconnects += 1; print(time.strftime("%H:%M:%S"), "server asked to close; reconnect"); conn.close(); conn, _ = connect()
    except Exception as e:
        # the request in flight got no answer: it counts as failed (R-A3 counts every
        # connection the server closed under a request)
        reconnects += 1; lost += 1; fail += 1; print(time.strftime("%H:%M:%S"), "connection lost:", type(e).__name__, e)
        try: conn.close()
        except Exception: pass
        try: conn, _ = connect(); print(time.strftime("%H:%M:%S"), "reconnected")
        except Exception as e2: fail += 1; print(time.strftime("%H:%M:%S"), "reconnect failed:", e2)
        continue
    time.sleep(1)
print(f"RESULT ok={ok} failed={fail} reconnects={reconnects} lost={lost}")
PY
KP=$!

sleep $(( DUR / 2 ))
if [ "$MODE" != norevoke ]; then
rc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 -H 'Content-Type: application/json' --max-time 15 -o /dev/null -w '%{http_code}' \
	-X POST "$ADMIN/admin/certs/revoke" -d "{\"serial\":\"$VSER\",\"reason\":\"superseded\"}")
echo "$(date -u +%H:%M:%S) revoked unrelated serial $VSER (HTTP $rc): CRL renewal and gateway reload follow" | tee "$W/revoke.log"
else echo "$(date -u +%H:%M:%S) no revocation (norevoke)" | tee "$W/revoke.log"; fi
wait $FP $KP; kill $RP 2>/dev/null; wait $RP 2>/dev/null

docker exec $GW sh -c "tail -n +$((ACC0+1)) /var/log/nginx/pqc-mtls-access.log" > "$W/access.log"
# Reloads during the run: the nginx worker PIDs in the gateway's periodic CRL-poll
# lines change at every reload (the reload notice itself is below the log level).
RELOADS=$(docker exec $GW sh -c "tail -n +$((ERR0+1)) /var/log/nginx/error.log" | sed -n 's/^.*\[warn\] \([0-9]*\)#.*crl_worker.*/\1/p' | sort -u | wc -l); RELOADS=$(( RELOADS > 0 ? RELOADS - 1 : 0 ))   # distinct worker PIDs - 1 (old and new log side by side briefly)
echo "== gateway reloads during the run (worker PID changes): $RELOADS"
echo "== renewals"; grep RENEWED "$W/renew.out" | sed 's/^/   /'
echo "== fresh-connection loop: $(wc -l < "$W/fresh.log") requests, $(grep -vc ' 404$' "$W/fresh.log") not 404"
grep -v ' 404$' "$W/fresh.log" | sed 's/^/   /' | head
echo "== keep-alive client"; grep -v "^RESULT" "$W/keepalive.log" | sed 's/^/   /' | head -12; grep "^RESULT" "$W/keepalive.log" | sed 's/^/   /'
echo "== gateway access log for $CN: $(grep -c "CN=$CN," "$W/access.log") lines; serials $(grep "CN=$CN," "$W/access.log" | python3 -I -c 'import json,sys; print(" ".join(sorted({json.loads(l)["serial"] for l in sys.stdin if l.strip()})))'); 444s $(grep "CN=$CN," "$W/access.log" | grep -c '"status":444'); non-404/201/409 $(grep "CN=$CN," "$W/access.log" | grep -vcE '"status":(404|201|409)')"

# ── asserted ──────────────────────────────────────────────────────────────────
NREN=$(grep -c RENEWED "$W/renew.out"); FRESH_BAD=$(grep -vc ' 404$' "$W/fresh.log")
KA=$(grep "^RESULT" "$W/keepalive.log"); KA_FAIL=$(echo "$KA" | sed -n 's/.*failed=\([0-9]*\).*/\1/p')
N444=$(grep "CN=$CN," "$W/access.log" | grep -c '"status":444'); NOTHER=$(grep "CN=$CN," "$W/access.log" | grep -vcE '"status":(404|201|409|400)')
pass=0; fail=0; check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
check "at least two unattended renewals ($NREN)" "[ $NREN -ge 2 ]"
check "fresh-connection loop: no request other than 404 ($FRESH_BAD)" "[ $FRESH_BAD = 0 ]"
NROT=$(grep -c 'status 400' "$W/keepalive.log"); NLOST=$(echo "$KA" | sed -n 's/.*lost=\([0-9]*\).*/\1/p')
check "keep-alive client: every failed request ($KA_FAIL) is a 400 at a rotation ($NROT, at most one per renewal: $NREN) or a request lost to a gateway reload ($NLOST, at most one per reload: $RELOADS)" "[ -n '$KA_FAIL' ] && [ $KA_FAIL -eq $(( NROT + NLOST )) ] && [ $NROT -le $NREN ] && [ $NLOST -le $RELOADS ] && ! grep -E 'status [0-9]+' '$W/keepalive.log' | grep -vq 'status 400'"
check "gateway: no 444 and no status other than 404/201/409/400 for the CN ($N444, $NOTHER)" "[ $N444 = 0 ] && [ $NOTHER = 0 ]"
echo "== result: $pass passed, $fail failed"; exit $fail
