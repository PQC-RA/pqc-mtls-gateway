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
# Usage: keepalive-stand.sh WORKDIR [SECONDS]
set -uo pipefail
O=/opt/openssl-3.6.2/bin/openssl; export LD_LIBRARY_PATH=/opt/openssl-3.6.2/lib64 OPENSSL_CONF=/dev/null
W=${1:?workdir}; DUR=${2:-200}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
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
TS=$(date -u +%H%M%S); CN="ka-$TS"; K="$W/client"
enroll "$CN" demo-120s "$K"; enroll "ka-victim-$TS" "" "$W/victim"
VSER=$($O x509 -in "$W/victim/client.crt" -noout -serial | cut -d= -f2)
echo "client $CN serial $($O x509 -in "$K/client.crt" -noout -serial | cut -d= -f2); victim serial $VSER"
ACC0=$(docker exec pqcfix-gateway sh -c 'wc -l < /var/log/nginx/pqc-mtls-access.log')

bash "$HERE/renew-client.sh" --dir "$K" --url https://pqc-gw.local:19443 --resolve pqc-gw.local:19443:127.0.0.1 --loop > "$W/renew.out" 2>&1 &
RP=$!
sleep 1   # identity.pem exists once the client has started

# Fresh connection per request, identity read from the atomically switched file.
( end=$(( $(date +%s) + DUR )); while [ "$(date +%s)" -lt "$end" ]; do
	c=$(curl -s "${RES[@]}" --cacert $CA --cert "$K/identity.pem" --max-time 5 -o /dev/null -w '%{http_code}' https://pqc-gw.local:19443/ 2>/dev/null) || true
	echo "$(date -u +%H:%M:%S) ${c:-000}"; sleep 1; done ) > "$W/fresh.log" &
FP=$!

# One keep-alive connection; reconnect only when the server closes it.
python3 -I - "$K/identity.pem" "$CA" "$DUR" > "$W/keepalive.log" 2>&1 <<'PY' &
import http.client, socket, ssl, sys, time
ident, ca, dur = sys.argv[1], sys.argv[2], int(sys.argv[3])
def connect():
    ctx = ssl.create_default_context(cafile=ca); ctx.load_cert_chain(ident)
    raw = socket.create_connection(("127.0.0.1", 19443), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname="pqc-gw.local")
    c = http.client.HTTPConnection("pqc-gw.local", 19443, timeout=5); c.sock = s
    return c, s.getpeercert(binary_form=False) is not None
end = time.time() + dur; ok = fail = reconnects = 0
conn, _ = connect(); print(time.strftime("%H:%M:%S"), "connected")
while time.time() < end:
    try:
        conn.request("GET", "/", headers={"Connection": "keep-alive"}); r = conn.getresponse(); r.read()
        if r.status == 404: ok += 1
        else: fail += 1; print(time.strftime("%H:%M:%S"), "status", r.status)
        if r.getheader("Connection", "").lower() == "close":
            reconnects += 1; print(time.strftime("%H:%M:%S"), "server asked to close; reconnect"); conn.close(); conn, _ = connect()
    except Exception as e:
        reconnects += 1; print(time.strftime("%H:%M:%S"), "connection lost:", type(e).__name__, e)
        try: conn.close()
        except Exception: pass
        try: conn, _ = connect(); print(time.strftime("%H:%M:%S"), "reconnected")
        except Exception as e2: fail += 1; print(time.strftime("%H:%M:%S"), "reconnect failed:", e2)
        continue
    time.sleep(1)
print(f"RESULT ok={ok} failed={fail} reconnects={reconnects}")
PY
KP=$!

sleep $(( DUR / 2 ))
rc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 -H 'Content-Type: application/json' --max-time 15 -o /dev/null -w '%{http_code}' \
	-X POST "$ADMIN/admin/certs/revoke" -d "{\"serial\":\"$VSER\",\"reason\":\"superseded\"}")
echo "$(date -u +%H:%M:%S) revoked unrelated serial $VSER (HTTP $rc): CRL renewal and gateway reload follow" | tee "$W/revoke.log"
wait $FP $KP; kill $RP 2>/dev/null; wait $RP 2>/dev/null

docker exec pqcfix-gateway sh -c "tail -n +$((ACC0+1)) /var/log/nginx/pqc-mtls-access.log" > "$W/access.log"
echo "== renewals"; grep RENEWED "$W/renew.out" | sed 's/^/   /'
echo "== fresh-connection loop: $(wc -l < "$W/fresh.log") requests, $(grep -vc ' 404$' "$W/fresh.log") not 404"
grep -v ' 404$' "$W/fresh.log" | sed 's/^/   /' | head
echo "== keep-alive client"; grep -v "^RESULT" "$W/keepalive.log" | sed 's/^/   /' | head -12; grep "^RESULT" "$W/keepalive.log" | sed 's/^/   /'
echo "== gateway access log for $CN: $(grep -c "CN=$CN," "$W/access.log") lines; serials $(grep "CN=$CN," "$W/access.log" | python3 -I -c 'import json,sys; print(" ".join(sorted({json.loads(l)["serial"] for l in sys.stdin if l.strip()})))'); 444s $(grep "CN=$CN," "$W/access.log" | grep -c '"status":444'); non-404/201/409 $(grep "CN=$CN," "$W/access.log" | grep -vcE '"status":(404|201|409)')"
docker exec pqcfix-gateway sh -c 'grep -c "reloading\|signal process started" /var/log/nginx/pqc-mtls-error.log 2>/dev/null; ls /signals' 2>/dev/null | tr '\n' ' ' | sed 's/^/== gateway: /'; echo
