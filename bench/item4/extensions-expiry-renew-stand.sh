#!/usr/bin/env bash
# extensions-expiry-renew-stand.sh: issuance profile and expiry on the ISOLATED
# stand, asserted (gaps 5 and 6 of the 2026-10-25 independent check).
#
#   A  six CSRs through /enroll with a demo-120s token: none asking for anything
#      (control), CA:TRUE, keyCertSign, anyExtendedKeyUsage, serverAuth+OCSPSigning,
#      a foreign SAN. Every leaf must carry EXACTLY the v3_m2m_leaf profile:
#      SKI, AKI, basicConstraints critical CA:FALSE, keyUsage critical
#      digitalSignature, extendedKeyUsage clientAuth; nothing else.
#   B  /renew with a hostile CSR (CA:TRUE, serverAuth+OCSPSigning, foreign SAN in
#      one CSR) for the control leaf: the successor carries exactly the profile.
#      /renew with a CSR for another CN: refused, nothing issued.
#   C  an expired certificate on /renew: (1) on a keep-alive connection opened
#      before notAfter: 400 from client_cert_expiry.lua, its log line names
#      /renew; (2) on a fresh connection: refused at the handshake (400);
#      nothing issued for that CN.
#
# Usage: extensions-expiry-renew-stand.sh WORKDIR
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
die(){ echo "GUARD ABORT: $*"; exit 90; }
stand_guard "$W"
pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
log(){ echo "$(date -u +%H:%M:%S) $*"; }
LAST=0; pace(){ local w=$(( LAST + 13 - $(date +%s) )); [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }
rows(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$"' "$IDX" | wc -l; }
# Exactly the v3_m2m_leaf extensions, nothing else (prints the reason when not).
profile_ok(){ $O x509 -in "$1" -noout -text | python3 -I -c '
import sys, re
t = sys.stdin.read()
m = re.search(r"X509v3 extensions:\n(.*?)\n    Signature Algorithm", t, re.S)
if not m: print("no extensions"); sys.exit(1)
ext, cur = {}, None
for line in m.group(1).splitlines():
    s = line.strip()
    if line.startswith(" " * 12) and not line.startswith(" " * 13):   # header: exactly 12 spaces
        cur = s; ext[cur] = []
    elif cur: ext[cur].append(s)
want = {
  "X509v3 Subject Key Identifier:": None,
  "X509v3 Authority Key Identifier:": None,
  "X509v3 Basic Constraints: critical": ["CA:FALSE"],
  "X509v3 Key Usage: critical": ["Digital Signature"],
  "X509v3 Extended Key Usage:": ["TLS Web Client Authentication"],
}
bad = [k for k in ext if k not in want] + [k for k in want if k not in ext]
bad += [f"{k}={ext[k]}" for k, v in want.items() if v is not None and k in ext and ext[k] != v]
if bad: print("profile differs:", bad); sys.exit(1)
'; }
enroll(){ # enroll NAME CN EXT -> $W/NAME/{client.key,client.crt}; prints HTTP code
	local d="$W/$1" t addext=(); mkdir -p "$d"; cp $CA "$d/ca-chain.crt"; [ -n "$3" ] && addext=(-addext "$3")
	$O req -new -newkey ML-DSA-65 -nodes -keyout "$d/client.key" -out "$d/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$2" "${addext[@]}" 2>/dev/null
	t=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?cn=$2&ttl=300&profile=demo-120s" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")')
	CSR_FILE="$d/csr.pem" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))' > "$d/body.json"
	curl -s "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d @"$d/body.json" -o "$d/enroll.json" -w '%{http_code}'
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1])).get("certificate",""))' "$d/enroll.json" "$d/client.crt" 2>/dev/null
}
TS=$(date -u +%H%M%S)
declare -A EXT=(
 [ctrl]=""
 [catrue]="basicConstraints=critical,CA:TRUE"
 [kucertsign]="keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
 [anyeku]="extendedKeyUsage=anyExtendedKeyUsage"
 [serverocsp]="extendedKeyUsage=serverAuth,OCSPSigning"
 [san]="subjectAltName=DNS:pqc-gw.local,DNS:attacker.example,IP:192.0.2.99,URI:spiffe://lab/admin"
)
echo; echo "== A  /enroll, six CSRs, demo-120s tokens"
for c in ctrl catrue kucertsign anyeku serverocsp san; do
	pace; code=$(enroll "$c" "ext-$c-$TS" "${EXT[$c]}")   # pace here: inside $(...) it would not keep LAST
	r=$(profile_ok "$W/$c/client.crt" 2>&1)
	check "A $c (asked: ${EXT[$c]:-nothing}): HTTP $code, exactly the M2M profile ${r:+($r)}" "[ '$code' = 201 ] && [ -z \"\$(profile_ok '$W/$c/client.crt')\" ]"
done

echo; echo "== C1  keep-alive connection for the 'catrue' leaf, opened before its notAfter"
K="$W/catrue"; cat "$K/client.key" "$K/client.crt" > "$K/identity.pem"
NA=$($O x509 -in "$K/client.crt" -noout -enddate | cut -d= -f2); NAE=$(date -u -d "$NA" +%s); CNC="ext-catrue-$TS"
log "notAfter $NA"
python3 -I - "$K/identity.pem" "$CA" "$NAE" > "$W/c1.log" 2>&1 <<'PY' &
import http.client, os, socket, ssl, sys, time, json
ident, ca, nae = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context(cafile=ca); ctx.load_cert_chain(ident)
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(os.environ["STAND_TLS_PORT"])), timeout=10), server_hostname="pqc-gw.local")
c = http.client.HTTPConnection("pqc-gw.local", int(os.environ["STAND_TLS_PORT"]), timeout=10); c.sock = s
c.request("GET", "/"); r = c.getresponse(); r.read(); print("before", r.status)
while time.time() < nae - 12:         # keep the connection busy (< 75 s idle), stop before notAfter
    time.sleep(10); c.request("GET", "/"); r = c.getresponse(); r.read()
print("last GET before notAfter", r.status)
while time.time() < nae + 2: time.sleep(0.5)
body = json.dumps({"csr": "x", "signature": "x", "timestamp": int(time.time())})
c.request("POST", "/renew", body=body, headers={"Content-Type": "application/json"})
r = c.getresponse(); r.read(); print("renew_after_notAfter", r.status, r.getheader("Connection"))
PY
CP=$!

echo; echo "== B  /renew with a hostile CSR for the control leaf, and with a CSR for another CN"
D="$W/ctrl"; NB=$(date -u -d "$($O x509 -in "$D/client.crt" -noout -startdate | cut -d= -f2)" +%s)
while [ "$(date +%s)" -lt $(( NB + 60 + 63 )) ]; do sleep 1; done   # past half of the lifetime
cp -r "$D" "$W/ctrl-othercn"
$O genpkey -algorithm ML-DSA-65 -out "$D/pending.key" 2>/dev/null
$O req -new -key "$D/pending.key" -out "$D/pending.csr" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=ext-ctrl-$TS" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "extendedKeyUsage=serverAuth,OCSPSigning" \
	-addext "subjectAltName=DNS:pqc-gw.local,IP:192.0.2.99" 2>/dev/null
OLD=$($O x509 -in "$D/client.crt" -noout -serial | cut -d= -f2)
bash "$HERE/renew-client.sh" --dir "$D" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --once > "$W/b-renew.out" 2>&1; rc=$?
NEW=$($O x509 -in "$D/client.crt" -noout -serial | cut -d= -f2)
r=$(profile_ok "$D/client.crt" 2>&1)
check "B hostile renewal CSR: renewed ($OLD -> $NEW), successor has exactly the M2M profile ${r:+($r)}" "[ $rc = 0 ] && [ '$OLD' != '$NEW' ] && [ -z \"\$(profile_ok '$D/client.crt')\" ]"
X="$W/ctrl-othercn"; R0=$(rows "other-$TS")
$O genpkey -algorithm ML-DSA-65 -out "$X/pending.key" 2>/dev/null
$O req -new -key "$X/pending.key" -out "$X/pending.csr" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=other-$TS" 2>/dev/null
bash "$HERE/renew-client.sh" --dir "$X" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --once > "$W/b-othercn.out" 2>&1; rc=$?
check "B renewal CSR for another CN: refused (exit $rc, $(grep -o '"reason":"[a-z_]*"' "$W/b-othercn.out" | head -1)), nothing issued for it" "[ $rc != 0 ] && [ \$(rows other-$TS) = $R0 ]"

echo; echo "== C  expired certificate on /renew"
wait $CP; cat "$W/c1.log" | sed 's/^/   /'
check "C1 keep-alive /renew after notAfter: 400 and the connection closed" "grep -q 'renew_after_notAfter 400 close' '$W/c1.log'"
sleep 1
check "C1 gateway log names /renew" "docker exec $GW sh -c 'grep client_cert_expiry /var/log/nginx/pqc-mtls-error.log' | grep 'serial $($O x509 -in "$K/client.crt" -noout -serial | cut -d= -f2)' | grep -q 'on /renew'"
mkdir -p "$W/c2"; cp "$K/client.key" "$K/client.crt" "$K/ca-chain.crt" "$W/c2/"
bash "$HERE/renew-client.sh" --dir "$W/c2" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --once > "$W/c2-renew.out" 2>&1; rc=$?
ACC=$(docker exec $GW sh -c "grep '\"uri\":\"/renew\"' /var/log/nginx/pqc-mtls-access.log | grep 'CN=$CNC,' | tail -1")
check "C2 fresh connection, expired certificate on /renew: refused (exit $rc), access log 400 with verify FAILED" "[ $rc != 0 ] && echo '$ACC' | grep -q '\"status\":400' && echo '$ACC' | grep -q 'FAILED'"
check "C nothing issued for $CNC beyond its first certificate" "[ \$(rows $CNC) = 1 ]"
echo; echo "== result: $pass passed, $fail failed"
exit $fail
