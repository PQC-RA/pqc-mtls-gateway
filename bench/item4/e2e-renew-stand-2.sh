#!/usr/bin/env bash
# e2e-renew-stand-2.sh: item 4 failure cases on the ISOLATED stand only.
# Same guard as e2e-renew-stand.sh (both stand ports chain to the throwaway CA,
# not to the live CA, and belong to $GW).
#
#   A. lost response: the renewal is issued but the client never sees it; the
#      retry with the same pending key gets the SAME successor (replay)
#   B. custodian down: renewal answers "retry later"; after the custodian is
#      back, the same pending key renews
#   C. two concurrent renewals with the SAME new key: one successor, both 201
#   D. two concurrent renewals with DIFFERENT new keys: one succeeds, the other
#      trips the conflict rule (by design: replicas sharing one certificate are
#      not supported, ADR-015 decision 9)
#   E. bootstrap enrollment racing a renewal for one CN: exactly one new certificate
#   F. lineage cap: a chain whose cap is less than half a lifetime away is refused;
#      a new bootstrap for that CN is then allowed (re-bootstrap window)
#
# Usage: e2e-renew-stand-2.sh WORKDIR
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; mkdir -p "$W"
HERE=$(cd "$(dirname "$0")" && pwd)
die(){ echo "GUARD ABORT: $*"; exit 90; }
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

stand_guard "$W"

TS=$(date -u +%H%M%S)
serial_of(){ $O x509 -in "$1" -noout -serial | cut -d= -f2; }
token(){ # token CN [PROFILE]
	local q="cn=$1&ttl=300"; [ -n "${2:-}" ] && q="$q&profile=$2"
	curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q" \
		| python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")' 2>/dev/null
}
enroll_with(){ # enroll_with TOKEN DIR -> HTTP code; client.crt on 201
	local t=$1 d=$2 cn body
	cn=$(sed -n 's#.*/CN=\([^/]*\).*#\1#p' "$d/subject")
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$d/enroll.key" -out "$d/enroll.csr" -subj "$(cat "$d/subject")" 2>/dev/null
	body=$(CSR_FILE="$d/enroll.csr" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$d/enroll.json" -w '%{http_code}'
}
bootstrap(){ # bootstrap CN PROFILE DIR
	mkdir -p "$3"; cp $CA "$3/ca-chain.crt"; echo "/C=BG/O=ACME/OU=M2M-Client/CN=$1" > "$3/subject"
	local t; t=$(token "$1" "$2"); [ -n "$t" ] || return 1
	[ "$(enroll_with "$t" "$3")" = 201 ] || return 1
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$3/enroll.json" "$3/client.crt"
	mv "$3/enroll.key" "$3/client.key"
}
# raw_renew DIR NEWKEY OUTPREFIX: one /renew request signed by DIR's current key for NEWKEY.
raw_renew(){
	local d=$1 nk=$2 out=$3 serial ts h
	OPENSSL_CONF=/dev/null $O req -new -key "$nk" -subj "$(cat "$d/subject")" -out "$out.csr" 2>/dev/null
	serial=$(serial_of "$d/client.crt"); ts=$(date -u +%s)
	h=$($O req -in "$out.csr" -outform DER | $O dgst -sha256 -r | cut -d' ' -f1)
	printf 'pqc-renew-v1\n%s\n%s\n%s' "$h" "$serial" "$ts" > "$out.msg"
	$O pkeyutl -sign -inkey "$d/client.key" -rawin -in "$out.msg" -out "$out.sig"
	CSR_FILE="$out.csr" SIG="$out.sig" TS=$ts python3 -I -c 'import base64,json,os; print(json.dumps({"csr":open(os.environ["CSR_FILE"]).read(),"pop":{"timestamp":int(os.environ["TS"]),"signature":base64.b64encode(open(os.environ["SIG"],"rb").read()).decode()}}))' > "$out.body"
	curl -sS "${RES[@]}" --cacert $CA --cert "$d/client.crt" --key "$d/client.key" --max-time 30 -H 'Content-Type: application/json' \
		--data-binary @"$out.body" -o "$out.json" -w '%{http_code}' -X POST "$URL/renew" > "$out.code" || echo 000 > "$out.code"
}
resp_serial(){ python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("serialNumber",""))' "$1" 2>/dev/null; }
wait_open(){ # wait until renewal opens (half the lifetime after the real issue time)
	local nb na; nb=$(date -u -d "$($O x509 -in "$1/client.crt" -noout -startdate | cut -d= -f2)" +%s); na=$(date -u -d "$($O x509 -in "$1/client.crt" -noout -enddate | cut -d= -f2)" +%s)
	local open=$(( nb + 60 + (na - nb - 60) / 2 + 2 )); local now; now=$(date -u +%s)
	[ "$now" -lt "$open" ] && sleep $(( open - now )); return 0
}
CLIENT=(bash "$HERE/renew-client.sh" --url $URL --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1)
gen_key(){ $O genpkey -algorithm ML-DSA-65 -out "$1" 2>/dev/null; }

echo "== A. lost response"
A="$W/A"; bootstrap "e2e-lost-$TS" demo-120s "$A" || die "bootstrap A failed"; wait_open "$A"
gen_key "$A/pending.key"; OPENSSL_CONF=/dev/null $O req -new -key "$A/pending.key" -subj "$(cat "$A/subject")" -out "$A/pending.csr" 2>/dev/null
raw_renew "$A" "$A/pending.key" "$A/lost"   # issued, response thrown away
LOST=$(resp_serial "$A/lost.json"); echo "      first request: HTTP $(cat "$A/lost.code"), serial $LOST (not delivered to the client)"
"${CLIENT[@]}" --dir "$A" --once > "$A/retry.out" 2>&1; sed 's/^/      /' "$A/retry.out"
check "the retry with the same key gets the same successor" "[ -n '$LOST' ] && [ \"\$(serial_of '$A/client.crt')\" = '$LOST' ] && grep -q replay '$A/retry.out'"

echo "== B. custodian down"
B="$W/B"; bootstrap "e2e-down-$TS" demo-120s "$B" || die "bootstrap B failed"; wait_open "$B"
docker stop $CUST >/dev/null
rc=0; "${CLIENT[@]}" --dir "$B" --once > "$B/down.out" 2>&1 || rc=$?; sed 's/^/      /' "$B/down.out"
check "with the custodian down the client is told to retry (exit 4)" "[ $rc -eq 4 ]"
PEND=$($O pkey -in "$B/pending.key" -pubout | $O dgst -sha256 -r)
docker start $CUST >/dev/null
for i in $(seq 1 90); do [ "$(docker inspect -f '{{.State.Health.Status}}' $CUST)" = healthy ] && break; sleep 1; done
"${CLIENT[@]}" --dir "$B" --once > "$B/up.out" 2>&1; sed 's/^/      /' "$B/up.out"
check "after the custodian is back the same pending key renews" "grep -q RENEWED '$B/up.out' && [ \"\$($O pkey -in '$B/client.key' -pubout | $O dgst -sha256 -r)\" = \"$PEND\" ]"

echo "== C. concurrent, same new key"
C="$W/C"; bootstrap "e2e-samekey-$TS" demo-120s "$C" || die "bootstrap C failed"; wait_open "$C"
gen_key "$C/nk.key"
raw_renew "$C" "$C/nk.key" "$C/r1" & raw_renew "$C" "$C/nk.key" "$C/r2" & wait
echo "      HTTP $(cat "$C/r1.code") serial $(resp_serial "$C/r1.json"); HTTP $(cat "$C/r2.code") serial $(resp_serial "$C/r2.json")"
check "both answered 201 with one and the same successor" "[ \"\$(cat '$C/r1.code')\" = 201 ] && [ \"\$(cat '$C/r2.code')\" = 201 ] && [ \"\$(resp_serial '$C/r1.json')\" = \"\$(resp_serial '$C/r2.json')\" ]"

echo "== D. concurrent, different new keys"
D="$W/D"; bootstrap "e2e-twokeys-$TS" demo-120s "$D" || die "bootstrap D failed"; wait_open "$D"
gen_key "$D/k1.key"; gen_key "$D/k2.key"; DS=$(serial_of "$D/client.crt")
raw_renew "$D" "$D/k1.key" "$D/r1" & raw_renew "$D" "$D/k2.key" "$D/r2" & wait
echo "      HTTP $(cat "$D/r1.code") $(head -c 160 "$D/r1.json"); HTTP $(cat "$D/r2.code") $(head -c 160 "$D/r2.json")"
check "exactly one 201 and one renewal_conflict" "[ \"\$( (cat '$D/r1.code'; echo; cat '$D/r2.code'; echo) | sort | tr '\n' ' ')\" = '201 409 ' ] && cat '$D/r1.json' '$D/r2.json' | grep -q 'reason.:.renewal_conflict'"
sleep 2
check "the predecessor $DS is revoked keyCompromise" "awk -F'\t' -v s=$DS '\$4==s && \$1==\"R\" && \$3 ~ /keyCompromise/' $DB/index.txt | grep -q ."

echo "== E. bootstrap racing a renewal for one CN"
E="$W/E"; bootstrap "e2e-race-$TS" demo-120s "$E" || die "bootstrap E failed"; wait_open "$E"
ET=$(token "e2e-race-$TS" demo-120s); gen_key "$E/nk.key"
before=$(awk -F'\t' -v cn="CN=e2e-race-$TS" 'index($6,cn)' $DB/index.txt | wc -l)
raw_renew "$E" "$E/nk.key" "$E/r1" & (enroll_with "$ET" "$E" > "$E/enroll.code") & wait
after=$(awk -F'\t' -v cn="CN=e2e-race-$TS" 'index($6,cn)' $DB/index.txt | wc -l)
echo "      renew HTTP $(cat "$E/r1.code"); enroll HTTP $(cat "$E/enroll.code"); index rows for the CN $before -> $after"
check "exactly one new certificate for the CN" "[ \$(( $after - $before )) -eq 1 ]"

echo "== F. lineage cap"
F="$W/F"; bootstrap "e2e-cap-$TS" demo-120s "$F" || die "bootstrap F failed"; FS=$(serial_of "$F/client.crt"); wait_open "$F"
# Stand-only manipulation: move this lineage's bootstrap back so its 365-day cap
# falls 30 s from now (less than half of a 120 s lifetime). Written like the
# custodian writes it (temp file, same owner and mode, rename).
python3 -I - "$DB/lineage.json" "$FS" <<'PY'
import json, os, sys, time
p, s = sys.argv[1], sys.argv[2]
L = json.load(open(p)); lid = L[s]["lineageId"]
for k, v in L.items():
    if v.get("lineageId") == lid: v["bootstrapAt"] = int(time.time() * 1000) - 365 * 86400 * 1000 + 30_000
t = p + ".tmp-e2e"; json.dump(L, open(t, "w")); os.chown(t, 1001, 1001); os.chmod(t, 0o640); os.rename(t, p)
PY
rc=0; "${CLIENT[@]}" --dir "$F" --once > "$F/cap.out" 2>&1 || rc=$?; sed 's/^/      /' "$F/cap.out"
check "renewal past the lineage cap is refused" "grep -q 'reason.:.lineage_cap_reached' '$F/cap.out'"
mkdir -p "$F/re"; cp "$F/subject" "$F/re/subject"; RT=$(token "e2e-cap-$TS" demo-120s)
code=$(enroll_with "$RT" "$F/re"); echo "      re-bootstrap HTTP $code"
check "a new bootstrap for that CN is allowed near the cap" "[ '$code' = 201 ]"

echo "== result: $pass passed, $fail failed"
[ $fail -eq 0 ]
