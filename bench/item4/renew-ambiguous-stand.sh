#!/usr/bin/env bash
# renew-ambiguous-stand.sh: a renewal whose outcome is ambiguous, on the ISOLATED
# stand (independent check 2026-10-25: "the ambiguous case on /renew is not tested").
#
# Two modes, N of each:
#   A  the custodian is paused: the API's first custodian call (the /issued
#      check of the presented certificate) times out after 15 s, the client is
#      told to retry (502), nothing was signed; after the custodian is back the
#      retry with the SAME pending key renews; exactly one successor
#   B  the custodian SIGNS but its answers carrying a certificate are dropped
#      (an iptables string rule in the stand custodian's network namespace,
#      matching "serialNumber"): the API's /sign call times out (ambiguous),
#      its inline lookup too, the client is told to retry; the CA index has the
#      new certificate before any retry (asserted); the rule is removed and the
#      retry with the same pending key gets exactly THAT certificate (replay)
#
# Usage: renew-ambiguous-stand.sh WORKDIR [N]
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; N=${2:-2}; mkdir -p "$W"
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
LAST=0; pace(){ local w=$(( LAST + 13 - $(date +%s) )); [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }
rowsfor(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$"' "$IDX" | wc -l; }
rowserial(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$" {print $4}' "$IDX" | tail -1; }
CPID=$(docker inspect -f '{{.State.Pid}}' $CUST)
RULE=(OUTPUT -p tcp --sport 8091 -m string --algo bm --string '"serialNumber"' -j DROP)
trap 'docker unpause $CUST >/dev/null 2>&1 || true; nsenter -t $CPID -n iptables -D "${RULE[@]}" 2>/dev/null || true' EXIT
for i in $(seq 1 $(( 2 * N ))); do
	mode=$([ $(( i % 2 )) = 1 ] && echo A || echo B)
	cn="amb$mode-$i-$TS"; d="$W/a$i"; pace; bootstrap "$cn" demo-120s "$d" || { echo "bootstrap $i failed"; fail=$((fail+1)); continue; }
	wait_open "$d"; r0=$(rowsfor "$cn"); old=$(serial_of "$d/client.crt"); T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	if [ $mode = A ]; then docker pause $CUST >/dev/null; else nsenter -t $CPID -n iptables -I "${RULE[@]}"; fi
	t0=$(date +%s); rc=0; "${CLIENT[@]}" --dir "$d" --once > "$d/first.out" 2>&1 || rc=$?; dt=$(( $(date +%s) - t0 ))
	if [ $mode = A ]; then docker unpause $CUST >/dev/null; fi
	sleep 2; r1=$(rowsfor "$cn"); CASER=$(rowserial "$cn")
	[ $mode = B ] && nsenter -t $CPID -n iptables -D "${RULE[@]}"
	echo "   $i ($mode): first attempt exit $rc after ${dt} s: $(tail -1 "$d/first.out" | cut -c1-90); CA rows $r0 -> $r1"
	check "$i ($mode): told to retry (exit 4) inside the gateway's 30 s, pending key kept" "[ $rc -eq 4 ] && [ $dt -lt 28 ] && [ -s '$d/pending.key' ]"
	if [ $mode = A ]; then
		check "$i (A): the API's custodian call timed out before any signing; nothing signed" "docker logs --since '$T0' $API 2>&1 | grep -q 'GET /issued/.*ambiguous' && [ $r1 -eq $r0 ]"
	else
		check "$i (B): the API's /sign call was ambiguous and the CA had signed (a new CA row before any retry)" "docker logs --since '$T0' $API 2>&1 | grep -qE 'POST /sign[): ].*ambiguous' && [ $r1 -eq $(( r0 + 1 )) ]"
	fi
	rc=0; "${CLIENT[@]}" --dir "$d" --once > "$d/retry.out" 2>&1 || rc=$?
	new=$(serial_of "$d/client.crt"); r2=$(rowsfor "$cn")
	echo "   $i ($mode): retry exit $rc, serial $old -> $new, CA rows $r2 $(grep -o '(replay)' "$d/retry.out")"
	check "$i ($mode): the device holds the successor, exactly one ($old -> $new)" "[ $rc -eq 0 ] && [ '$new' != '$old' ] && [ $r2 -eq $(( r0 + 1 )) ]"
	[ $mode = B ] && check "$i (B): it is the certificate the CA signed while the answer was lost ($CASER), as a replay" "[ '$new' = '$CASER' ] && grep -q '(replay)' '$d/retry.out'"
done
echo "== result: $pass passed, $fail failed"
exit $fail
