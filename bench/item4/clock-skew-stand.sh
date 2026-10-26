#!/usr/bin/env bash
# clock-skew-stand.sh: renewal with a client whose clock is off, on the ISOLATED
# stand (ITEM4-Design gap row 26; independent check 2026-10-25). The reference
# client's --clock-offset makes it sign its proof of possession, schedule, and
# verify the returned certificate as if its clock were off by N seconds.
#
# The server sides involved: the proof timestamp must be within 120 s of the
# API's clock (POP_SKEW_S, refused as pop_stale); the custodian backdates
# notBefore by 60 s, so a client up to 60 s behind accepts its new certificate.
#
#   -45 s   renewed (inside both)
#   +100 s  renewed (proof inside 120 s)
#   -90 s   the server issues, but the client, 90 s behind, finds the new
#           certificate not yet valid and refuses it (kept pending; recorded)
#   -150 s  refused pop_stale, nothing issued
#   +150 s  refused pop_stale, nothing issued
#
# Usage: clock-skew-stand.sh WORKDIR
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
rows(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$"' "$IDX" | wc -l; }
pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
LAST=0; pace(){ local w=$(( LAST + 13 - $(date +%s) )); [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }
TS=$(date -u +%H%M%S)
CASES="m45:-45 p100:100 m90:-90 m150:-150 p150:150"
for c in $CASES; do n=${c%%:*}; pace; enroll "skew-$n-$TS" demo-120s "$W/$n"; done
for c in $CASES; do
	n=${c%%:*}; off=${c#*:}; d="$W/$n"; cn="skew-$n-$TS"
	nb=$(date -u -d "$($O x509 -in "$d/client.crt" -noout -startdate | cut -d= -f2)" +%s)
	while [ "$(date +%s)" -lt $(( nb + 60 + 63 )) ]; do sleep 1; done
	old=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2); r0=$(rows "$cn")
	bash "$HERE/renew-client.sh" --dir "$d" --url $ADMIN --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --once --clock-offset "$off" > "$d/renew.out" 2>&1; rc=$?
	new=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2); r1=$(rows "$cn")
	reason=$(grep -o '"reason":"[a-z_]*"' "$d/renew.out" | head -1)
	echo "   offset $off s: exit $rc, serial $old -> $new, CA rows $r0 -> $r1 ${reason} $(grep -o 'REFUSED[^"]*' "$d/renew.out" | head -1)"
	case $n in
	m45|p100) check "offset $off s: renewed" "[ $rc = 0 ] && [ '$old' != '$new' ] && [ $r1 = $(( r0 + 1 )) ]" ;;
	m90) check "offset $off s: issued by the server, refused by the client as not yet valid, still pending" "[ $rc != 0 ] && [ '$old' = '$new' ] && [ $r1 = $(( r0 + 1 )) ] && grep -q 'does not verify' '$d/renew.out' && [ -s '$d/pending.key' ]" ;;
	m150|p150) check "offset $off s: refused pop_stale, nothing issued" "[ $rc != 0 ] && echo '$reason' | grep -q pop_stale && [ $r1 = $r0 ]" ;;
	esac
done
echo "== result: $pass passed, $fail failed"
exit $fail
