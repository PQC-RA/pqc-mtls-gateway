#!/usr/bin/env bash
# enroll-reserve-commit-stand.sh: the item-4 requirement's acceptance tests 1 to 4
# for bootstrap enrollment (reserve-then-commit tokens), on the ISOLATED stand.
# 50-Operations/Item-4-Requirement-Enroll-Token-Reserve-Commit in the vault.
#
#   T1 custodian stopped: 5xx, token unused; custodian back: the same token enrolls
#   T2 concurrent double submit of one token (custodian paused so the two
#      requests overlap for certain): one 201, one 409 in_progress, one index row
#   T3 custodian paused after it accepted the request (the API's 15 s timeout,
#      an ambiguous outcome): never a second certificate under the token, and the
#      token ends used if and only if the CA index has the certificate
#   T4 management-api killed between reserve and commit: after the lease
#      (60 s) and a reconcile pass (every 30 s), used iff the CA issued
#   T3, T4 then: the device retries with the SAME key and gets its certificate
#      (the committed one, as a replay, if the CA had issued); a different key
#      gets 403 token_already_used
#
# Token state is read from Redis (pqc:enroll:<token>): used = usedAt set,
# reserved = reservation set, else unused. CA rows from the stand index.
# Every enrollment request is paced (the endpoint allows 5 a minute per address).
#
# Usage: enroll-reserve-commit-stand.sh WORKDIR [PROFILE]   (PROFILE e.g. demo-120s; empty = legacy)
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; PROFILE=${2:-}; mkdir -p "$W"
API=$API; REDIS=$REDIS
die(){ echo "GUARD ABORT: $*"; exit 90; }
stand_guard "$W"

pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
log(){ echo "$(date -u +%H:%M:%S) $*"; }
LAST=0; pace(){ local w=$(( LAST + 13 - $(date +%s) )); [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }
token(){ # token CN -> token
	local q="cn=$1&ttl=900"; [ -n "$PROFILE" ] && q="$q&profile=$PROFILE"
	curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q" \
		| python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")'
}
state(){ # state TOKEN -> used:<serial> | reserved | unused | absent
	docker exec $REDIS redis-cli --raw GET "pqc:enroll:$1" | python3 -I -c '
import json,sys
s=sys.stdin.read().strip()
if not s: print("absent"); sys.exit()
m=json.loads(s)
print("used:"+str(m.get("serial","?")) if m.get("usedAt") else ("reserved" if m.get("reservation") else "unused"))'
}
rows(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$"' "$IDX" | wc -l; }
rowserial(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$" {print $4}' "$IDX" | tr '\n' ' ' | sed 's/ $//'; }
mkreq(){ # mkreq CN TOKEN NAME -> $W/NAME.json
	$O req -new -newkey ML-DSA-65 -nodes -keyout "$W/$3.key" -out "$W/$3.csr" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$1" 2>/dev/null
	CSR_FILE="$W/$3.csr" TOKEN=$2 python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))' > "$W/$3.json"
}
enroll(){ # enroll NAME -> prints HTTP code; body in $W/NAME.resp
	curl -s "${RES[@]}" --cacert $CA --max-time 40 -X POST "$ENROLL" -H 'Content-Type: application/json' -d @"$W/$1.json" -o "$W/$1.resp" -w '%{http_code}' || true
}
api_up(){ for _ in $(seq 1 60); do
	[ "$(curl -s "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -o /dev/null -w '%{http_code}' --max-time 5 "$ADMIN/admin/certs/enrollment-tokens")" = 200 ] && return 0; sleep 1; done; return 1; }
cust_up(){ for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Health.Status}}' $CUST)" = healthy ] && return 0; sleep 1; done; return 1; }
# recovered NAME CN: the retry's 201 response carries the certificate the CA index
# holds for CN, with the key of NAME's CSR (the device has its certificate, no admin)
recovered(){ local r="$W/$1.resp"
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1])).get("certificate",""))' "$r" "$W/$1.got.crt" 2>/dev/null
	[ -s "$W/$1.got.crt" ] || return 1
	[ "$($O x509 -in "$W/$1.got.crt" -noout -serial | cut -d= -f2)" = "$(rowserial "$2")" ] || return 1
	[ "$($O x509 -in "$W/$1.got.crt" -noout -pubkey | $O dgst -sha256 -r)" = "$($O req -in "$W/$1.csr" -noout -pubkey | $O dgst -sha256 -r)" ]
}
consistent(){ # consistent CN TOKEN: used iff exactly one row with that serial; unused iff no row
	local st r; st=$(state "$2"); r=$(rows "$1")
	case "$st" in used:*) [ "$r" = 1 ] && [ "${st#used:}" = "$(rowserial "$1")" ] ;; unused) [ "$r" = 0 ] ;; *) return 1 ;; esac
}
trap 'docker unpause $CUST >/dev/null 2>&1; docker start $CUST $API >/dev/null 2>&1' EXIT
TS=$(date -u +%H%M%S)

echo; echo "== T1 custodian stopped"
CN1=rc1-$TS; T1=$(token $CN1); mkreq $CN1 "$T1" t1
docker stop $CUST >/dev/null; log "custodian stopped"
pace; c=$(enroll t1); log "enroll -> $c $(head -c 160 "$W/t1.resp")"
check "T1 custodian down: 5xx" "[[ '$c' =~ ^5 ]]"
check "T1 token still unused" "[ \"\$(state $T1)\" = unused ]"
check "T1 no CA row for $CN1" "[ \$(rows $CN1) = 0 ]"
docker start $CUST >/dev/null; cust_up; log "custodian healthy"
pace; c=$(enroll t1); log "same token again -> $c"
check "T1 the same token enrolls after the custodian is back (201)" "[ '$c' = 201 ]"
check "T1 token used, exactly one CA row with its serial" "consistent $CN1 $T1"

echo; echo "== T2 concurrent double submit (custodian paused so both overlap)"
CN2=rc2-$TS; T2=$(token $CN2); mkreq $CN2 "$T2" t2a; mkreq $CN2 "$T2" t2b
pace; docker pause $CUST >/dev/null; log "custodian paused"
( enroll t2a > "$W/t2a.code" ) & PA=$!
sleep 1.5; cb=$(enroll t2b); log "second request -> $cb $(head -c 160 "$W/t2b.resp")"
check "T2 token reserved while the first request waits" "[ \"\$(state $T2)\" = reserved ]"
sleep 1; docker unpause $CUST >/dev/null; log "custodian unpaused"; wait $PA; ca=$(cat "$W/t2a.code"); log "first request -> $ca"
check "T2 one 201 and one 409" "[ '$ca $cb' = '201 409' ]"
check "T2 the 409 carries the reason in_progress" "grep -q '\"reason\":\"in_progress\"' '$W/t2b.resp'"
check "T2 exactly one CA row, token used with its serial" "consistent $CN2 $T2"

echo; echo "== T3 custodian paused past the API's 15 s timeout (ambiguous)"
CN3=rc3-$TS; T3=$(token $CN3); mkreq $CN3 "$T3" t3
pace; docker pause $CUST >/dev/null; log "custodian paused"
t0=$(date +%s); c=$(enroll t3); dt=$(( $(date +%s) - t0 )); log "enroll -> $c after ${dt} s $(head -c 160 "$W/t3.resp")"
check "T3 client told it failed (5xx)" "[[ '$c' =~ ^5 ]]"
check "T3 the API answered (502) inside the gateway's 30 s, not nginx's 504 (${dt} s)" "[ '$c' = 502 ] && [ $dt -lt 28 ]"
log "token now: $(state $T3)"
docker unpause $CUST >/dev/null; log "custodian unpaused"; sleep 3
log "after unpause: token $(state $T3), CA rows $(rows $CN3)"
pace; c=$(enroll t3); log "retry inside the lease -> $c $(head -c 120 "$W/t3.resp")"
check "T3 retry inside the lease issues nothing new" "[ '$c' != 201 ] || [ \$(rows $CN3) = 1 ]"
log "waiting for the lease (60 s) and a reconcile pass (30 s)"
for _ in $(seq 1 30); do st=$(state $T3); [ "$st" != reserved ] && break; sleep 5; done
log "settled: token $st, CA rows $(rows $CN3) ($(rowserial $CN3))"
check "T3 token used iff the CA index has the certificate" "consistent $CN3 $T3"
pace; c=$(enroll t3); log "retry with the same key after settling -> $c $(head -c 120 "$W/t3.resp")"
check "T3 the retry with the same key gets a certificate (201; a replay if the CA had issued)" "[ '$c' = 201 ] && recovered t3 $CN3"
check "T3 at most one certificate under the token" "[ \$(rows $CN3) -le 1 ]"
check "T3 still consistent after the retry" "consistent $CN3 $T3"
mkreq $CN3 "$T3" t3x; pace; c=$(enroll t3x); log "retry with a DIFFERENT key -> $c $(head -c 120 "$W/t3x.resp")"
check "T3 a different key is refused (403 token_already_used), nothing issued" "[ '$c' = 403 ] && grep -q token_already_used '$W/t3x.resp' && [ \$(rows $CN3) = 1 ]"

echo; echo "== T4 management-api killed between reserve and commit"
CN4=rc4-$TS; T4=$(token $CN4); mkreq $CN4 "$T4" t4
pace; docker pause $CUST >/dev/null; log "custodian paused"
( enroll t4 > "$W/t4.code" ) & P4=$!
sleep 2; log "token before the kill: $(state $T4)"
check "T4 token reserved before the kill" "[ \"\$(state $T4)\" = reserved ]"
docker kill $API >/dev/null; log "management-api killed"
docker unpause $CUST >/dev/null; log "custodian unpaused"; wait $P4; log "client -> $(cat "$W/t4.code")"
docker start $API >/dev/null; api_up && log "management-api back"
log "waiting for the lease (60 s) and a reconcile pass (30 s)"
for _ in $(seq 1 30); do st=$(state $T4); [ "$st" != reserved ] && break; sleep 5; done
log "settled: token $st, CA rows $(rows $CN4) ($(rowserial $CN4))"
check "T4 token used iff the CA issued" "consistent $CN4 $T4"
pace; c=$(enroll t4); log "retry with the same key after settling -> $c $(head -c 120 "$W/t4.resp")"
check "T4 the retry with the same key gets a certificate (201; a replay if the CA had issued)" "[ '$c' = 201 ] && recovered t4 $CN4"
check "T4 at most one certificate under the token" "[ \$(rows $CN4) -le 1 ]"
check "T4 still consistent after the retry" "consistent $CN4 $T4"
mkreq $CN4 "$T4" t4x; pace; c=$(enroll t4x); log "retry with a DIFFERENT key -> $c $(head -c 120 "$W/t4x.resp")"
check "T4 a different key is refused (403 token_already_used), nothing issued" "[ '$c' = 403 ] && grep -q token_already_used '$W/t4x.resp' && [ \$(rows $CN4) = 1 ]"

echo; echo "== audit: token.reserve / token.release / cert.enroll entries for this run"
grep -hE '"action":"(token\.(reserve|release|commit)|cert\.enroll)"' $MGMT_LOG \
	| grep -E "rc[1-4]-$TS" | python3 -I -c 'import json,sys
for l in sys.stdin:
    e=json.loads(l); print("  ", e["ts"], e["action"], e["target"], json.dumps(e.get("params",{}))[:120])'
echo; echo "== result: $pass passed, $fail failed"
exit $fail
