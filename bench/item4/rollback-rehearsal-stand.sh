#!/usr/bin/env bash
# rollback-rehearsal-stand.sh: item 4 rollbacks rehearsed on the ISOLATED stand
# (ADR-019 decisions 5 and 6), with the old code running on state written by
# the new code, then rolled forward again.
#
#   0. guard (as the e2e scripts); key-free state backup; snapshot of the stand
#      override and env; a bootstrap token minted by the NEW code and left unused
#   1. stage 2 -> stage 1: switches off, custodian and API recreated, CRL renewed
#      (-updatedb under the lock); /renew answers 404; legacy enrollment works;
#      a profile token is refused
#   2. stage 1 -> before item 4: custodian and API on the pre-item-4 code, gateway
#      and crl-renewer on its config (ROLLBACK_COMMIT); all four recreated.
#      Old code on new state: the token minted by the new code enrolls; admin
#      list and detail read the index; revocation reaches the CRL and the edge
#   3. roll forward: the override and env restored, four services recreated,
#      e2e-renew-stand.sh passes again
#
# Added after the 2026-10-25 independent check (gaps 3, 4, 6):
#   0. also a token USED by the new code (its certificate is checked later)
#   1b. a token left RESERVED by the new code (custodian paused, enrollment sent,
#      management-api killed, custodian resumed: the CA issues, nobody commits),
#      then the drain step of the rollback procedure: wait until no reservation
#      is left in Redis (the reconcile commits it); the token is then used
#   1c. the same again but NOT drained: the rollback to the old code follows at
#      once, and the old API is shown that still-reserved token (the hazard the
#      drain step exists for; the result is recorded, not asserted)
#   2. old code: the used token is refused; admin detail reads a certificate
#      issued by the new code (its fingerprint-index entry)
#
# Usage: rollback-rehearsal-stand.sh WORKDIR
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/lib" && pwd)/pq-openssl.sh"
W=${1:?workdir}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
FIX=$STAND_DIR; FIXC=$STAND_COMPOSE; RB=$FIX/rollback
# the pre-item-4 code, prepared by scripts/stand-up.sh (ROLLBACK_COMMIT)
OLD_CUST=${STAND_OLD_CUSTODIAN:?source STAND_DIR/stand.env (scripts/stand-up.sh)}; OLD_API=${STAND_OLD_API:?}
die(){ echo "ABORT: $*"; exit 90; }
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
guard(){ stand_guard "$W"; }
waitup(){ for i in $(seq 1 90); do
	local ok=1; for c in $CUST $GW; do [ "$(docker inspect -f '{{.State.Health.Status}}' $c 2>/dev/null)" = healthy ] || ok=0; done
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:$STAND_API_PORT/api/admin/health)" != 000 ] || ok=0
	[ $ok = 1 ] && return 0; sleep 2; done; return 1; }
token(){ local q="cn=$1&ttl=900"; [ -n "${2:-}" ] && q="$q&profile=$2"
	curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q"; }
tok_of(){ python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")' 2>/dev/null; }
enroll(){ # enroll TOKEN CN DIR -> http code
	mkdir -p "$3"; OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$3/client.key" -out "$3/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$2" 2>/dev/null
	local body; body=$(CSR_FILE="$3/csr.pem" TOKEN=$1 python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$3/enroll.json" -w '%{http_code}'
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1])).get("certificate",""))' "$3/enroll.json" "$3/client.crt" 2>/dev/null; }
tstate(){ docker exec $REDIS redis-cli --raw GET "pqc:enroll:$1" | python3 -I -c '
import json,sys
s=sys.stdin.read().strip()
if not s: print("absent"); sys.exit()
m=json.loads(s); print("used:"+str(m.get("serial","?")) if m.get("usedAt") else ("reserved" if m.get("reservation") else "unused"))'; }
reservations(){ docker exec $REDIS sh -c 'for k in $(redis-cli --raw KEYS "pqc:enroll:*"); do [ "$k" = pqc:enroll:index ] || redis-cli --raw GET "$k"; done' | grep -c '"reservation"' || true; }
rows(){ awk -F'\t' -v cn="CN=$1" '$6 ~ cn"$"' $DB/index.txt | wc -l; }
leave_reserved(){ # leave_reserved TOKEN CN DIR: the CA issues, management-api dies before the commit
	pace; docker pause $CUST >/dev/null
	( enroll "$1" "$2" "$3" > "$3.code" 2>/dev/null ) & local p=$!
	sleep 2; docker kill $API >/dev/null; docker unpause $CUST >/dev/null; wait $p
	sleep 3; echo "      left: token $(tstate "$1"), CA rows for $2: $(rows "$2"), client got HTTP $(cat "$3.code" 2>/dev/null)"; }
mtls(){ curl -s "${RES[@]}" --cacert $CA --cert "$1/client.crt" --key "$1/client.key" --max-time 10 -o /dev/null -w '%{http_code}' "$ADMIN/" || true; }
TS=$(date -u +%H%M%S)
# /enroll allows 5 requests a minute per address (burst 3): pace every enrollment.
LAST=0; pace(){ local w=$(( LAST + 13 - $(date +%s) )); [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }

echo "== 0. preparation"
guard
bash "$HERE/../../scripts/backup-state.sh" stand "$W" > "$W/state-backup.out" 2>&1; tail -1 "$W/state-backup.out" | sed 's/^/      /'
check "key-free state backup before the rollback" "grep -q 'STATE BACKUP OK' '$W/state-backup.out'"
cp -p $FIX/compose.override.yml "$W/override.item4"; cp -p $FIX/env "$W/env.item4"
NEWTOK=$(token "rb-newtok-$TS" | tok_of); echo "      token minted by the new code for rb-newtok-$TS: ${NEWTOK:0:12}…"
check "a token minted by the new code" "[ -n '$NEWTOK' ]"
USEDTOK=$(token "rb-used-$TS" | tok_of); pace; c=$(enroll "$USEDTOK" "rb-used-$TS" "$W/s2-used")
check "a token used by the new code (201, token used)" "[ '$c' = 201 ] && [[ \"\$(tstate $USEDTOK)\" == used:* ]]"
USEDSER=$($O x509 -in "$W/s2-used/client.crt" -noout -serial | cut -d= -f2)

echo "== 1. stage 2 -> stage 1 (switches off)"
sed -i 's/^RENEWAL_ENABLED=.*/RENEWAL_ENABLED=/; s/^CUSTODIAN_DEMO_PROFILE=.*/CUSTODIAN_DEMO_PROFILE=/' $FIX/env
$FIXC up -d --no-deps pqc-ca-custodian management-api > "$W/s1-up.out" 2>&1; waitup || die "stack not healthy after stage-1 recreate"
T_UPD=$(date -u +%Y-%m-%dT%H:%M:%SZ); docker exec $RENEWER touch /signals/renew-crl; sleep 4
D1="$W/s1-demo"; mkdir -p "$D1"
# ADR-019 decision 5: the switch off reaches the custodian itself, -updatedb runs
# under the CA lock (the renewer's renewal does it, logged), unique_subject stays no.
check "the custodian itself runs with renewal off" "docker logs --since '$T_UPD' $CUST 2>&1 | grep -q 'renewal=off' || docker logs $CUST 2>&1 | grep 'listening' | tail -1 | grep -q 'renewal=off'"
check "-updatedb ran under the CA lock after the switch (renewer log)" "docker logs --since '$T_UPD' $RENEWER 2>&1 | grep -q 'Intermediate index updated'"
check "unique_subject stays no in index.txt.attr" "grep -q '^unique_subject = no' $DB/index.txt.attr"
code=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 10 -o "$W/s1-renew.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$ADMIN/renew")
check "/renew answers 404 with the switch off" "[ '$code' = 404 ]"
pace; c=$(enroll "$(token "rb-s1-legacy-$TS" | tok_of)" "rb-s1-legacy-$TS" "$W/s1-legacy")
check "legacy enrollment works (365 days)" "[ '$c' = 201 ] && [ \$(( \$(date -u -d \"\$($O x509 -in '$W/s1-legacy/client.crt' -noout -enddate | cut -d= -f2)\" +%s) - \$(date -u +%s) )) -gt 31000000 ]"
pt=$(token "rb-s1-prof-$TS" demo-120s); echo "      profile token: $(echo "$pt" | head -c 160)"
pc=000; ptok=$(echo "$pt" | tok_of); [ -n "$ptok" ] && { pace; pc=$(enroll "$ptok" "rb-s1-prof-$TS" "$W/s1-prof"); }
check "no renewal-profile certificate with the switch off (token refused at mint, or enrollment 4xx)" "{ [ -z '$ptok' ] && echo '$pt' | grep -qi 'disabled'; } || [[ '$pc' =~ ^4 ]]"

echo "== 1b. a reservation left by the new code, then the drain step"
R1=$(token "rb-res1-$TS" | tok_of); leave_reserved "$R1" "rb-res1-$TS" "$W/s1-res1"
check "token left reserved, the CA issued" "[ \"\$(tstate $R1)\" = reserved ] && [ \$(rows rb-res1-$TS) = 1 ]"
docker start $API >/dev/null; waitup || die "API not back"
for i in $(seq 1 40); do [ "$(reservations)" = 0 ] && break; sleep 5; done
echo "      drained after about $((i*5)) s: reservations left $(reservations), token $(tstate $R1)"
S1=$(awk -F'\t' -v cn="CN=rb-res1-$TS" '$6 ~ cn"$" {print $4}' $DB/index.txt)
check "drain: no reservation left; the token is used with the CA's serial ($S1)" "[ \"\$(reservations)\" = 0 ] && [ \"\$(tstate $R1)\" = 'used:$S1' ]"

echo "== 1c. a reservation NOT drained before the rollback (the hazard, recorded)"
R2=$(token "rb-res2-$TS" | tok_of); leave_reserved "$R2" "rb-res2-$TS" "$W/s1-res2"

echo "== 2. stage 1 -> today (old code on new state)"
python3 -I - "$FIX/compose.override.yml" "$OLD_CUST" "$OLD_API" "$RB" <<'PY'
import re, sys
p, cust, api, rb = sys.argv[1:]
s = open(p).read()
s = re.sub(r"image: \S*ca-custodian:\S+", "image: " + cust, s)
s = re.sub(r"image: \S*management-api[:@]\S+", "image: " + api, s)
s = s.replace("   - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro\n", f"   - {rb}/config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro\n")
s = s.replace("   - ./config/nginx/lua:/etc/nginx/lua:ro\n", f"   - {rb}/config/nginx/lua:/etc/nginx/lua:ro\n")
s = s.replace("   - ./docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro\n", f"   - {rb}/docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro\n")
s = s.replace("   - ./scripts/pqc-crl-renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro\n", f"   - {rb}/scripts/pqc-crl-renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro\n")
open(p, "w").write(s)
PY
grep -c "$RB" $FIX/compose.override.yml | sed 's/^/      rollback mounts: /'
$FIXC up -d --no-deps pqc-ca-custodian management-api gateway crl-renewer > "$W/s0-up.out" 2>&1; waitup || die "stack not healthy on the old code"
docker ps --filter label=com.docker.compose.project=$STAND_PROJECT --format '      {{.Names}} {{.Image}} {{.Status}}'
guard
check "old gateway config loads (nginx -t)" "docker exec $GW nginx -t > '$W/s0-nginx-t.out' 2>&1"
check "no /renew location on the old gateway" "! docker exec $GW grep -q 'location = /renew' /etc/nginx/nginx.conf"
pace; c=$(enroll "$NEWTOK" "rb-newtok-$TS" "$W/s0-newtok"); echo "      enrollment with the new-code token: HTTP $c $(head -c 160 "$W/s0-newtok/enroll.json")"
check "the old API enrolls with a token minted by the new code" "[ '$c' = 201 ]"
pace; c=$(enroll "$(token "rb-s0-legacy-$TS" | tok_of)" "rb-s0-legacy-$TS" "$W/s0-legacy")
check "the old API enrolls with its own token" "[ '$c' = 201 ]"
lc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 15 -o "$W/s0-list.json" -w '%{http_code}' "$ADMIN/admin/certs")
check "admin list reads the index written by the new code" "[ '$lc' = 200 ] && grep -q 'rb-newtok-$TS' '$W/s0-list.json'"
SER=$($O x509 -in "$W/s0-legacy/client.crt" -noout -serial | cut -d= -f2)
dc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 15 -o "$W/s0-detail.json" -w '%{http_code}' "$ADMIN/admin/certs/$SER")
check "admin detail for $SER" "[ '$dc' = 200 ]"
dc2=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 15 -o "$W/s0-detail-new.json" -w '%{http_code}' "$ADMIN/admin/certs/$USEDSER")
check "admin detail for $USEDSER, issued by the new code" "[ '$dc2' = 200 ] && grep -q 'rb-used-$TS' '$W/s0-detail-new.json'"
pace; c=$(enroll "$USEDTOK" "rb-used-$TS" "$W/s0-used-replay"); echo "      replay of the used token: HTTP $c $(head -c 120 "$W/s0-used-replay/enroll.json")"
check "the old API refuses a token the new code used" "[ '$c' = 403 ] && [ \$(rows rb-used-$TS) = 1 ]"
echo "      hazard: token $(tstate $R2) before the old API sees it; CA rows for rb-res2-$TS: $(rows rb-res2-$TS)"
pace; c=$(enroll "$R2" "rb-res2-$TS" "$W/s0-res2-replay")
echo "      HAZARD RESULT: the old API answered HTTP $c to the undrained reservation; CA rows for rb-res2-$TS now $(rows rb-res2-$TS); token $(tstate $R2) (used:? = marked used by the old API, which records no serial)" | tee "$W/hazard.txt"
check "mTLS works with the new certificate before revocation" "[ \"\$(mtls '$W/s0-legacy')\" = 404 ]"
rc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 -H 'Content-Type: application/json' --max-time 15 -o "$W/s0-revoke.json" -w '%{http_code}' -X POST "$ADMIN/admin/certs/revoke" -d "{\"serial\":\"$SER\",\"reason\":\"superseded\"}")
sleep 5
check "the old code revokes, and the old renewer publishes it" "[ '$rc' = 200 ] && awk -F'\t' -v s=$SER '\$4==s && \$1==\"R\"' $DB/index.txt | grep -q ."
check "the revoked certificate is refused at the edge" "[ \"\$(mtls '$W/s0-legacy')\" != 404 ]"

echo "== 3. roll forward"
cp -p "$W/override.item4" $FIX/compose.override.yml; cp -p "$W/env.item4" $FIX/env
$FIXC up -d --no-deps pqc-ca-custodian management-api gateway crl-renewer > "$W/fwd-up.out" 2>&1; waitup || die "stack not healthy after roll forward"
guard
bash "$HERE/e2e-renew-stand.sh" "$W/e2e-after" > "$W/e2e-after.out" 2>&1; tail -1 "$W/e2e-after.out" | sed 's/^/      /'
check "item 4 end-to-end passes again after the roll forward" "grep -q '0 failed' '$W/e2e-after.out'"

echo "== result: $pass passed, $fail failed"
[ $fail -eq 0 ]
