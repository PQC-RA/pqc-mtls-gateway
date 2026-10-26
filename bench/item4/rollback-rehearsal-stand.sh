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
#   2. stage 1 -> today: custodian and API on their pre-fix images, gateway and
#      crl-renewer on the live commit's config (9d8cad2); all four recreated.
#      Old code on new state: the token minted by the new code enrolls; admin
#      list and detail read the index; revocation reaches the CRL and the edge
#   3. roll forward: the override and env restored, four services recreated,
#      e2e-renew-stand.sh passes again
#
# Usage: rollback-rehearsal-stand.sh WORKDIR
set -uo pipefail
O=/opt/openssl-3.6.2/bin/openssl; export LD_LIBRARY_PATH=/opt/openssl-3.6.2/lib64 OPENSSL_CONF=/dev/null
W=${1:?workdir}; mkdir -p "$W"; HERE=$(cd "$(dirname "$0")" && pwd)
FIX=/root/pqcfix; FIXC=$FIX/fixc; RB=$FIX/rollback-9d8cad2
CA=$FIX/pki/ca-chain.crt; LIVE_CA=/etc/pki/pqc-ca/ca-chain.crt; DB=$FIX/pki/intermediate/db
ADM_C=$FIX/admin/fix-tmp-admin.crt; ADM_K=$FIX/admin/fix-tmp-admin.key
ADMIN=https://pqc-gw.local:19443; ENROLL=https://pqc-gw.local:18443/enroll
RES=(--resolve pqc-gw.local:19443:127.0.0.1 --resolve pqc-gw.local:18443:127.0.0.1)
OLD_CUST=pqc-gw-pqc-ca-custodian:pre-fix-20261025T092000Z
OLD_API=pqc-management-api:pre-fix-20261025T092000Z
die(){ echo "ABORT: $*"; exit 90; }
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
guard(){
	for p in 19443 18443; do
		echo | timeout 8 $O s_client -connect 127.0.0.1:$p -servername pqc-gw.local -showcerts 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > "$W/srv-$p.pem"
		$O verify -CAfile $CA -untrusted "$W/srv-$p.pem" "$W/srv-$p.pem" >/dev/null 2>&1 || die "$p does not chain to the throwaway CA"
		if $O verify -CAfile $LIVE_CA "$W/srv-$p.pem" >/dev/null 2>&1; then die "$p chains to LIVE"; fi
	done
	[ "$(docker port pqcfix-gateway 443/tcp)" = "127.0.0.1:19443" ] || die "ports are not pqcfix-gateway"
	echo "GUARD OK"
}
waitup(){ for i in $(seq 1 90); do
	local ok=1; for c in pqcfix-ca-custodian pqcfix-gateway; do [ "$(docker inspect -f '{{.State.Health.Status}}' $c 2>/dev/null)" = healthy ] || ok=0; done
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:13000/api/admin/health)" != 000 ] || ok=0
	[ $ok = 1 ] && return 0; sleep 2; done; return 1; }
token(){ local q="cn=$1&ttl=900"; [ -n "${2:-}" ] && q="$q&profile=$2"
	curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q"; }
tok_of(){ python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")' 2>/dev/null; }
enroll(){ # enroll TOKEN CN DIR -> http code
	mkdir -p "$3"; OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$3/client.key" -out "$3/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$2" 2>/dev/null
	local body; body=$(CSR_FILE="$3/csr.pem" TOKEN=$1 python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$3/enroll.json" -w '%{http_code}'
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1])).get("certificate",""))' "$3/enroll.json" "$3/client.crt" 2>/dev/null; }
mtls(){ curl -s "${RES[@]}" --cacert $CA --cert "$1/client.crt" --key "$1/client.key" --max-time 10 -o /dev/null -w '%{http_code}' "$ADMIN/" || true; }
TS=$(date -u +%H%M%S)

echo "== 0. preparation"
guard
bash /root/pqc-tls-gateway-fix/scripts/backup-state.sh stand "$W" > "$W/state-backup.out" 2>&1; tail -1 "$W/state-backup.out" | sed 's/^/      /'
check "key-free state backup before the rollback" "grep -q 'STATE BACKUP OK' '$W/state-backup.out'"
cp -p $FIX/compose.override.yml "$W/override.item4"; cp -p $FIX/env "$W/env.item4"
NEWTOK=$(token "rb-newtok-$TS" | tok_of); echo "      token minted by the new code for rb-newtok-$TS: ${NEWTOK:0:12}…"
check "a token minted by the new code" "[ -n '$NEWTOK' ]"

echo "== 1. stage 2 -> stage 1 (switches off)"
sed -i 's/^RENEWAL_ENABLED=.*/RENEWAL_ENABLED=/; s/^CUSTODIAN_DEMO_PROFILE=.*/CUSTODIAN_DEMO_PROFILE=/' $FIX/env
$FIXC up -d --no-deps pqc-ca-custodian management-api > "$W/s1-up.out" 2>&1; waitup || die "stack not healthy after stage-1 recreate"
docker exec pqcfix-crl-renewer touch /signals/renew-crl; sleep 4
D1="$W/s1-demo"; mkdir -p "$D1"
code=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 10 -o "$W/s1-renew.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$ADMIN/renew")
check "/renew answers 404 with the switch off" "[ '$code' = 404 ]"
c=$(enroll "$(token "rb-s1-legacy-$TS" | tok_of)" "rb-s1-legacy-$TS" "$W/s1-legacy")
check "legacy enrollment works (365 days)" "[ '$c' = 201 ] && [ \$(( \$(date -u -d \"\$($O x509 -in '$W/s1-legacy/client.crt' -noout -enddate | cut -d= -f2)\" +%s) - \$(date -u +%s) )) -gt 31000000 ]"
pt=$(token "rb-s1-prof-$TS" demo-120s); echo "      profile token: $(echo "$pt" | head -c 160)"
pc=000; ptok=$(echo "$pt" | tok_of); [ -n "$ptok" ] && pc=$(enroll "$ptok" "rb-s1-prof-$TS" "$W/s1-prof")
check "no renewal-profile certificate is issued with the switch off" "[ '$pc' != 201 ]"

echo "== 2. stage 1 -> today (old code on new state)"
python3 -I - "$FIX/compose.override.yml" "$OLD_CUST" "$OLD_API" "$RB" <<'PY'
import re, sys
p, cust, api, rb = sys.argv[1:]
s = open(p).read()
s = re.sub(r"image: pqcfix-ca-custodian:item4-[0-9a-f]+", "image: " + cust, s)
s = re.sub(r"image: pqcfix-management-api:item4-[0-9a-f]+", "image: " + api, s)
s = s.replace("   - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro\n", f"   - {rb}/config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro\n")
s = s.replace("   - ./config/nginx/lua:/etc/nginx/lua:ro\n", f"   - {rb}/config/nginx/lua:/etc/nginx/lua:ro\n")
s = s.replace("   - ./docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro\n", f"   - {rb}/docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro\n")
s = s.replace("   - ./scripts/pqc-crl-renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro\n", f"   - {rb}/scripts/pqc-crl-renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro\n")
open(p, "w").write(s)
PY
grep -c "$RB" $FIX/compose.override.yml | sed 's/^/      rollback mounts: /'
$FIXC up -d --no-deps pqc-ca-custodian management-api gateway crl-renewer > "$W/s0-up.out" 2>&1; waitup || die "stack not healthy on the old code"
docker ps --filter label=com.docker.compose.project=pqcfix --format '      {{.Names}} {{.Image}} {{.Status}}'
guard
check "old gateway config loads (nginx -t)" "docker exec pqcfix-gateway nginx -t > '$W/s0-nginx-t.out' 2>&1"
check "no /renew location on the old gateway" "! docker exec pqcfix-gateway grep -q 'location = /renew' /etc/nginx/nginx.conf"
c=$(enroll "$NEWTOK" "rb-newtok-$TS" "$W/s0-newtok"); echo "      enrollment with the new-code token: HTTP $c $(head -c 160 "$W/s0-newtok/enroll.json")"
check "the old API enrolls with a token minted by the new code" "[ '$c' = 201 ]"
c=$(enroll "$(token "rb-s0-legacy-$TS" | tok_of)" "rb-s0-legacy-$TS" "$W/s0-legacy")
check "the old API enrolls with its own token" "[ '$c' = 201 ]"
lc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 15 -o "$W/s0-list.json" -w '%{http_code}' "$ADMIN/admin/certs")
check "admin list reads the index written by the new code (E rows, lineage files present)" "[ '$lc' = 200 ] && grep -q 'rb-newtok-$TS' '$W/s0-list.json'"
SER=$($O x509 -in "$W/s0-legacy/client.crt" -noout -serial | cut -d= -f2)
dc=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K --max-time 15 -o "$W/s0-detail.json" -w '%{http_code}' "$ADMIN/admin/certs/$SER")
check "admin detail for $SER" "[ '$dc' = 200 ]"
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
