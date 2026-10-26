#!/usr/bin/env bash
# e2e-renew-stand.sh: item 4 end-to-end on the ISOLATED stand only
# (127.0.0.1:19443 mTLS, 127.0.0.1:18443 enrollment, throwaway PKI in /root/pqcfix/pki).
#
#   1. guard: both ports chain to the throwaway CA and NOT to the live CA,
#      and belong to pqcfix-gateway
#   2. bootstrap: admin token with profile demo-120s, enrollment on :18443
#   3. renewal refused before half of the lifetime (too_early)
#   4. the reference client renews twice unattended (--loop)
#   5. conflict rule: the superseded certificate renews again with another key
#      -> identity frozen, both certificates revoked
#   6. the revoked current certificate is refused on /renew
#   7. a legacy (365-day, no profile) certificate is refused (not_renewable)
#
# Usage: e2e-renew-stand.sh WORKDIR
set -uo pipefail
O=/opt/openssl-3.6.2/bin/openssl; export LD_LIBRARY_PATH=/opt/openssl-3.6.2/lib64 OPENSSL_CONF=/dev/null
W=${1:?workdir}; mkdir -p "$W"
HERE=$(cd "$(dirname "$0")" && pwd)
CA=/root/pqcfix/pki/ca-chain.crt; LIVE_CA=/etc/pki/pqc-ca/ca-chain.crt
ADM_C=/root/pqcfix/admin/fix-tmp-admin.crt; ADM_K=/root/pqcfix/admin/fix-tmp-admin.key
ADMIN=https://pqc-gw.local:19443; ENROLL=https://pqc-gw.local:18443/enroll
RES=(--resolve pqc-gw.local:19443:127.0.0.1 --resolve pqc-gw.local:18443:127.0.0.1)
die(){ echo "GUARD ABORT: $*"; exit 90; }
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

for p in 19443 18443; do
	echo | timeout 8 $O s_client -connect 127.0.0.1:$p -servername pqc-gw.local -showcerts 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > "$W/srv-$p.pem"
	$O verify -CAfile $CA -untrusted "$W/srv-$p.pem" "$W/srv-$p.pem" >/dev/null 2>&1 || die "$p does not chain to the throwaway CA"
	if $O verify -CAfile $LIVE_CA "$W/srv-$p.pem" >/dev/null 2>&1; then die "$p chains to LIVE"; fi
done
[ "$(docker port pqcfix-gateway 443/tcp)" = "127.0.0.1:19443" ] && [ "$(docker port pqcfix-gateway 8443/tcp)" = "127.0.0.1:18443" ] || die "ports are not pqcfix-gateway"
echo "GUARD OK"

TS=$(date -u +%H%M%S)
enroll() { # enroll CN PROFILE DIR -> client.crt/client.key in DIR
	local cn=$1 profile=$2 d=$3 q tok t body
	mkdir -p "$d"; cp $CA "$d/ca-chain.crt"
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$d/client.key" -out "$d/csr.pem" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=$cn" 2>/dev/null
	q="cn=$cn&ttl=300"; [ -n "$profile" ] && q="$q&profile=$profile"
	tok=$(curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q")
	t=$(echo "$tok" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d.get("token") or "")' 2>/dev/null)
	[ -n "$t" ] || { echo "no token: $(echo "$tok" | head -c 300)"; return 1; }
	body=$(CSR_FILE="$d/csr.pem" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$d/enroll.json" -w '%{http_code}\n' > "$d/enroll.code"
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$d/enroll.json" "$d/client.crt" 2>/dev/null
	[ -s "$d/client.crt" ]
}
lifetime() { local nb na; nb=$(date -u -d "$($O x509 -in "$1" -noout -startdate | cut -d= -f2)" +%s); na=$(date -u -d "$($O x509 -in "$1" -noout -enddate | cut -d= -f2)" +%s); echo $((na-nb)); }
CLIENT=(bash "$HERE/renew-client.sh" --url https://pqc-gw.local:19443 --resolve pqc-gw.local:19443:127.0.0.1)

echo "== 2. bootstrap (demo-120s)"
D="$W/demo"; CN="e2e-renew-$TS"
check "bootstrap enrollment with profile demo-120s" "enroll $CN demo-120s $D"
S0=$($O x509 -in "$D/client.crt" -noout -serial | cut -d= -f2); echo "      serial $S0, lifetime $(lifetime "$D/client.crt") s (60 s backdate included)"
$O x509 -in "$D/client.crt" -noout -ext basicConstraints,keyUsage,extendedKeyUsage 2>&1 | sed 's/^/      /'

echo "== 3. too early"
rc=0; "${CLIENT[@]}" --dir "$D" --once > "$W/too-early.out" 2>&1 || rc=$?
cat "$W/too-early.out" | sed 's/^/      /'
check "renewal before half of the lifetime is refused (too_early, exit 3)" "[ $rc -eq 3 ]"

echo "== 4. two unattended renewals"
timeout 260 "${CLIENT[@]}" --dir "$D" --loop --retry 5 > "$W/loop.out" 2>&1 &
LP=$!
for i in $(seq 1 260); do [ "$(grep -c RENEWED "$W/loop.out")" -ge 2 ] && break; sleep 1; done
kill $LP 2>/dev/null; wait $LP 2>/dev/null
sed 's/^/      /' "$W/loop.out"
check "two renewals without a person" "[ \$(grep -c RENEWED '$W/loop.out') -ge 2 ]"
S2=$($O x509 -in "$D/client.crt" -noout -serial | cut -d= -f2)
check "the current certificate carries the current key" "[ \"\$($O x509 -in '$D/client.crt' -noout -pubkey | $O dgst -sha256 -r)\" = \"\$($O pkey -in '$D/client.key' -pubout | $O dgst -sha256 -r)\" ]"
docker exec pqcfix-gateway sh -c 'grep "\"/renew\"\|POST /renew" /var/log/nginx/pqc-mtls-access.log | tail -6' > "$W/access-renew.log" 2>/dev/null
echo "      access log lines for /renew: $(wc -l < "$W/access-renew.log")"

echo "== 5. conflict rule"
# prev.crt is the superseded certificate (still valid for a few seconds). Renewing it
# again with a DIFFERENT new key is what a thief holding the old key would do.
C="$W/conflict"; mkdir -p "$C"; cp "$D/prev.crt" "$C/client.crt"; cp "$D/prev.key" "$C/client.key"; cp $CA "$C/ca-chain.crt"
PREV=$($O x509 -in "$C/client.crt" -noout -serial | cut -d= -f2)
rc=0; "${CLIENT[@]}" --dir "$C" --once > "$W/conflict.out" 2>&1 || rc=$?
sed 's/^/      /' "$W/conflict.out"
check "a second key for one predecessor is refused as a conflict" "grep -q 'reason.:.renewal_conflict' '$W/conflict.out'"
sleep 3
IDX=/root/pqcfix/pki/intermediate/db/index.txt
check "predecessor $PREV revoked keyCompromise" "awk -F'\t' -v s=$PREV '\$4==s && \$1==\"R\" && \$3 ~ /keyCompromise/' $IDX | grep -q ."
check "its successor $S2 revoked keyCompromise" "awk -F'\t' -v s=$S2 '\$4==s && \$1==\"R\" && \$3 ~ /keyCompromise/' $IDX | grep -q ."
check "lineage frozen" "python3 -I -c 'import json,sys; L=json.load(open(\"/root/pqcfix/pki/intermediate/db/lineage.json\")); sys.exit(0 if L.get(\"$S2\",{}).get(\"frozen\") else 1)'"

echo "== 6. revoked certificate refused"
sleep 3
rc=0; "${CLIENT[@]}" --dir "$D" --once > "$W/revoked.out" 2>&1 || rc=$?
sed 's/^/      /' "$W/revoked.out"
check "the revoked current certificate cannot renew" "[ $rc -ne 0 ] && ! grep -q RENEWED '$W/revoked.out'"

echo "== 7. legacy certificate refused"
L="$W/legacy"
check "legacy enrollment (no profile)" "enroll e2e-legacy-$TS '' $L"
rc=0; "${CLIENT[@]}" --dir "$L" --once > "$W/legacy.out" 2>&1 || rc=$?
sed 's/^/      /' "$W/legacy.out"
check "a 365-day certificate without a renewal profile is refused" "grep -q 'reason.:.not_renewable' '$W/legacy.out'"

echo "== result: $pass passed, $fail failed"
[ $fail -eq 0 ]
