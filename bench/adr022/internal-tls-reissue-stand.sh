#!/usr/bin/env bash
# internal-tls-reissue-stand.sh: the :8081 move of ADR-022 rehearsed on the
# ISOLATED stand from the state live is in today (RSA-2048 internal CA and
# leaf), with running containers, in the order the README gives, including the
# failure the order exists to prevent (review finding M1: management-api pins
# the internal CA and reads it only at start).
#
#   source STAND_DIR/stand.env; internal-tls-reissue-stand.sh WORKDIR [OLD_COMMIT]
#
#   0. the RSA internal CA and leaf of OLD_COMMIT's setup-pki.sh (default: the
#      last commit before ADR-022) written IN PLACE over the stand's, the new
#      layout's files removed; gateway reloaded, management-api restarted: it
#      now runs with the RSA CA only. Admin call and route push work.
#   1. plain setup-pki.sh (what deploy.sh runs): changes nothing, says so
#   2. REISSUE_INTERNAL_CA=1 setup-pki.sh with that management-api still
#      running: the trust file becomes the RSA + ML-DSA-65 bundle (same inode),
#      :8081 still RSA, everything works; the switch to ML-DSA-65 is REFUSED
#      because management-api predates the bundle (the M1 failure, prevented)
#   3. management-api restarted (the API step of the rollout)
#   4. switch to ML-DSA-65: no management-api restart; route push (a new TLS
#      connection from the RUNNING process), admin call, JWKS, healthcheck work
#   5. rollback to RSA, 6. forward again: same, no restart
#   7. GATEWAY_TLS_LEAF_ALG=ML-DSA-65 (end state): works; a switch to RSA is refused
#   8. drop-rsa: the trust file holds the ML-DSA-65 CA only; after a
#      management-api restart everything works; RSA can no longer be switched to
# The route push is the probe for the running process: the admin key store and
# jwks-rsa cache the JWKS for an hour, a push opens a connection each time.
set -uo pipefail
W=${1:?workdir}; mkdir -p "$W"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); TREE=$(cd "$HERE/../.." && pwd)
. "$HERE/../item4/stand-env.sh"
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitup(){ local c ok; for _ in $(seq 1 90); do ok=1
	for c in "$CUST" "$GW"; do [ "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)" = healthy ] || ok=0; done
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' "http://127.0.0.1:$STAND_API_PORT/api/admin/health")" != 000 ] || ok=0
	[ $ok = 1 ] && return 0; sleep 2; done; return 1; }
stand_guard "$W"
ENVF=$STAND_DIR/env; P=$STAND_DIR/pki; S=$STAND_DIR/ssl
OLD=${2:-${OLD_COMMIT:-14ec12f}}
SW=(env PKI_DIR="$P" SSL_DIR="$S" OPENSSL_BIN="$O" GATEWAY_CONTAINER="$GW" API_CONTAINER="$API" bash "$TREE/scripts/internal-tls-switch.sh")
PKI=(env PKI_DIR="$P" SSL_DIR="$S" OPENSSL_BIN="$O" SKIP_APP_PERMS=1 bash "$TREE/scripts/setup-pki.sh")
CN=adr022-m1-probe
adm(){ curl -sS "${RES[@]}" --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" --max-time 15 -o /dev/null -w '%{http_code}' "$ADMIN/admin/whoami" 2>/dev/null || echo 000; }
push(){ # PUT one client policy: management-api pushes the full routing document to :8081
	curl -sS "${RES[@]}" --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" --max-time 20 -X PUT \
		-H X-PQC-CSRF:1 -H "Origin: https://127.0.0.1" -H 'Content-Type: application/json' \
		-d "{\"backend\":\"http://127.0.0.1:9\",\"description\":\"adr022 M1 probe $1\"}" \
		-o "$W/push-$1.out" -w '%{http_code}' "$ADMIN/admin/policy/routes/$CN" 2>/dev/null || echo 000; }
alg(){ $O x509 -in "$1" -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -1; }
ncerts(){ grep -c 'BEGIN CERTIFICATE' "$1"; }
api_view(){ docker exec "$API" cat /etc/pki/internal-tls-ca.crt | grep -c 'BEGIN CERTIFICATE'; }
served_alg(){ docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -servername gateway -brief 2>&1' | sed -n 's/^Signature type: //p'; }
health(){ docker exec "$GW" sh -c "printf 'GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -CAfile /etc/pki/pqc-ca/internal-tls-ca.crt -verify_return_error -quiet 2>/dev/null | grep -q '200 OK'"; }
node_jwks(){ # a NEW Node process in the container: the mounted trust file as Node reads it
	docker exec "$API" node -e '
		require("https").get(process.env.GATEWAY_JWKS_URI, r => { console.log("HTTP " + r.statusCode); r.resume(); })
			.on("error", e => console.log("ERR " + e.message));'; }
started(){ docker inspect -f '{{.State.StartedAt}}' "$API"; }
inodes(){ stat -c %i "$P/internal-tls-ca.crt" "$P/internal-tls/internal-tls-ca.key" "$S/internal-tls.crt" "$S/internal-tls.key" | tr '\n' ' '; }
leaf_env(){ # leaf_env VALUE: set GATEWAY_TLS_LEAF_ALG and recreate management-api (and gateway: nginx resolves it once)
	if grep -q '^GATEWAY_TLS_LEAF_ALG=' "$ENVF"; then sed -i "s|^GATEWAY_TLS_LEAF_ALG=.*|GATEWAY_TLS_LEAF_ALG=$1|" "$ENVF"; else echo "GATEWAY_TLS_LEAF_ALG=$1" >> "$ENVF"; fi
	"$STAND_COMPOSE" up -d --no-deps --force-recreate management-api gateway > "$W/up-leaf-$1.out" 2>&1; waitup; sleep 2; }
api_restart(){ docker restart "$API" >/dev/null; waitup; sleep 2; }
state(){ echo "      trust file $(ncerts "$P/internal-tls-ca.crt") CA(s) (API sees $(api_view)), :8081 serves $(served_alg), API started $(started)"; }

leaf_env ""
echo "== 0. the RSA internal TLS of $OLD (live today), written in place; management-api restarted on it"
mkdir -p "$W/old"; git -C "$TREE" show "$OLD:scripts/setup-pki.sh" > "$W/old/setup-pki.sh" 2>/dev/null \
	|| { [ -f "$STAND_DIR/rollback-tree/scripts/setup-pki.sh" ] && cp "$STAND_DIR/rollback-tree/scripts/setup-pki.sh" "$W/old/setup-pki.sh"; }
[ -s "$W/old/setup-pki.sh" ] || { echo "ABORT: no setup-pki.sh of $OLD"; exit 90; }
mkdir -p "$W/old/repo/scripts" "$W/old/repo/pki"; cp "$W/old/setup-pki.sh" "$W/old/repo/scripts/"; cp -r "$TREE/pki/templates" "$W/old/repo/pki/"; cp "$TREE/scripts/gen-enroll-classical-cert.sh" "$W/old/repo/scripts/"
( cd "$W/old/repo" && PKI_DIR="$W/old/pki" SSL_DIR="$W/old/ssl" OPENSSL_BIN=$O SKIP_APP_PERMS=1 SERVER_IP=127.0.0.1 bash scripts/setup-pki.sh > "$W/old/setup.log" 2>&1 )
[ "$(alg "$W/old/pki/internal-tls-ca.crt")" = rsaEncryption ] || { echo "ABORT: $OLD did not make an RSA internal CA"; exit 90; }
cat "$W/old/pki/internal-tls-ca.crt" > "$P/internal-tls-ca.crt"; cat "$W/old/pki/internal-tls/internal-tls-ca.key" > "$P/internal-tls/internal-tls-ca.key"
cat "$W/old/ssl/internal-tls.crt" > "$S/internal-tls.crt"; cat "$W/old/ssl/internal-tls.key" > "$S/internal-tls.key"
rm -f "$P/internal-tls-ca-mldsa.crt" "$P/internal-tls-ca-rsa.crt" "$P/internal-tls/internal-tls-ca-rsa.key" \
	"$S/internal-tls-mldsa.crt" "$S/internal-tls-mldsa.key" "$S/internal-tls-rsa.crt" "$S/internal-tls-rsa.key"
rm -rf "$W/old/pki" "$W/old/ssl"
docker exec "$GW" nginx -s reload >/dev/null 2>&1; sleep 2; api_restart
INO0=$(inodes); state
check "starting point: RSA CA only, :8081 serves RSA, admin 200, route push 200" \
	"[ \"\$(alg $P/internal-tls-ca.crt)\" = rsaEncryption ] && [ \"\$(ncerts $P/internal-tls-ca.crt)\" = 1 ] && [ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(adm)\" = 200 ] && [ \"\$(push 0)\" = 200 ]"
API_T0=$(started)

echo "== 1. plain setup-pki.sh, as deploy.sh runs it"
sha_before=$(sha256sum "$P/internal-tls-ca.crt" "$S/internal-tls.crt" "$S/internal-tls.key" | sha256sum)
"${PKI[@]}" > "$W/plain.log" 2>&1; rc=$?
grep -E 'WARNING|Left unchanged|REISSUE' "$W/plain.log" | sed 's/^/      /'
check "exit 0, warns, changes nothing (RSA CA and leaf untouched)" \
	"[ $rc = 0 ] && grep -q 'is rsaEncryption, not ML-DSA-65' '$W/plain.log' && [ \"\$(sha256sum $P/internal-tls-ca.crt $S/internal-tls.crt $S/internal-tls.key | sha256sum)\" = '$sha_before' ] && [ ! -e $P/internal-tls-ca-mldsa.crt ]"

echo "== 2. REISSUE_INTERNAL_CA=1 setup-pki.sh while management-api runs on the RSA CA only"
REISSUE_INTERNAL_CA=1 "${PKI[@]}" > "$W/reissue.log" 2>&1; rc=$?
grep -E 'kept|trust file|NEXT|Internal TLS' "$W/reissue.log" | sed 's/^/      /'; state
check "exit 0; trust file = bundle of 2 CAs (ML-DSA-65 first) in place (inodes $INO0); ML-DSA-65 CA and leaf beside; RSA copies kept" \
	"[ $rc = 0 ] && [ \"\$(inodes)\" = '$INO0' ] && [ \"\$(ncerts $P/internal-tls-ca.crt)\" = 2 ] && [ \"\$(alg $P/internal-tls-ca.crt)\" = ML-DSA-65 ] && [ \"\$(alg $P/internal-tls-ca-mldsa.crt)\" = ML-DSA-65 ] && [ \"\$(alg $S/internal-tls-mldsa.crt)\" = ML-DSA-65 ] && [ \"\$(alg $P/internal-tls-ca-rsa.crt)\" = rsaEncryption ] && [ \"\$(alg $S/internal-tls-rsa.crt)\" = rsaEncryption ]"
check ":8081 still serves RSA; admin 200 and route push 200 without any restart; healthcheck OK with the bundle" \
	"[ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(adm)\" = 200 ] && [ \"\$(push 2)\" = 200 ] && health"
"${SW[@]}" mldsa > "$W/switch-refused.log" 2>&1; rc=$?
sed 's/^/      /' "$W/switch-refused.log"
check "switch to ML-DSA-65 REFUSED: management-api started before the bundle (the M1 failure, prevented); nothing changed" \
	"[ $rc != 0 ] && grep -q 'started before' '$W/switch-refused.log' && [ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(push 2b)\" = 200 ]"
check "management-api was not restarted by steps 1-2" "[ \"\$(started)\" = '$API_T0' ]"

echo "== 3. management-api restarted (the API step of the rollout): it reads the bundle"
api_restart; API_T1=$(started); state
check "admin 200, route push 200 (RSA :8081, API on the bundle)" "[ \"\$(adm)\" = 200 ] && [ \"\$(push 3)\" = 200 ]"

echo "== 4. switch :8081 to ML-DSA-65 (gateway reload only)"
"${SW[@]}" mldsa > "$W/switch-mldsa.log" 2>&1; rc=$?
sed 's/^/      /' "$W/switch-mldsa.log"; state
check "switch OK, :8081 serves ML-DSA-65, verified with the trust file" "[ $rc = 0 ] && [ \"\$(served_alg)\" = mldsa65 ] && grep -q 'verification OK' '$W/switch-mldsa.log'"
check "NO management-api restart: route push 200 from the running process, admin 200, healthcheck OK" \
	"[ \"\$(started)\" = '$API_T1' ] && [ \"\$(push 4)\" = 200 ] && [ \"\$(adm)\" = 200 ] && health"
check "Node 22 in the container fetches the JWKS over the ML-DSA-65 :8081 with the mounted bundle" "node_jwks | grep -qx 'HTTP 200'"

echo "== 5. rollback: switch :8081 back to RSA"
"${SW[@]}" rsa > "$W/switch-rsa.log" 2>&1; rc=$?
sed 's/^/      /' "$W/switch-rsa.log"
check "rollback OK without restart: :8081 RSA, route push 200, admin 200" \
	"[ $rc = 0 ] && [ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(started)\" = '$API_T1' ] && [ \"\$(push 5)\" = 200 ] && [ \"\$(adm)\" = 200 ] && health"

echo "== 6. forward again"
"${SW[@]}" mldsa > "$W/switch-mldsa-2.log" 2>&1; rc=$?
check "forward again without restart: :8081 ML-DSA-65, route push 200, admin 200" \
	"[ $rc = 0 ] && [ \"\$(served_alg)\" = mldsa65 ] && [ \"\$(started)\" = '$API_T1' ] && [ \"\$(push 6)\" = 200 ] && [ \"\$(adm)\" = 200 ]"

echo "== 7. end state of the leaf type: GATEWAY_TLS_LEAF_ALG=ML-DSA-65"
leaf_env ML-DSA-65
check "route push 200 and admin 200 with the leaf check on all three channels" "[ \"\$(push 7)\" = 200 ] && [ \"\$(adm)\" = 200 ]"
"${SW[@]}" rsa > "$W/switch-rsa-refused.log" 2>&1; rc=$?
sed 's/^/      /' "$W/switch-rsa-refused.log"
check "switch to RSA refused while GATEWAY_TLS_LEAF_ALG is set; :8081 unchanged" "[ $rc != 0 ] && grep -q GATEWAY_TLS_LEAF_ALG '$W/switch-rsa-refused.log' && [ \"\$(served_alg)\" = mldsa65 ]"

echo "== 8. drop-rsa: the trust file holds the ML-DSA-65 CA only"
I8=$(stat -c %i "$P/internal-tls-ca.crt")
"${SW[@]}" drop-rsa > "$W/drop-rsa.log" 2>&1; rc=$?
sed 's/^/      /' "$W/drop-rsa.log"
api_restart; state
check "drop-rsa in place: 1 CA, ML-DSA-65; after the restart route push 200, admin 200, healthcheck OK" \
	"[ $rc = 0 ] && [ \"\$(stat -c %i $P/internal-tls-ca.crt)\" = '$I8' ] && [ \"\$(ncerts $P/internal-tls-ca.crt)\" = 1 ] && [ \"\$(alg $P/internal-tls-ca.crt)\" = ML-DSA-65 ] && [ \"\$(push 8)\" = 200 ] && [ \"\$(adm)\" = 200 ] && health"
leaf_env ""
"${SW[@]}" rsa > "$W/switch-rsa-after-drop.log" 2>&1; rc=$?
check "after drop-rsa an RSA :8081 can no longer be switched to (the RSA CA is not trusted)" "[ $rc != 0 ] && grep -q 'no longer holds the RSA CA' '$W/switch-rsa-after-drop.log' && [ \"\$(served_alg)\" = mldsa65 ]"
leaf_env ML-DSA-65

echo "== 9. setup-pki.sh again: nothing to do"
sha9=$(sha256sum "$P/internal-tls-ca.crt" "$S/internal-tls.crt" "$S/internal-tls-mldsa.crt" | sha256sum)
"${PKI[@]}" > "$W/rerun.log" 2>&1; rc=$?
check "re-run: exit 0, 'current (skip)', files unchanged" "[ $rc = 0 ] && grep -q 'current (skip)' '$W/rerun.log' && [ \"\$(sha256sum $P/internal-tls-ca.crt $S/internal-tls.crt $S/internal-tls-mldsa.crt | sha256sum)\" = '$sha9' ]"

curl -sS "${RES[@]}" --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" --max-time 20 -X DELETE \
	-H X-PQC-CSRF:1 -H "Origin: https://127.0.0.1" -o /dev/null "$ADMIN/admin/policy/routes/$CN" 2>/dev/null || true
check "no private key in the work directory" "! grep -rlq 'PRIVATE KEY' '$W'"
echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
