#!/usr/bin/env bash
# internal-tls-reissue-stand.sh: the :8081 move of ADR-022 rehearsed on the
# ISOLATED stand from the state live is in today (RSA-2048 internal CA and
# leaf), with running containers, then rolled back and forward again.
#
#   source STAND_DIR/stand.env; internal-tls-reissue-stand.sh WORKDIR [OLD_COMMIT]
#
#   0. the RSA internal CA and leaf of OLD_COMMIT's setup-pki.sh (default: the
#      last commit before ADR-022) written IN PLACE over the stand's; gateway
#      reloaded, management-api restarted; admin works over RSA :8081
#   1. this tree's setup-pki.sh on the stand PKI: reissued as ML-DSA-65, in
#      place (same inodes, so the single-file mount in management-api sees it
#      without a recreate), RSA kept as *-rsa.*; reload + restart; admin works,
#      also with GATEWAY_TLS_LEAF_ALG=ML-DSA-65; a second run changes nothing
#   2. rollback: the *-rsa.* files written in place over the active ones,
#      reload + restart, GATEWAY_TLS_LEAF_ALG unset; admin works over RSA
#   3. forward again: setup-pki.sh reissues ML-DSA-65; admin works
# Needs the stand in the dual window or the end state (admin-v2 accepted).
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
FILES=("$P/internal-tls-ca.crt" "$P/internal-tls/internal-tls-ca.key" "$S/internal-tls.crt" "$S/internal-tls.key")
adm(){ curl -sS "${RES[@]}" --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" --max-time 15 -o /dev/null -w '%{http_code}' "$ADMIN/admin/whoami" 2>/dev/null || echo 000; }
alg(){ $O x509 -in "$1" -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -1; }
api_ca_alg(){ docker exec "$API" cat /etc/pki/internal-tls-ca.crt | $O x509 -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -1; }
served_alg(){ docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -servername gateway -brief 2>&1' | sed -n 's/^Signature type: //p'; }
inodes(){ stat -c %i "${FILES[@]}" | tr '\n' ' '; }
leaf_env(){ # leaf_env VALUE: set GATEWAY_TLS_LEAF_ALG and recreate management-api (and gateway: nginx resolves it once)
	if grep -q '^GATEWAY_TLS_LEAF_ALG=' "$ENVF"; then sed -i "s|^GATEWAY_TLS_LEAF_ALG=.*|GATEWAY_TLS_LEAF_ALG=$1|" "$ENVF"; else echo "GATEWAY_TLS_LEAF_ALG=$1" >> "$ENVF"; fi
	"$STAND_COMPOSE" up -d --no-deps --force-recreate management-api gateway > "$W/up-leaf-$1.out" 2>&1; waitup; sleep 2; }
switch(){ # reload the gateway (re-reads the certificate), restart management-api (re-reads NODE_EXTRA_CA_CERTS)
	docker exec "$GW" nginx -s reload >/dev/null 2>&1; sleep 2
	docker restart "$API" >/dev/null; waitup; sleep 2; }

leaf_env ""
INO0=$(inodes)
echo "== 0. the RSA internal TLS of $OLD (live today), written in place"
mkdir -p "$W/old"; git -C "$TREE" show "$OLD:scripts/setup-pki.sh" > "$W/old/setup-pki.sh" 2>/dev/null \
	|| { [ -f "$STAND_DIR/rollback-tree/scripts/setup-pki.sh" ] && cp "$STAND_DIR/rollback-tree/scripts/setup-pki.sh" "$W/old/setup-pki.sh"; }
[ -s "$W/old/setup-pki.sh" ] || { echo "ABORT: no setup-pki.sh of $OLD"; exit 90; }
mkdir -p "$W/old/repo/scripts" "$W/old/repo/pki"; cp "$W/old/setup-pki.sh" "$W/old/repo/scripts/"; cp -r "$TREE/pki/templates" "$W/old/repo/pki/"; cp "$TREE/scripts/gen-enroll-classical-cert.sh" "$W/old/repo/scripts/"
( cd "$W/old/repo" && PKI_DIR="$W/old/pki" SSL_DIR="$W/old/ssl" OPENSSL_BIN=$O SKIP_APP_PERMS=1 SERVER_IP=127.0.0.1 bash scripts/setup-pki.sh > "$W/old/setup.log" 2>&1 )
cat "$W/old/pki/internal-tls-ca.crt" > "$P/internal-tls-ca.crt"; cat "$W/old/pki/internal-tls/internal-tls-ca.key" > "$P/internal-tls/internal-tls-ca.key"
cat "$W/old/ssl/internal-tls.crt" > "$S/internal-tls.crt"; cat "$W/old/ssl/internal-tls.key" > "$S/internal-tls.key"
rm -f "$P/internal-tls-ca-rsa.crt" "$P/internal-tls/internal-tls-ca-rsa.key" "$S/internal-tls-rsa.crt" "$S/internal-tls-rsa.key"
rm -rf "$W/old/pki" "$W/old/ssl"
switch
echo "      CA $(alg "$P/internal-tls-ca.crt"), served $(served_alg), API trusts $(api_ca_alg), admin HTTP $(adm)"
check "starting point: :8081 serves RSA, the API trusts the RSA CA, admin works" "[ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(api_ca_alg)\" = rsaEncryption ] && [ \"\$(adm)\" = 200 ]"

echo "== 1. setup-pki.sh reissues as ML-DSA-65, in place"
PKI_DIR=$P SSL_DIR=$S OPENSSL_BIN=$O SKIP_APP_PERMS=1 bash "$TREE/scripts/setup-pki.sh" > "$W/reissue.log" 2>&1; rc=$?
grep -E 'kept|internal CA|Internal|ML-DSA' "$W/reissue.log" | sed 's/^/      /'
check "setup-pki.sh exit 0, inodes unchanged ($INO0)" "[ $rc = 0 ] && [ \"\$(inodes)\" = '$INO0' ]"
check "CA and leaf ML-DSA-65; RSA kept as internal-tls-ca-rsa.crt and internal-tls-rsa.crt" "[ \"\$(alg $P/internal-tls-ca.crt)\" = ML-DSA-65 ] && [ \"\$(alg $S/internal-tls.crt)\" = ML-DSA-65 ] && [ \"\$(alg $P/internal-tls-ca-rsa.crt)\" = rsaEncryption ] && [ \"\$(alg $S/internal-tls-rsa.crt)\" = rsaEncryption ]"
check "the running management-api sees the new CA through its single-file mount, before any restart" "[ \"\$(api_ca_alg)\" = ML-DSA-65 ]"
switch
echo "      served $(served_alg), admin HTTP $(adm)"
check "after reload + API restart: :8081 serves ML-DSA-65, admin works" "[ \"\$(served_alg)\" = mldsa65 ] && [ \"\$(adm)\" = 200 ]"
leaf_env ML-DSA-65
check "with GATEWAY_TLS_LEAF_ALG=ML-DSA-65: admin works" "[ \"\$(adm)\" = 200 ]"
sha_before=$(sha256sum "${FILES[@]}" | sha256sum)
PKI_DIR=$P SSL_DIR=$S OPENSSL_BIN=$O SKIP_APP_PERMS=1 bash "$TREE/scripts/setup-pki.sh" > "$W/reissue-2.log" 2>&1
check "a second run changes nothing (idempotent)" "grep -q 'current (skip)' '$W/reissue-2.log' && [ \"\$(sha256sum ${FILES[*]} | sha256sum)\" = '$sha_before' ]"

echo "== 2. rollback to RSA (files on disk, in place)"
leaf_env ""
cat "$P/internal-tls-ca-rsa.crt" > "$P/internal-tls-ca.crt"; cat "$P/internal-tls/internal-tls-ca-rsa.key" > "$P/internal-tls/internal-tls-ca.key"
cat "$S/internal-tls-rsa.crt" > "$S/internal-tls.crt"; cat "$S/internal-tls-rsa.key" > "$S/internal-tls.key"
switch
echo "      served $(served_alg), admin HTTP $(adm)"
check "rollback: :8081 serves RSA again, admin works" "[ \"\$(served_alg)\" = rsa_pss_rsae_sha256 ] && [ \"\$(adm)\" = 200 ]"

echo "== 3. forward again"
PKI_DIR=$P SSL_DIR=$S OPENSSL_BIN=$O SKIP_APP_PERMS=1 bash "$TREE/scripts/setup-pki.sh" > "$W/reissue-3.log" 2>&1
switch; leaf_env ML-DSA-65
echo "      served $(served_alg), admin HTTP $(adm)"
check "forward again: ML-DSA-65 served, admin works with the leaf check; rollback copies untouched" "[ \"\$(served_alg)\" = mldsa65 ] && [ \"\$(adm)\" = 200 ] && [ \"\$(alg $S/internal-tls-rsa.crt)\" = rsaEncryption ]"
check "no private key in the work directory" "! grep -rlq 'PRIVATE KEY' '$W'"
echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
