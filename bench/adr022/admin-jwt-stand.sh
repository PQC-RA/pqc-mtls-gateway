#!/usr/bin/env bash
# admin-jwt-stand.sh: ADR-022 on the ISOLATED stand. The admin token admin-v2
# (ML-DSA-65) end to end through the gateway, the kid switch in both
# directions, the dual window, the end state with admin-v1 gone, replay and
# binding of a token captured on the gateway-to-API hop, and the :8081 TLS
# settings (ML-DSA-65 leaf, TLS 1.3, X25519MLKEM768 only).
#
#   source STAND_DIR/stand.env; admin-jwt-stand.sh WORKDIR
#
# Changes the stand's env (ADMIN_JWT_KID, ADMIN_JWKS_KIDS, JWT_EXPECTED_KID,
# ADMIN_V2_PUB_SHA256, GATEWAY_TLS_LEAF_ALG) and recreates gateway and
# management-api; it ends in the ADR-022 end state and restores nothing else.
# Never touches anything outside the stand (stand-env.sh guards).
set -uo pipefail
W=${1:?workdir}; mkdir -p "$W"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../item4/stand-env.sh"
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
guard(){ stand_guard "$W"; }
waitup(){ local c ok; for _ in $(seq 1 90); do ok=1
	for c in "$CUST" "$GW"; do [ "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)" = healthy ] || ok=0; done
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' "http://127.0.0.1:$STAND_API_PORT/api/admin/health")" != 000 ] || ok=0
	[ $ok = 1 ] && return 0; sleep 2; done; return 1; }
ENVF=$STAND_DIR/env
PIN=$(sed -n 's/^ADMIN_V2_PUB_SHA256=//p' "$ENVF")
[ ${#PIN} = 64 ] || { echo "ABORT: no ADMIN_V2_PUB_SHA256 in $ENVF"; exit 90; }
guard

set_env(){ # set_env KEY=VALUE ...
	local kv k
	for kv in "$@"; do k=${kv%%=*}
		if grep -q "^$k=" "$ENVF"; then sed -i "s|^$k=.*|$kv|" "$ENVF"; else echo "$kv" >> "$ENVF"; fi
	done; }
apply(){ # apply LABEL KEY=VALUE ...: set env, recreate gateway + management-api, wait
	local label=$1; shift; set_env "$@"
	echo "== $label: $(grep -E '^(ADMIN_JWT_KID|ADMIN_JWKS_KIDS|JWT_EXPECTED_KID|GATEWAY_TLS_LEAF_ALG)=' "$ENVF" | tr '\n' ' ')"
	# Both, always: nginx resolves management-api once at start.
	"$STAND_COMPOSE" up -d --no-deps --force-recreate management-api gateway > "$W/up-${label// /_}.out" 2>&1
	waitup || { echo "ABORT: stand not healthy after '$label'"; exit 91; }
	sleep 2; }
adm(){ # adm METHOD PATH [OUTFILE] -> http code (admin identity, through the gateway)
	local out=${3:-/dev/null} extra=()
	[ "$1" != GET ] && extra=(-H X-PQC-CSRF:1 -H "Origin: https://127.0.0.1")
	curl -sS "${RES[@]}" --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" "${extra[@]}" --max-time 15 \
		-X "$1" -o "$out" -w '%{http_code}' "$ADMIN$2" 2>/dev/null || echo 000; }
jwks(){ # the JWKS as management-api fetches it: Node 22, https://gateway:8081, NODE_EXTRA_CA_CERTS
	docker exec "$API" node -e '
		require("https").get(process.env.GATEWAY_JWKS_URI, r => { let b = ""; r.on("data", c => b += c); r.on("end", () => console.log(b)); })
			.on("error", e => { console.log("ERR " + e.message); });'; }
jwks_kids(){ jwks | python3 -I -c 'import json,sys; print(" ".join(sorted(k["kid"] for k in json.load(sys.stdin)["keys"])))' 2>/dev/null; }
api_kid_log(){ docker logs --since "$1" "$API" 2>&1 | grep -o 'Admin token verified & authorized: kid=[a-z0-9-]*' | tail -1 | sed 's/.*kid=//'; }

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); TS=$(date -u +%H%M%S)
echo "stand $STAND_PROJECT, gateway $(docker inspect -f '{{.Config.Image}}' "$GW"), management-api $(docker inspect -f '{{.Config.Image}}' "$API"), started $T0"

# ── 1. :8081 ─────────────────────────────────────────────────────────────────
echo "== 1. :8081 control plane"
docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -servername gateway -CAfile /etc/pki/pqc-ca/internal-tls-ca.crt -verify_return_error -brief 2>&1' > "$W/8081-s_client.txt"
cat "$W/8081-s_client.txt" | sed 's/^/      /'
check ":8081 TLS 1.3, X25519MLKEM768, server signature ML-DSA-65, verified against the pinned internal CA" \
	"grep -q 'Protocol version: TLSv1.3' '$W/8081-s_client.txt' && grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' '$W/8081-s_client.txt' && grep -q 'Signature type: mldsa65' '$W/8081-s_client.txt' && grep -q 'Verification: OK' '$W/8081-s_client.txt'"
docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -tls1_2 2>&1' > "$W/8081-tls12.txt"
check ":8081 refuses TLS 1.2 (alert protocol version)" "grep -q 'alert protocol version' '$W/8081-tls12.txt' && grep -q 'no peer certificate available' '$W/8081-tls12.txt'"
docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -groups X25519:P-256 2>&1' > "$W/8081-classical-group.txt"
check ":8081 refuses a classical-only key exchange (X25519, P-256: handshake failure)" "grep -q 'alert handshake failure' '$W/8081-classical-group.txt' && grep -q 'no peer certificate available' '$W/8081-classical-group.txt'"
$O x509 -in "$STAND_DIR/ssl/internal-tls.crt" -noout -text > "$W/8081-leaf.txt"
$O x509 -in "$STAND_DIR/pki/internal-tls-ca.crt" -noout -text > "$W/8081-ca.txt"
check ":8081 leaf and internal CA are ML-DSA-65; leaf keyUsage digitalSignature only" \
	"grep -q 'Public Key Algorithm: ML-DSA-65' '$W/8081-leaf.txt' && grep -q 'Public Key Algorithm: ML-DSA-65' '$W/8081-ca.txt' && grep -A1 'Key Usage: critical' '$W/8081-leaf.txt' | tail -1 | grep -qx ' *Digital Signature'"
docker exec "$GW" cat /etc/nginx/nginx.conf | python3 -I -c '
import re, sys
c = sys.stdin.read(); i = c.index("listen 8081"); j = c.index("location", i)
blk = c[i:j]
print("certificates", len(re.findall(r"^\s*ssl_certificate\s", blk, re.M)), "protocols", re.search(r"ssl_protocols ([^;]*);", blk).group(1), "groups", re.search(r"Groups ([^;]*);", blk).group(1))' > "$W/8081-conf.txt"
sed 's/^/      /' "$W/8081-conf.txt"
check "nginx.conf :8081: one certificate (no RSA fallback), TLSv1.3, Groups X25519MLKEM768" "grep -qx 'certificates 1 protocols TLSv1.3 groups X25519MLKEM768' '$W/8081-conf.txt'"

# ── 2. end state ──────────────────────────────────────────────────────────────
apply "end state" ADMIN_JWT_KID=admin-v2 ADMIN_JWKS_KIDS=admin-v2 JWT_EXPECTED_KID=admin-v2 GATEWAY_TLS_LEAF_ALG=ML-DSA-65
guard
jwks > "$W/jwks-end.json"
python3 -I - "$W/jwks-end.json" "$PIN" > "$W/jwks-end-check.txt" <<'PY'
import base64, hashlib, json, sys
d = json.load(open(sys.argv[1])); ks = {k["kid"]: k for k in d["keys"]}
a = ks.get("admin-v2", {}); pub = base64.urlsafe_b64decode(a.get("pub", "") + "=" * (-len(a.get("pub", "")) % 4))
print("kids", " ".join(sorted(ks)))
print("admin-v2", a.get("kty"), a.get("alg"), len(pub), "pin_ok" if hashlib.sha256(pub).hexdigest() == sys.argv[2] else "pin_BAD")
PY
cat "$W/jwks-end-check.txt" | sed 's/^/      /'
check "JWKS (fetched by Node 22 over the ML-DSA-65 :8081): backend-v1, lookup-v1, admin-v2 only" "grep -qx 'kids admin-v2 backend-v1 lookup-v1' '$W/jwks-end-check.txt'"
check "JWKS admin-v2 = AKP, ML-DSA-65, 1952-byte pub matching the API pin" "grep -qx 'admin-v2 AKP ML-DSA-65 1952 pin_ok' '$W/jwks-end-check.txt'"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
c=$(adm GET /admin/whoami "$W/whoami-end.json")
check "admin call GET /admin/whoami: 200, verified as kid admin-v2" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v2 ]"
c=$(adm GET "/admin/certs?limit=1" "$W/list-end.json")
check "admin call with a query string: 200 (htu is the path)" "[ '$c' = 200 ]"
c=$(adm POST "/admin/certs/enrollment-tokens?cn=adr022-$TS&ttl=60" "$W/token-end.json")
check "mutating admin call POST /admin/certs/enrollment-tokens: 201 (htm POST)" "[ '$c' = 201 ]"
c=$(adm GET "/admin/certs/a%20b")
check "an admin path nginx would re-escape is refused at the gateway (400), not minted" "[ '$c' = 400 ]"

# ── 3. a token captured on the gateway -> management-api hop (plain HTTP) ─────
echo "== 3. captured token: replay, other path, expiry"
NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$API" | tr ' ' '\n' | grep -m1 'mgmt')
IF=br-$(docker network inspect -f '{{.Id}}' "$NET" | cut -c1-12)
timeout 20 tcpdump -i "$IF" -s 0 -U -w "$W/hop.pcap" 'tcp dst port 3000' 2>/dev/null &
TCPD=$!; sleep 2
c=$(adm GET /admin/whoami); sleep 1; kill $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
# Reassemble the TCP payload towards :3000 (the header is ~5 KB, several segments).
TOK=$(python3 -I - "$W/hop.pcap" <<'PY'
import re, struct, sys
d = open(sys.argv[1], "rb").read(); off = 24; flows = {}
while off + 16 <= len(d):
    _, _, incl, _ = struct.unpack("<IIII", d[off:off + 16]); pkt = d[off + 16:off + 16 + incl]; off += 16 + incl
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00": continue
    ip = pkt[14:]; ihl = (ip[0] & 15) * 4
    if ip[9] != 6: continue
    tcp = ip[ihl:]; sport, dport, seq = struct.unpack(">HHI", tcp[:8]); doff = (tcp[12] >> 4) * 4
    pl = tcp[doff:struct.unpack(">H", ip[2:4])[0] - ihl]
    if pl: flows.setdefault((ip[12:16], sport), {})[seq] = pl
for segs in flows.values():
    data = b"".join(segs[k] for k in sorted(segs))
    m = re.search(rb"Authorization: Bearer ([A-Za-z0-9._-]+)", data, re.I)
    if m: print(m.group(1).decode()); break
PY
)
echo "      captured a token of ${#TOK} characters on $IF"
python3 -I - "$TOK" > "$W/captured-token.txt" <<'PY'
import base64, json, sys
t = sys.argv[1]; h, p, s = t.split(".")
d = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
print("header", d(h).decode()); pl = json.loads(d(p))
print("claims", " ".join(sorted(pl))); print("htm", pl.get("htm"), "htu", pl.get("htu"), "lifetime", pl["exp"] - pl["iat"])
print("sig_bytes", len(d(s)), "token_chars", len(t))
PY
sed 's/^/      /' "$W/captured-token.txt"
check "captured token: header exactly {\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\",\"kid\":\"admin-v2\"}, 3309-byte signature" \
	"grep -qxF 'header {\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\",\"kid\":\"admin-v2\"}' '$W/captured-token.txt' && grep -q '^sig_bytes 3309' '$W/captured-token.txt'"
check "captured token: jti, htm GET, htu /api/admin/whoami, 60 s" "grep -q 'jti' '$W/captured-token.txt' && grep -qx 'htm GET htu /api/admin/whoami lifetime 60' '$W/captured-token.txt'"
API_URL=http://127.0.0.1:$STAND_API_PORT
r1=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$API_URL/api/admin/whoami")
check "replay of the captured token to management-api inside its 60 s: 401" "[ '$r1' = 401 ]"
r2=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$API_URL/api/admin/certs")
check "the captured token on another path: 401" "[ '$r2' = 401 ]"
r3=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" -H X-PQC-CSRF:1 "$API_URL/api/admin/whoami")
check "the captured token with another method: 401 (or 404 if no POST route)" "[ '$r3' = 401 ] || [ '$r3' = 404 ]"
docker logs --since "$T0" "$API" 2>&1 | grep -oE 'Admin token refused: [a-z_]+' | sort | uniq -c > "$W/refusals.txt"
sed 's/^/      /' "$W/refusals.txt"
check "refusals logged as replay and htu" "grep -q 'refused: replay' '$W/refusals.txt' && grep -q 'refused: htu' '$W/refusals.txt'"

# ── 4. end state refuses admin-v1, and the order matters ──────────────────────
apply "gateway admin-v1 against an admin-v2-only API" ADMIN_JWT_KID=admin-v1 ADMIN_JWKS_KIDS=admin-v1,admin-v2 JWT_EXPECTED_KID=admin-v2
c=$(adm GET /admin/whoami)
check "RS256 admin-v1 token refused by the end-state API: 401" "[ '$c' = 401 ]"
apply "gateway admin-v2 against an admin-v1-only API (wrong order)" ADMIN_JWT_KID=admin-v2 ADMIN_JWKS_KIDS= JWT_EXPECTED_KID=admin-v1
c=$(adm GET /admin/whoami)
check "admin-v2 token refused by an API that does not accept it yet: 401 (the API ships first)" "[ '$c' = 401 ]"

# ── 5. the dual window and the kid switch in both directions ─────────────────
apply "dual window, gateway admin-v1" ADMIN_JWT_KID=admin-v1 ADMIN_JWKS_KIDS= JWT_EXPECTED_KID=admin-v1,admin-v2 GATEWAY_TLS_LEAF_ALG=
check "JWKS in the dual window: admin-v1 and admin-v2 beside backend-v1, lookup-v1" "[ \"\$(jwks_kids)\" = 'admin-v1 admin-v2 backend-v1 lookup-v1' ]"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ); c=$(adm GET /admin/whoami)
check "dual window, gateway on admin-v1: 200 as admin-v1" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v1 ]"
apply "switch admin-v1 -> admin-v2" ADMIN_JWT_KID=admin-v2
since=$(date -u +%Y-%m-%dT%H:%M:%SZ); c=$(adm GET /admin/whoami)
check "switch to admin-v2 (gateway config only): 200 as admin-v2" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v2 ]"
apply "switch admin-v2 -> admin-v1 (rollback)" ADMIN_JWT_KID=admin-v1
since=$(date -u +%Y-%m-%dT%H:%M:%SZ); c=$(adm GET /admin/whoami)
check "switch back to admin-v1 (rollback by gateway config): 200 as admin-v1" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v1 ]"
apply "switch admin-v1 -> admin-v2 again" ADMIN_JWT_KID=admin-v2
since=$(date -u +%Y-%m-%dT%H:%M:%SZ); c=$(adm GET /admin/whoami)
check "switch to admin-v2 again: 200 as admin-v2" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v2 ]"

# ── 6. LookupTokenGuard's jwks-rsa with the AKP entry in the real JWKS ────────
docker exec -w /usr/src/app "$API" node -e '
	const c = require("jwks-rsa")({ jwksUri: process.env.GATEWAY_JWKS_URI });
	Promise.all(["lookup-v1", "backend-v1"].map(k => c.getSigningKey(k).then(x => k + ":" + x.getPublicKey().length)))
		.then(r => console.log("OK " + r.join(" "))).catch(e => console.log("FAIL " + e.message));' > "$W/jwks-rsa.txt" 2>&1
sed 's/^/      /' "$W/jwks-rsa.txt"
check "jwks-rsa (LookupTokenGuard) reads lookup-v1 from the live JWKS that also holds the AKP entry" "grep -q '^OK lookup-v1:' '$W/jwks-rsa.txt'"

# ── 7. the pin ────────────────────────────────────────────────────────────────
apply "wrong pin" JWT_EXPECTED_KID=admin-v2 ADMIN_JWKS_KIDS=admin-v2 "ADMIN_V2_PUB_SHA256=$(printf '%064d' 0)"
c=$(adm GET /admin/whoami)
docker logs --since 30s "$API" 2>&1 | grep -o 'pub does not match the pinned SHA-256' | head -1 > "$W/pin.txt"
check "a JWKS admin-v2 key that does not match the API's pin: 401, logged" "[ '$c' = 401 ] && grep -q pinned '$W/pin.txt'"

# ── 8. back to the end state ──────────────────────────────────────────────────
apply "end state (final)" ADMIN_JWT_KID=admin-v2 ADMIN_JWKS_KIDS=admin-v2 JWT_EXPECTED_KID=admin-v2 ADMIN_V2_PUB_SHA256=$PIN GATEWAY_TLS_LEAF_ALG=ML-DSA-65
since=$(date -u +%Y-%m-%dT%H:%M:%SZ); c=$(adm GET /admin/whoami)
check "end state restored: 200 as admin-v2, JWKS without admin-v1" "[ '$c' = 200 ] && [ \"\$(api_kid_log $since)\" = admin-v2 ] && [ \"\$(jwks_kids)\" = 'admin-v2 backend-v1 lookup-v1' ]"
sleep 61
r4=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$API_URL/api/admin/whoami")
check "the captured token after its 60 s (and after an API restart that emptied the jti cache): 401" "[ '$r4' = 401 ]"

echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
