#!/usr/bin/env bash
# migration-listener-test.sh: the migration listener (config/nginx/migration/) in a
# THROWAWAY gateway container, against throwaway classical and post-quantum
# identities. It never touches a running deployment: its own container, its own
# loopback ports, read-only mounts of an existing test PKI.
#
# Needs: the gateway image (GW_IMAGE), a test PKI made by scripts/setup-pki.sh
# (PKI_DIR, SSL_DIR) with its admin identity (ADMIN_CRT/KEY, ML-DSA-65), the
# gateway secrets (SECRETS_DIR), Docker networks on which the names used by
# nginx.conf resolve (NETWORKS), OpenSSL 3.5+ at OSSL.
#
# Cases:
#   1 post-quantum client, no client certificate        -> class pq, ML-DSA-65 server certificate
#   2 post-quantum client, ML-DSA-65 client certificate -> pq, verified, ML-DSA-65 key logged
#   3 client with post-quantum key exchange, classical signatures only -> pq-kex, ECDSA server cert
#   4 classical client, TLS 1.3 (X25519, ECDSA)          -> classical, served
#   5 classical client, TLS 1.2                          -> classical, served
#   6 classical client certificate from a customer CA   -> accepted, classical
#   7 the same client under pq-required (policy.json)    -> 403 pq_required
#   8 the inventory (control-plane listener, HMAC) holds pq, pq-kex and classical
#     records and the customer-CA client as classical; unsigned, it answers 401
#   9 the strict listener in the same container refuses a classical client
#     certificate even over X25519MLKEM768, and serves the ML-DSA-65 one
#  R  a second connection with the first one's session is a full handshake
#  T  a client that sends only an X25519 key share is asked for X25519MLKEM768
#  X  a client-sent X-PQ-Class is replaced by the measured class
#  U  an unverified (self-signed) certificate is refused and creates no identity
#  10-14 with REAL_CLIENTS=1: real classical client stacks (real-clients.sh)
#
# Usage: migration-listener-test.sh WORKDIR
set -uo pipefail
W=${1:?workdir}; mkdir -p "$W"; [ -z "$(ls -A "$W")" ] || { echo "$W not empty"; exit 2; }
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
GW_IMAGE=${GW_IMAGE:-pqc-gateway:1.0.0}
PKI_DIR=${PKI_DIR:?PKI_DIR}; SSL_DIR=${SSL_DIR:?SSL_DIR}; SECRETS_DIR=${SECRETS_DIR:?SECRETS_DIR}
ADMIN_CRT=${ADMIN_CRT:?ADMIN_CRT}; ADMIN_KEY=${ADMIN_KEY:?ADMIN_KEY}
NETWORKS=${NETWORKS:?space-separated docker networks}
OSSL=${OSSL:-/opt/openssl/bin/openssl}; LIBDIR=${LIBDIR:-$(dirname "$(dirname "$OSSL")")/lib64}
P_MIG=${P_MIG:-29444}; P_STRICT=${P_STRICT:-29445}; P_CTL=${P_CTL:-29446}
H=pqc-gw.local; NAME=mig-test-$$
O(){ LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" "$@"; }
pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
cleanup(){ docker rm -f $NAME >/dev/null 2>&1; find "$W" \( -name '*.key' -o -name '*.p12' -o -name 'sess.pem' \) -exec shred -u {} + 2>/dev/null; }
trap cleanup EXIT

# ── throwaway classical PKI: a customer CA, its server and client certificates ──
mkdir -p "$W/mig" "$W/cl"
O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/cl/ca.key" -out "$W/cl/ca.crt" -subj "/O=Customer/CN=Customer Classical CA" -days 2 \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
for n in server client; do
	O req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/cl/$n.key" -out "$W/cl/$n.csr" -subj "/O=Customer/CN=classical-$n" 2>/dev/null
	ext=$([ $n = server ] && echo "subjectAltName=DNS:$H
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth" || echo "keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth")
	O x509 -req -in "$W/cl/$n.csr" -CA "$W/cl/ca.crt" -CAkey "$W/cl/ca.key" -CAcreateserial -days 2 -out "$W/cl/$n.crt" -extfile <(echo "$ext") 2>/dev/null
done
cp "$W/cl/server.crt" "$W/mig/classical-server.crt"; cp "$W/cl/server.key" "$W/mig/classical-server.key"
cat "$PKI_DIR/hybrid-ca-chain.crt" "$W/cl/ca.crt" > "$W/mig/client-ca-bundle.pem"
CL_FPR=$(O x509 -in "$W/cl/client.crt" -outform DER | sha256sum | cut -d' ' -f1)
printf '{\n  "default": "observe"\n}\n' > "$W/mig/policy.json"
# The test answers from the content phase (after the access phase that classifies)
# instead of proxying to a backend.
python3 -I - "$REPO/config/nginx/migration/listener.conf.example" "$W/mig/listener.conf" <<'PY2'
import sys
s = open(sys.argv[1]).read()
s = s.replace("proxy_pass http://backend.example:8080;", 'content_by_lua_block { ngx.say("class=", ngx.var.pqc_pq_class, " hdr=", ngx.req.get_headers()["x-pq-class"] or "") }')
s = s.replace("server_name api.example.com;", "server_name pqc-gw.local;")
open(sys.argv[2], "w").write(s)
PY2
chmod -R a+rX "$W/mig"; chmod 640 "$W/mig/classical-server.key"

start(){ # (re)start the throwaway gateway with the current $W/mig
	docker rm -f $NAME >/dev/null 2>&1
	local first; first=${NETWORKS%% *}
	docker create --name $NAME --network "$first" \
		-p 127.0.0.1:$P_MIG:9443 -p 127.0.0.1:$P_STRICT:443 -p 127.0.0.1:$P_CTL:8081 \
		-v "$REPO/config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$REPO/config/nginx/lua:/etc/nginx/lua:ro" \
		-v "$REPO/config/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro" -v "$W/mig:/etc/nginx/migration:ro" \
		-v "$PKI_DIR:/etc/pki/pqc-ca:ro" -v /etc/pki/pqc-empty:/etc/pki/pqc-ca/intermediate/private:ro -v /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro \
		-v "$SSL_DIR:/etc/ssl/pqc:ro" \
		-v "$SECRETS_DIR/gateway-signing.key:/run/secrets/gateway-signing-key:ro" -v "$SECRETS_DIR/gateway-signing-key-admin.key:/run/secrets/gateway-signing-key-admin:ro" \
		-v "$SECRETS_DIR/gateway-signing-key-lookup.key:/run/secrets/gateway-signing-key-lookup:ro" -v "$SECRETS_DIR/control-plane-hmac.key:/run/secrets/control-plane-hmac:ro" \
		-v "$SECRETS_DIR/enroll-hmac.key:/run/secrets/enroll-hmac:ro" \
		--entrypoint sh "$GW_IMAGE" -c 'mkdir -p /var/cache/nginx/client_temp /var/log/nginx /var/cache/pqc-gw/routes; exec nginx -g "daemon off;"' >/dev/null
	for n in ${NETWORKS#* }; do [ "$n" != "$first" ] && docker network connect "$n" $NAME; done
	docker start $NAME >/dev/null
	for i in $(seq 1 30); do echo | timeout 3 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client -connect 127.0.0.1:$P_MIG -servername $H >/dev/null 2>&1 && return 0; sleep 1; done
	docker logs $NAME 2>&1 | tail -5; return 1
}
req(){ # req LABEL CLIENT-ARGS... -> prints "<server sig> | <http body>"
	local l=$1; shift
	printf 'GET / HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n' $H "${XH:-}" | timeout 10 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
		-connect 127.0.0.1:$P_MIG -servername $H -ign_eof "$@" > "$W/$l.out" 2>&1
	echo "$(grep -m1 -oE 'Peer signature type: [^ ]+' "$W/$l.out" | cut -d' ' -f4) | $(grep -m1 -oE 'class=[a-z-]+|pq_required' "$W/$l.out" || grep -m1 -oE 'HTTP/1.1 [0-9]+' "$W/$l.out")"
}
start || { echo "gateway did not start"; exit 1; }
echo "throwaway gateway $NAME up (migration :$P_MIG, strict :$P_STRICT, control :$P_CTL)"
PQ=(-groups X25519MLKEM768 -CAfile "$PKI_DIR/ca-chain.crt")
CL=(-groups X25519:P-256 -sigalgs ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256 -CAfile "$W/cl/ca.crt")

r=$(req c1 "${PQ[@]}"); echo "   1: $r"; check "1 post-quantum client: ML-DSA-65 server certificate, class pq" "echo '$r' | grep -q '^mldsa65 | class=pq\$'"
lastlog(){ docker exec $NAME sh -c 'tail -1 /var/log/nginx/pqc-migration-access.log'; }
r=$(req c2 "${PQ[@]}" -cert "$ADMIN_CRT" -key "$ADMIN_KEY"); echo "   2: $r"; lastlog > "$W/c2.log"
check "2 post-quantum client with an ML-DSA-65 certificate: class pq, verified, ML-DSA-65 key" "echo '$r' | grep -q '^mldsa65 | class=pq\$' && grep -q '\"verify\":\"SUCCESS\"' '$W/c2.log' && grep -q '\"client_key\":\"ML-DSA-65\"' '$W/c2.log'"
r=$(req c3 -groups X25519MLKEM768 -sigalgs ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256 -CAfile "$W/cl/ca.crt"); echo "   3: $r"; check "3 post-quantum key exchange, classical signatures: ECDSA server certificate, class pq-kex" "echo '$r' | grep -q '^ecdsa_secp256r1_sha256 | class=pq-kex\$'"
r=$(req c4 "${CL[@]}"); echo "   4: $r"; check "4 classical client, TLS 1.3: served, class classical" "echo '$r' | grep -q '^ecdsa_secp256r1_sha256 | class=classical\$'"
r=$(req c5 -tls1_2 -CAfile "$W/cl/ca.crt"); echo "   5: $r"; check "5 classical client, TLS 1.2: served, class classical" "echo '$r' | grep -q 'class=classical\$'"
r=$(req c6 "${CL[@]}" -cert "$W/cl/client.crt" -key "$W/cl/client.key"); echo "   6: $r"; check "6 classical client certificate from the customer CA: accepted, class classical" "echo '$r' | grep -q 'class=classical\$' && grep -q 'CN=classical-client' <(docker exec $NAME sh -c 'tail -1 /var/log/nginx/pqc-migration-access.log')"

printf '{\n  "default": "observe",\n  "sha256:%s": "pq-required"\n}\n' "$CL_FPR" > "$W/mig/policy.json"
docker exec $NAME nginx -s reload; sleep 2
r=$(req c7 "${CL[@]}" -cert "$W/cl/client.crt" -key "$W/cl/client.key"); echo "   7: $r"; check "7 the same client under pq-required: 403 pq_required" "echo '$r' | grep -q 'pq_required' && grep -q 'HTTP/1.1 403' '$W/c7.out'"
r=$(req c7b "${CL[@]}"); echo "   7b: $r"; check "7 a classical client WITHOUT that certificate is still only observed" "echo '$r' | grep -q 'class=classical\$'"

# R: resumption is off on the migration listener
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' $H | O s_client -connect 127.0.0.1:$P_MIG -servername $H -ign_eof "${CL[@]}" -sess_out "$W/sess.pem" > "$W/r1.out" 2>&1
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' $H | O s_client -connect 127.0.0.1:$P_MIG -servername $H -ign_eof "${CL[@]}" -sess_in "$W/sess.pem" > "$W/r2.out" 2>&1
check "R a second connection offering the first one's session is a full handshake" "grep -q '^New, TLSv1.3' '$W/r2.out' && ! grep -q '^Reused' '$W/r2.out' && grep -q 'class=classical' '$W/r2.out'"
# T: X25519MLKEM768 is preferred over a key share the client happened to send; the
# HelloRetryRequest shows as a second ClientHello (s_client -msg names it ServerHello)
r=$(req ct -groups X25519:X25519MLKEM768 -CAfile "$PKI_DIR/ca-chain.crt" -msg); echo "   T: $r $(grep -m1 -oE 'Negotiated TLS1.3 group: [^ ]+' "$W/ct.out")"
hellos=$(grep -c '], ClientHello' "$W/ct.out")
check "T a client sending only an X25519 key share is asked for X25519MLKEM768 and gets pq" "grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' '$W/ct.out' && [ '$hellos' = 2 ] && echo '$r' | grep -q 'class=pq\$'"
# X: a client cannot name its own class
r=$(XH=$'X-PQ-Class: pq\r\n' req cx "${CL[@]}"); echo "   X: $(grep -m1 -oE 'class=[a-z-]+ hdr=[a-z-]*' "$W/cx.out")"
check "X a client-sent X-PQ-Class: pq from a classical client reaches the backend as classical" "grep -q 'class=classical hdr=classical' '$W/cx.out'"
# U: a self-signed certificate under any name is refused and is no identity
O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/cl/forged.key" -out "$W/cl/forged.crt" -subj "/O=Customer/CN=payments-prod" -days 1 2>/dev/null
FORGED_FPR=$(O x509 -in "$W/cl/forged.crt" -outform DER | sha256sum | cut -d' ' -f1)
r=$(req cu "${CL[@]}" -cert "$W/cl/forged.crt" -key "$W/cl/forged.key"); echo "   U: $r"

inv(){ # inv OUTFILE [unsigned] -> HTTP status of GET /migration/inventory
	local ts sig hdr=()
	if [ "${2:-}" != unsigned ]; then
		ts=$(date +%s)
		sig=$(python3 -I -c 'import hmac,hashlib,sys; k=open(sys.argv[1],"rb").read().rstrip(); print(hmac.new(k,(sys.argv[2]+"\nGET\n/migration/inventory\n").encode(),hashlib.sha256).hexdigest())' "$SECRETS_DIR/control-plane-hmac.key" "$ts")
		hdr=(-H "X-Timestamp: $ts" -H "X-Hub-Signature-256: sha256=$sig")
	fi
	curl -s -o "$1" -w '%{http_code}' --cacert "$PKI_DIR/internal-tls-ca.crt" --resolve gateway:$P_CTL:127.0.0.1 "${hdr[@]}" https://gateway:$P_CTL/migration/inventory 2>/dev/null || \
		curl -sk -o "$1" -w '%{http_code}' "${hdr[@]}" https://127.0.0.1:$P_CTL/migration/inventory
}
code_unsigned=$(inv "$W/inventory-unsigned.json" unsigned); code=$(inv "$W/inventory.json")
echo "   8: inventory HTTP $code, unsigned HTTP $code_unsigned"
check "U the self-signed certificate is refused (400) and appears nowhere in the inventory" "grep -q 'HTTP/1.1 400' '$W/cu.out' && ! grep -q '$FORGED_FPR' '$W/inventory.json' && ! grep -q 'payments-prod' '$W/inventory.json'"
python3 -I - "$W/inventory.json" "$CL_FPR" <<'PY' > "$W/inventory-check.txt"
import json, sys
d = json.load(open(sys.argv[1])); fpr = sys.argv[2]
seen = set()
for r in d["records"]:
    seen.update((r.get("classes") or {r["class"]: 1}).keys())
cl = [r for r in d["records"] if r["identity"] == "sha256:" + fpr]
print("classes", " ".join(sorted(seen)), "records", len(d["records"]), "classical_client", cl[0]["class"] if cl else "missing", cl[0].get("client_key", "") if cl else "")
PY
echo "   8: $(cat "$W/inventory-check.txt")"
check "8 the inventory (HMAC) holds pq, pq-kex and classical, the customer-CA client as classical (EC key); unsigned 401" "[ '$code' = 200 ] && [ '$code_unsigned' = 401 ] && grep -q 'classes classical pq pq-kex' '$W/inventory-check.txt' && grep -q 'classical_client classical EC' '$W/inventory-check.txt'"

strict(){ printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' $H | timeout 10 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
	-connect 127.0.0.1:$P_STRICT -servername $H -ign_eof -groups X25519MLKEM768 -CAfile "$PKI_DIR/ca-chain.crt" "$@"; }
strict -cert "$W/cl/client.crt" -key "$W/cl/client.key" > "$W/c9.out" 2>&1
strict -cert "$ADMIN_CRT" -key "$ADMIN_KEY" > "$W/c9-control.out" 2>&1
echo "   9: classical cert -> $(grep -m1 -oE 'HTTP/1.1 [0-9]+|alert [a-z ]+' "$W/c9.out" || echo 'no response'); ML-DSA-65 cert -> $(grep -m1 -oE 'HTTP/1.1 [0-9]+' "$W/c9-control.out")"
check "9 the strict listener refuses the classical client certificate over X25519MLKEM768 and answers the ML-DSA-65 one" "grep -qE 'HTTP/1.1 [0-9]{3}' '$W/c9-control.out' && ! grep -qE 'HTTP/1.1 (200|404)' '$W/c9.out'"
# 10 to 14: real classical stacks (CPython on OpenSSL 1.1.1 and 3.0, Java 21, curl on
# OpenSSL 3.5) in their own containers; see real-clients.sh for the images.
[ "${REAL_CLIENTS:-0}" = 1 ] && . "$REPO/bench/migration/real-clients.sh"
docker exec $NAME sh -c 'cat /var/log/nginx/pqc-migration-access.log' > "$W/migration-access.log" 2>/dev/null
echo "== result: $pass passed, $fail failed"
exit $fail
