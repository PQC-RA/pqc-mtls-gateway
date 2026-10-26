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
#   2 post-quantum client, ML-DSA-65 client certificate -> pq
#   3 client with post-quantum key exchange, classical signatures only -> pq-kex, ECDSA server cert
#   4 classical client, TLS 1.3 (X25519, ECDSA)          -> classical, served
#   5 classical client, TLS 1.2                          -> classical, served
#   6 classical client certificate from a customer CA   -> accepted, classical
#   7 the same client under pq-required (policy.json)    -> 403 pq_required
#   8 the inventory on the control-plane listener lists 1 to 7 with their classes
#   9 the strict listener in the same container still refuses a classical client
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
cleanup(){ docker rm -f $NAME >/dev/null 2>&1; find "$W" -name '*.key' -exec shred -u {} + 2>/dev/null; }
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
s = s.replace("proxy_pass http://backend.example:8080;", 'content_by_lua_block { ngx.say("class=", ngx.var.pqc_pq_class) }')
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
	printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' $H | timeout 10 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
		-connect 127.0.0.1:$P_MIG -servername $H -ign_eof "$@" > "$W/$l.out" 2>&1
	echo "$(grep -m1 -oE 'Peer signature type: [^ ]+' "$W/$l.out" | cut -d' ' -f4) | $(grep -m1 -oE 'class=[a-z-]+|pq_required' "$W/$l.out" || grep -m1 -oE 'HTTP/1.1 [0-9]+' "$W/$l.out")"
}
start || { echo "gateway did not start"; exit 1; }
echo "throwaway gateway $NAME up (migration :$P_MIG, strict :$P_STRICT, control :$P_CTL)"
PQ=(-groups X25519MLKEM768 -CAfile "$PKI_DIR/ca-chain.crt")
CL=(-groups X25519:P-256 -sigalgs ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256 -CAfile "$W/cl/ca.crt")

r=$(req c1 "${PQ[@]}"); echo "   1: $r"; check "1 post-quantum client: ML-DSA-65 server certificate, class pq" "echo '$r' | grep -q '^mldsa65 | class=pq\$'"
r=$(req c2 "${PQ[@]}" -cert "$ADMIN_CRT" -key "$ADMIN_KEY"); echo "   2: $r"; check "2 post-quantum client with an ML-DSA-65 certificate: class pq" "echo '$r' | grep -q '^mldsa65 | class=pq\$'"
r=$(req c3 -groups X25519MLKEM768 -sigalgs ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256 -CAfile "$W/cl/ca.crt"); echo "   3: $r"; check "3 post-quantum key exchange, classical signatures: ECDSA server certificate, class pq-kex" "echo '$r' | grep -q '^ecdsa_secp256r1_sha256 | class=pq-kex\$'"
r=$(req c4 "${CL[@]}"); echo "   4: $r"; check "4 classical client, TLS 1.3: served, class classical" "echo '$r' | grep -q '^ecdsa_secp256r1_sha256 | class=classical\$'"
r=$(req c5 -tls1_2 -CAfile "$W/cl/ca.crt"); echo "   5: $r"; check "5 classical client, TLS 1.2: served, class classical" "echo '$r' | grep -q 'class=classical\$'"
r=$(req c6 "${CL[@]}" -cert "$W/cl/client.crt" -key "$W/cl/client.key"); echo "   6: $r"; check "6 classical client certificate from the customer CA: accepted, class classical" "echo '$r' | grep -q 'class=classical\$' && grep -q 'CN=classical-client' <(docker exec $NAME sh -c 'tail -1 /var/log/nginx/pqc-migration-access.log')"

printf '{\n  "default": "observe",\n  "sha256:%s": "pq-required"\n}\n' "$CL_FPR" > "$W/mig/policy.json"
docker exec $NAME nginx -s reload; sleep 2
r=$(req c7 "${CL[@]}" -cert "$W/cl/client.crt" -key "$W/cl/client.key"); echo "   7: $r"; check "7 the same client under pq-required: 403 pq_required" "echo '$r' | grep -q 'pq_required' && grep -q 'HTTP/1.1 403' '$W/c7.out'"
r=$(req c7b "${CL[@]}"); echo "   7b: $r"; check "7 a classical client WITHOUT that certificate is still only observed" "echo '$r' | grep -q 'class=classical\$'"

curl -s --cacert "$PKI_DIR/internal-tls-ca.crt" --resolve gateway:$P_CTL:127.0.0.1 https://gateway:$P_CTL/migration/inventory -o "$W/inventory.json" || \
	curl -sk https://127.0.0.1:$P_CTL/migration/inventory -o "$W/inventory.json"
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
check "8 the inventory lists pq, pq-kex and classical, and the customer-CA client as classical (EC key)" "grep -q 'classes classical pq pq-kex' '$W/inventory-check.txt' && grep -q 'classical_client classical EC' '$W/inventory-check.txt'"

printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' $H | timeout 10 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
	-connect 127.0.0.1:$P_STRICT -servername $H -ign_eof "${CL[@]}" -cert "$W/cl/client.crt" -key "$W/cl/client.key" > "$W/c9.out" 2>&1
check "9 the strict listener in the same gateway refuses the classical client (no 200/404)" "! grep -qE 'HTTP/1.1 (200|404)' '$W/c9.out'"
docker exec $NAME sh -c 'cat /var/log/nginx/pqc-migration-access.log' > "$W/migration-access.log" 2>/dev/null
echo "== result: $pass passed, $fail failed"
exit $fail
