#!/usr/bin/env bash
# edge-link-test.sh: an edge link (ADR-020) end to end in THROWAWAY containers:
#
#   scada (control net) -> central gateway :1502 (real nginx.conf + stream include)
#     ==PQ mTLS, both sides verified (wan net)==> edge box :8502 (config/edge/)
#     -> Modbus/TCP device :502 (cell net, internal: reachable only through the box)
#
# A throwaway ML-DSA-65 PKI is made for the link; nothing touches a running
# deployment. Needs what migration-listener-test.sh needs for the central
# gateway (GW_IMAGE, PKI_DIR, SSL_DIR, SECRETS_DIR, ADMIN_CRT/KEY, NETWORKS,
# OSSL), plus the image pqc-test-modbus:local (FROM python:3.12-slim,
# pip install pymodbus==3.8.6).
#
# Checks:
#   E1 the SCADA reads the device's holding registers through the link
#   E2 the box logged TLS 1.3, X25519MLKEM768, a verified client: the central gateway
#   E3 the device is not reachable from the control or the wan network
#   P  positive control: the central gateway's certificate, straight to the box, gets a Modbus answer
#   E4 a valid ML-DSA-65 certificate from the same CA, not in allowed-clients.txt: closed, no answer
#   E5 a classical (EC) certificate from the same CA: refused in the handshake
#   E6 no client certificate: refused
#   E7 a classical client (X25519 only): refused
#   E8 the strict listener of the central gateway still answers its ML-DSA-65 client
#   E9 a box with a certificate from another CA under the same name: the central
#      gateway refuses it, the SCADA gets nothing
#   L  latency (recorded, no threshold): new connection per read and one
#      connection for all reads, through the link and straight on the cell network
#
# Usage: edge-link-test.sh WORKDIR
set -uo pipefail
W=${1:?workdir}; mkdir -p "$W"; [ -z "$(ls -A "$W")" ] || { echo "$W not empty"; exit 2; }
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
GW_IMAGE=${GW_IMAGE:-pqc-gateway:1.0.0}; MB_IMAGE=${MB_IMAGE:-pqc-test-modbus:local}
PKI_DIR=${PKI_DIR:?PKI_DIR}; SSL_DIR=${SSL_DIR:?SSL_DIR}; SECRETS_DIR=${SECRETS_DIR:?SECRETS_DIR}
ADMIN_CRT=${ADMIN_CRT:?ADMIN_CRT}; ADMIN_KEY=${ADMIN_KEY:?ADMIN_KEY}
NETWORKS=${NETWORKS:?space-separated docker networks}
OSSL=${OSSL:-/opt/openssl/bin/openssl}; LIBDIR=${LIBDIR:-$(dirname "$(dirname "$OSSL")")/lib64}
N_LAT=${N_LAT:-30}
T=edge-test-$$; CENTRAL=$T-central; EDGE=$T-edge; DEVICE=$T-device
NET_CTL=$T-control; NET_WAN=$T-wan; NET_CELL=$T-cell
O(){ LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" "$@"; }
pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
cleanup(){
	docker rm -f $CENTRAL $EDGE $DEVICE $T-rogue >/dev/null 2>&1
	docker network rm $NET_CTL $NET_WAN $NET_CELL >/dev/null 2>&1
	find "$W" -name '*.key' -exec shred -u {} + 2>/dev/null
}
trap cleanup EXIT

# ── throwaway ML-DSA-65 PKI for the link ──
mkdir -p "$W/pki" "$W/edge" "$W/stream" "$W/rogue"
ca(){ O req -x509 -newkey ML-DSA-65 -nodes -keyout "$W/pki/$1.key" -out "$W/pki/$1.crt" -subj "/O=Edge Test/CN=$2" -days 2 \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null; }
leaf(){ # leaf CA NAME KEYALG EXT...
	local c=$1 n=$2 alg=$3; shift 3
	if [ "$alg" = EC ]; then O req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/pki/$n.key" -out "$W/pki/$n.csr" -subj "/O=Edge Test/CN=$n" 2>/dev/null
	else O req -new -newkey ML-DSA-65 -nodes -keyout "$W/pki/$n.key" -out "$W/pki/$n.csr" -subj "/O=Edge Test/CN=$n" 2>/dev/null; fi
	O x509 -req -in "$W/pki/$n.csr" -CA "$W/pki/$c.crt" -CAkey "$W/pki/$c.key" -CAcreateserial -days 2 -out "$W/pki/$n.crt" \
		-extfile <(printf '%s\n' "$@") 2>/dev/null
}
ca ca "Edge Test CA"; ca rogue-ca "Rogue CA"
SRV=("keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:edge.example")
CLI=("keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth")
leaf ca edge-server ML "${SRV[@]}"; leaf rogue-ca rogue-server ML "${SRV[@]}"
leaf ca central-gateway ML "${CLI[@]}"; leaf ca other-client ML "${CLI[@]}"; leaf ca classical-client EC "${CLI[@]}"
fpr(){ O x509 -in "$1" -outform DER | sha256sum | cut -d' ' -f1; }

# edge box files
cp "$W/pki/edge-server.crt" "$W/pki/edge-server.key" "$W/edge/"; cp "$W/pki/ca.crt" "$W/edge/central-ca.pem"
printf '# the central gateway\n%s\n' "$(fpr "$W/pki/central-gateway.crt")" > "$W/edge/allowed-clients.txt"
# fixed addresses: the box on wan (the same for the rogue box later), the device on cell
SUB=10.$((200 + RANDOM % 50)).$((RANDOM % 250)); EDGE_ADDR=$SUB.10; DEV_ADDR=$SUB.140
sed "s/192.0.2.20:502/$DEV_ADDR:502/" "$REPO/config/edge/nginx.conf" > "$W/edge/nginx.conf"
mkdir -p "$W/edge/lua"   # mount point for the box's Lua (the directory is mounted read-only)
# rogue box: same configuration, another CA's certificate under the same name
cp -r "$W/edge/"* "$W/rogue/"; cp "$W/pki/rogue-server.crt" "$W/rogue/edge-server.crt"; cp "$W/pki/rogue-server.key" "$W/rogue/edge-server.key"
# central side
sed "s/192.0.2.10:8502/$EDGE_ADDR:8502/" "$REPO/config/nginx/stream/edge-link.conf.example" > "$W/stream/edge-link.conf"
cp "$W/pki/central-gateway.crt" "$W/stream/central-client.crt"; cp "$W/pki/central-gateway.key" "$W/stream/central-client.key"
cp "$W/pki/ca.crt" "$W/stream/edge-ca.pem"
chmod -R a+rX "$W/edge" "$W/rogue" "$W/stream"

# ── the Modbus device and the tools ──
cat > "$W/device.py" <<'PY'
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server import StartTcpServer
# pymodbus serves request address N from block address N+1
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(1, [4242, 1717, 2026] + [0] * 97))
StartTcpServer(context=ModbusServerContext(slaves=store, single=True), address=("0.0.0.0", 502))
PY
cat > "$W/client.py" <<'PY'
import json, statistics, sys, time
from pymodbus.client import ModbusTcpClient
host, port, mode, n = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
def read(c):
    r = c.read_holding_registers(0, count=3, slave=1)
    if r.isError():
        raise RuntimeError(str(r))
    return r.registers
if mode == "read":
    c = ModbusTcpClient(host, port=port, timeout=15, retries=0)
    if not c.connect():
        print("no connection"); sys.exit(1)
    try:
        print("registers", *read(c))
    except Exception as e:
        print("error", e); sys.exit(1)
    finally:
        c.close()
else:
    times = []
    c = None
    for i in range(n):
        t0 = time.perf_counter()
        if mode == "new" or c is None:
            c = ModbusTcpClient(host, port=port, timeout=15, retries=0)
            if not c.connect():
                print("no connection"); sys.exit(1)
        read(c)
        if mode == "new":
            c.close()
        times.append((time.perf_counter() - t0) * 1000)
    if c: c.close()
    print(json.dumps({"mode": mode, "n": n, "median_ms": round(statistics.median(times), 2),
                      "p95_ms": round(sorted(times)[int(0.95 * (n - 1))], 2), "first_ms": round(times[0], 2)}))
PY
chmod a+r "$W/device.py" "$W/client.py"

docker network create $NET_CTL >/dev/null
docker network create --subnet $SUB.0/25 $NET_WAN >/dev/null || { echo "subnet $SUB.0/25 taken, run again"; exit 1; }
docker network create --internal --subnet $SUB.128/25 $NET_CELL >/dev/null || { echo "subnet $SUB.128/25 taken, run again"; exit 1; }
docker run -d --name $DEVICE --network $NET_CELL --ip $DEV_ADDR --network-alias device.example -v "$W:/w:ro" "$MB_IMAGE" python /w/device.py >/dev/null
edge_up(){ # edge_up NAME DIR
	docker create --name "$1" --network $NET_WAN --ip $EDGE_ADDR --network-alias edge.example \
		-v "$2:/etc/pqc-edge:ro" -v "$REPO/config/edge/lua:/etc/pqc-edge/lua:ro" -v "$REPO/config/nginx/lua:/etc/nginx/lua:ro" \
		--entrypoint sh "$GW_IMAGE" -c 'mkdir -p /var/log/nginx; exec nginx -c /etc/pqc-edge/nginx.conf -g "daemon off;"' >/dev/null
	docker network connect $NET_CELL "$1"; docker start "$1" >/dev/null
}
edge_up $EDGE "$W/edge"
first=${NETWORKS%% *}
docker create --name $CENTRAL --network "$first" --network-alias central \
	-v "$REPO/config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$REPO/config/nginx/lua:/etc/nginx/lua:ro" \
	-v "$REPO/config/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro" -v "$W/stream:/etc/nginx/stream:ro" \
	-v "$PKI_DIR:/etc/pki/pqc-ca:ro" -v /etc/pki/pqc-empty:/etc/pki/pqc-ca/intermediate/private:ro -v /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro \
	-v "$SSL_DIR:/etc/ssl/pqc:ro" \
	-v "$SECRETS_DIR/gateway-signing.key:/run/secrets/gateway-signing-key:ro" -v "$SECRETS_DIR/gateway-signing-key-admin.key:/run/secrets/gateway-signing-key-admin:ro" \
	-v "$SECRETS_DIR/gateway-signing-key-lookup.key:/run/secrets/gateway-signing-key-lookup:ro" -v "$SECRETS_DIR/control-plane-hmac.key:/run/secrets/control-plane-hmac:ro" \
	-v "$SECRETS_DIR/enroll-hmac.key:/run/secrets/enroll-hmac:ro" \
	--entrypoint sh "$GW_IMAGE" -c 'mkdir -p /var/cache/nginx/client_temp /var/log/nginx /var/cache/pqc-gw/routes; exec nginx -g "daemon off;"' >/dev/null
for n in ${NETWORKS#* } $NET_CTL $NET_WAN; do [ "$n" != "$first" ] && docker network connect "$n" $CENTRAL; done
docker network disconnect "$NET_CTL" $CENTRAL 2>/dev/null; docker network connect --alias central $NET_CTL $CENTRAL
docker start $CENTRAL >/dev/null
sleep 3
docker ps -a --filter name=$T --format '{{.Names}} {{.Status}}'
for c in $EDGE $CENTRAL; do [ "$(docker inspect -f '{{.State.Running}}' $c)" = true ] || { echo "$c not running:"; docker logs $c 2>&1 | tail -5; }; done

MB=(docker run --rm -v "$W:/w:ro" "$MB_IMAGE" python /w/client.py)
on(){ local net=$1; shift; docker run --rm --network "$net" -v "$W:/w:ro" "$MB_IMAGE" python /w/client.py "$@"; }

# E1, E2
r=$(on $NET_CTL central 1502 read 1 2>&1 | tail -1); echo "  E1: $r"
check "E1 the SCADA reads the device's registers through the link" "[ '$r' = 'registers 4242 1717 2026' ]"
docker exec $EDGE sh -c 'tail -1 /var/log/nginx/pqc-edge.log' > "$W/e2.log"; echo "  E2: $(cat "$W/e2.log")"
check "E2 the box logged TLS 1.3, X25519MLKEM768 (0x11ec), a verified client: the central gateway" \
	"grep -q '\"proto\":\"TLSv1.3\"' '$W/e2.log' && grep -qE '\"group\":\"(X25519MLKEM768|0x11ec)\"' '$W/e2.log' && grep -q '\"verify\":\"SUCCESS\"' '$W/e2.log' && grep -q 'CN=central-gateway' '$W/e2.log'"

# E3 isolation
r1=$(on $NET_CTL device.example 502 read 1 2>&1 | tail -1); r2=$(on $NET_WAN device.example 502 read 1 2>&1 | tail -1)
echo "  E3: from control: $r1; from wan: $r2"
check "E3 the device is not reachable from the control or the wan network" "! echo '$r1 $r2' | grep -q registers"

# straight to the box with s_client, sending one Modbus read (transaction 1, unit 1, FC 3, 3 registers)
EDGE_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_WAN\").IPAddress}}" $EDGE)
direct(){ # direct LABEL ARGS... -> bytes of Modbus answer
	local l=$1; shift
	printf '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03' | timeout 15 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
		-connect "$EDGE_IP:8502" -servername edge.example -CAfile "$W/pki/ca.crt" -quiet -ign_eof "$@" > "$W/$l.bin" 2> "$W/$l.err"
	wc -c < "$W/$l.bin" | tr -d ' '
}
b=$(direct p -groups X25519MLKEM768 -cert "$W/pki/central-gateway.crt" -key "$W/pki/central-gateway.key"); echo "  P: $b bytes"
check "P positive control: the central gateway's certificate, straight to the box, gets a Modbus answer" "[ '$b' -ge 9 ]"
b=$(direct e4 -groups X25519MLKEM768 -cert "$W/pki/other-client.crt" -key "$W/pki/other-client.key"); echo "  E4: $b bytes"
check "E4 a valid ML-DSA-65 certificate from the same CA, not allowed: closed without an answer" "[ '$b' = 0 ] && docker exec $EDGE grep -q 'not in the allowed list' /var/log/nginx/error.log"
lines_before=$(docker exec $EDGE sh -c 'wc -l < /var/log/nginx/pqc-edge.log')
b=$(direct e5 -groups X25519MLKEM768 -cert "$W/pki/classical-client.crt" -key "$W/pki/classical-client.key"); echo "  E5: $b bytes, $(grep -m1 -oE 'alert [a-z ]+' "$W/e5.err")"
check "E5 a classical (EC) certificate from the same CA: no answer" "[ '$b' = 0 ]"
b=$(direct e6 -groups X25519MLKEM768); echo "  E6: $b bytes, $(grep -m1 -oE 'alert [a-z ]+' "$W/e6.err")"
check "E6 no client certificate: no answer" "[ '$b' = 0 ]"
docker exec $EDGE sh -c "tail -n +$((lines_before + 1)) /var/log/nginx/pqc-edge.log" > "$W/e56.log"
echo "  E5/E6 box log: $(wc -l < "$W/e56.log") line(s): $(grep -oE '"verify":"[^"]*"|"bytes_out":[0-9]+' "$W/e56.log" | tr '\n' ' ')"
check "E5/E6 on the box: neither session verified, nothing reached the device" "! grep -q '\"verify\":\"SUCCESS\"' '$W/e56.log' && ! grep -qE '\"bytes_out\":[1-9]' '$W/e56.log'"
b=$(direct e7 -groups X25519:P-256 -cert "$W/pki/central-gateway.crt" -key "$W/pki/central-gateway.key"); echo "  E7: $b bytes, $(grep -m1 -oE 'alert [a-z ]+' "$W/e7.err")"
check "E7 a classical key exchange (X25519, P-256), even with the right certificate: no answer" "[ '$b' = 0 ] && grep -q 'alert handshake failure' '$W/e7.err'"

# E8 the central gateway's HTTP side is unchanged
CENTRAL_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_WAN\").IPAddress}}" $CENTRAL)
printf 'GET / HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: close\r\n\r\n' | timeout 10 env LD_LIBRARY_PATH=$LIBDIR OPENSSL_CONF=/dev/null "$OSSL" s_client \
	-connect "$CENTRAL_IP:443" -servername pqc-gw.local -ign_eof -groups X25519MLKEM768 -CAfile "$PKI_DIR/ca-chain.crt" -cert "$ADMIN_CRT" -key "$ADMIN_KEY" > "$W/e8.out" 2>&1
echo "  E8: $(grep -m1 -oE 'HTTP/1.1 [0-9]+' "$W/e8.out")"
check "E8 the central gateway's strict :443 still answers its ML-DSA-65 client" "grep -qE 'HTTP/1.1 [0-9]{3}' '$W/e8.out'"

# L latency, recorded
lat_link_new=$(on $NET_CTL central 1502 new "$N_LAT" 2>&1 | tail -1); lat_link_keep=$(on $NET_CTL central 1502 keep "$N_LAT" 2>&1 | tail -1)
lat_cell_new=$(on $NET_CELL device.example 502 new "$N_LAT" 2>&1 | tail -1); lat_cell_keep=$(on $NET_CELL device.example 502 keep "$N_LAT" 2>&1 | tail -1)
printf 'link new  %s\nlink keep %s\ncell new  %s\ncell keep %s\n' "$lat_link_new" "$lat_link_keep" "$lat_cell_new" "$lat_cell_keep" | tee "$W/latency.txt" | sed 's/^/  L: /'
check "L latency recorded for all four paths" "[ \$(grep -c median_ms '$W/latency.txt') = 4 ]"

# E9 a box with another CA's certificate under the same name
docker rm -f $EDGE >/dev/null; edge_up $T-rogue "$W/rogue"; sleep 2
r=$(on $NET_CTL central 1502 read 1 2>&1 | tail -1); echo "  E9: $r"
docker exec $CENTRAL sh -c 'cat /var/log/nginx/error.log' > "$W/central-error.log" 2>/dev/null
check "E9 a box with another CA's certificate: the central gateway refuses it, the SCADA gets nothing" \
	"! echo '$r' | grep -q registers && grep -q 'upstream SSL certificate verify error' '$W/central-error.log'"

docker exec $CENTRAL sh -c 'cat /var/log/nginx/pqc-edge-link.log' > "$W/central-link.log" 2>/dev/null
docker logs $T-rogue > "$W/rogue.out" 2>&1
echo "== result: $pass passed, $fail failed"
exit $fail
