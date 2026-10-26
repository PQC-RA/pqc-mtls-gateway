#!/usr/bin/env bash
# test8b-classical-client.sh: test 8b. Does the gateway refuse a client that
# sends a CLASSICAL certificate although its CertificateRequest allows
# ML-DSA-65 only?
#
# A compliant client never does this: offered only ML-DSA-65, it withholds its
# classical certificate. So the server-side guard (ssl_conf_command
# ClientSignatureAlgorithms ML-DSA-65) is not exercised by any ordinary client.
# The client here is OpenSSL 3.6.2 with a test-only patch,
# test8b-force-client-sigalg.patch beside this script, that ignores the
# server's list and signs with its own classical algorithm, only when
# TEST8B_FORCE_CLIENT_SIGALG is set. Build it apart from everything else and
# never install it as a system OpenSSL:
#
#   tar xf openssl-3.6.2.tar.gz && cd openssl-3.6.2
#   patch -p0 < .../bench/test8b/test8b-force-client-sigalg.patch
#   ./Configure --prefix=$PWD/../openssl-8b no-docs no-tests && make -j && make install_sw
#   OPENSSL_8B=$PWD/../openssl-8b
#
# The classical leaves are signed by the deployment's ML-DSA-65 intermediate,
# so the chain verifies: only the signature-algorithm guard can stop them.
#
#   1  control: the stock client with the ECDSA leaf sends no certificate
#   2  patched client, ECDSA P-256 leaf -> the gateway must refuse
#   3  patched client, RSA-3072 leaf (rsa_pss_rsae) -> the gateway must refuse
#   4  patched client, the ML-DSA-65 admin leaf -> accepted (the client works)
#   5  proof the guard is what refuses: a local openssl s_server with the same
#      server certificate and CA, WITHOUT the guard, accepts the ECDSA leaf
#      from the patched client; WITH -client_sigalgs ML-DSA-65 it refuses it
#
# It signs two 1-day classical-keyed leaves with the intermediate CA on this
# host (openssl ca, writing the CA index; run it when no enrollment is in
# flight) and revokes them through the admin API at the end. So it refuses to
# run unless TEST8B_I_UNDERSTAND=1. It must run on the gateway host, as root:
# it reads the CA tree, the server key (case 5) and the gateway's log volume.
#
# Usage: TEST8B_I_UNDERSTAND=1 OPENSSL_8B=<prefix> test8b-classical-client.sh WORKDIR
set -uo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# -- environment: the deployment on this host, docker-compose.yml as shipped --
HOST=${HOST:-127.0.0.1}                 # loopback only, enforced below
TLS_PORT=${TLS_PORT:-443}               # the mTLS listener as published on the host
SNI=${SNI:-pqc-gw.local}
PKI=${PKI:-/etc/pki/pqc-ca}
SSL_DIR=${SSL_DIR:-/etc/ssl/pqc}
CA=$PKI/ca-chain.crt; DB=$PKI/intermediate/db
ADM_C=${ADMIN_CERT:-$REPO/admin-cert/gateway-admin.crt}; ADM_K=${ADMIN_KEY:-$REPO/admin-cert/gateway-admin.key}
GW=${GW_CONTAINER:-pqc-gateway}
NGINX_LOGS=${NGINX_LOGS:-/var/lib/docker/volumes/pqc-gw_pqc-logs-nginx/_data}
OSSL_PREFIX=${OSSL_PREFIX:-/opt/openssl}          # stock OpenSSL 3.5+ (the deploy's alias)
SPORT=${SPORT:-29801}                   # loopback port for case 5's local s_server
P8=${OPENSSL_8B:?set OPENSSL_8B to the prefix of the patched test-only OpenSSL build}
O="$OSSL_PREFIX/bin/openssl"
export LD_LIBRARY_PATH=$OSSL_PREFIX/lib64 OPENSSL_CONF=/dev/null

if [ "${TEST8B_I_UNDERSTAND:-0}" != 1 ]; then
	echo "refusing to run: this signs two classical-keyed test certificates with the"
	echo "intermediate CA on this host. Set TEST8B_I_UNDERSTAND=1."
	exit 2
fi
W=${1:?workdir}; mkdir -p "$W"
pass=0; fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

# guard WORKDIR: refuse anything but the gateway on this host. HOST must be a
# loopback address, the port must be the one $GW publishes, and the server
# certificate on it must chain to the CA in $PKI, the CA this test signs with.
guard() {
	local w=$1
	case "$HOST" in 127.*|::1|localhost) ;; *) echo "GUARD ABORT: HOST=$HOST is not local"; exit 90 ;; esac
	[ -x "$P8/bin/openssl" ] || { echo "GUARD ABORT: no patched openssl at $P8/bin/openssl"; exit 90; }
	docker port "$GW" 443/tcp 2>/dev/null | grep -qE ":$TLS_PORT\$" \
		|| { echo "GUARD ABORT: $GW does not publish :443 on host port $TLS_PORT"; exit 90; }
	echo | timeout 8 "$O" s_client -connect "$HOST:$TLS_PORT" -servername "$SNI" -showcerts 2>/dev/null \
		| sed -n '/BEGIN CERT/,/END CERT/p' > "$w/srv-$TLS_PORT.pem"
	"$O" verify -CAfile "$CA" -untrusted "$w/srv-$TLS_PORT.pem" "$w/srv-$TLS_PORT.pem" >/dev/null 2>&1 \
		|| { echo "GUARD ABORT: $HOST:$TLS_PORT does not chain to $CA"; exit 90; }
	for f in "$NGINX_LOGS/pqc-mtls-access.log" "$NGINX_LOGS/pqc-mtls-handshake.log"; do
		[ -r "$f" ] || { echo "GUARD ABORT: cannot read $f"; exit 90; }
	done
	echo "GUARD OK ($GW on $HOST:$TLS_PORT, CA $PKI)"
}
guard "$W"

# -- classical leaves signed by the intermediate (host-path config copy) --------
sed "s#^dir[[:space:]]*=.*#dir               = $PKI/intermediate#" "$PKI/intermediate/openssl-intermediate.cnf" > "$W/int-host.cnf"
TS=$(date -u +%H%M%S)
mkleaf(){ # mkleaf NAME KEYARGS...
	local n=$1; shift
	"$O" genpkey "$@" -out "$W/$n.key" 2>/dev/null
	"$O" req -new -key "$W/$n.key" -subj "/C=BG/O=ACME/OU=M2M-Client/CN=t8b-$n-$TS" -out "$W/$n.csr"
	"$O" ca -config "$W/int-host.cnf" -batch -notext -days 1 -in "$W/$n.csr" -out "$W/$n.crt" 2>"$W/$n.ca.err"
	# The custodian (uid 1001) writes the same database; keep it writable for it.
	chown 1001:1001 "$DB"/index.txt* "$DB"/serial* 2>/dev/null || true
}
mkleaf ecdsa -algorithm EC -pkeyopt ec_paramgen_curve:P-256
mkleaf rsa -algorithm RSA -pkeyopt rsa_keygen_bits:3072
for n in ecdsa rsa; do
	echo "   $n leaf: $("$O" x509 -in "$W/$n.crt" -noout -serial -ext keyUsage,extendedKeyUsage 2>/dev/null | tr '\n' ' ')"
	check "$n leaf chains to the ML-DSA-65 CA" "'$O' verify -CAfile '$CA' '$W/$n.crt' >/dev/null 2>&1"
done

ACC0=$(wc -l < "$NGINX_LOGS/pqc-mtls-access.log"); HS0=$(wc -l < "$NGINX_LOGS/pqc-mtls-handshake.log")
try(){ # try LABEL CLIENT(stock|patched) CERT KEY [PORT] -> $W/LABEL.out ; prints the HTTP status line if any
	local l=$1 cl=$2 crt=$3 key=$4 port=${5:-$TLS_PORT} run
	if [ "$cl" = patched ]; then run=(env TEST8B_FORCE_CLIENT_SIGALG=1 "LD_LIBRARY_PATH=$P8/lib64" OPENSSL_CONF=/dev/null "$P8/bin/openssl")
	else run=(env "LD_LIBRARY_PATH=$OSSL_PREFIX/lib64" OPENSSL_CONF=/dev/null "$O"); fi
	printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$SNI" \
		| timeout 15 "${run[@]}" s_client -connect "$HOST:$port" -servername "$SNI" -CAfile "$CA" \
			-cert "$crt" -key "$key" -groups X25519MLKEM768 -ign_eof > "$W/$l.out" 2>&1
	grep -m1 -oE 'HTTP/1\.[01] [0-9]+' "$W/$l.out" || echo "no HTTP response"
}

echo; echo "== 1 control: the stock client withholds its classical certificate"
r=$(try c1-stock-ecdsa stock "$W/ecdsa.crt" "$W/ecdsa.key"); echo "   $r"
check "1 the stock client sends no certificate; the gateway answers 400 (no required certificate)" "grep -qE 'No client certificate|Client Certificate Types|400' '$W/c1-stock-ecdsa.out' && ! grep -q TEST8B '$W/c1-stock-ecdsa.out' && echo '$r' | grep -q ' 400'"

echo; echo "== 2 patched client, ECDSA P-256 leaf"
r=$(try c2-patched-ecdsa patched "$W/ecdsa.crt" "$W/ecdsa.key"); echo "   $r"; grep -m2 -E 'TEST8B|alert|error' "$W/c2-patched-ecdsa.out" | sed 's/^/   /'
check "2 the patched client did send the ECDSA certificate (forced sigalg ecdsa_secp256r1_sha256)" "grep -q 'TEST8B: forcing client sigalg ecdsa_secp256r1_sha256' '$W/c2-patched-ecdsa.out'"
check "2 the gateway refused it: no HTTP 200/404 answer" "! echo '$r' | grep -qE ' (200|404)'"

echo; echo "== 3 patched client, RSA-3072 leaf"
r=$(try c3-patched-rsa patched "$W/rsa.crt" "$W/rsa.key"); echo "   $r"; grep -m2 -E 'TEST8B|alert|error' "$W/c3-patched-rsa.out" | sed 's/^/   /'
check "3 the patched client did send the RSA certificate (forced rsa_pss sigalg)" "grep -q 'TEST8B: forcing client sigalg rsa_pss' '$W/c3-patched-rsa.out'"
check "3 the gateway refused it: no HTTP 200/404 answer" "! echo '$r' | grep -qE ' (200|404)'"

echo; echo "== 4 patched client, ML-DSA-65 admin leaf (the client itself works)"
r=$(try c4-patched-mldsa patched "$ADM_C" "$ADM_K"); echo "   $r"
check "4 an ML-DSA-65 certificate through the patched client is served (404 for /)" "echo '$r' | grep -q ' 404'"

sleep 1
tail -n +$((HS0+1)) "$NGINX_LOGS/pqc-mtls-handshake.log" > "$W/gateway-handshake.log"
tail -n +$((ACC0+1)) "$NGINX_LOGS/pqc-mtls-access.log" > "$W/gateway-access.log"
echo "   gateway handshake log lines during the test:"; sed 's/^/      /' "$W/gateway-handshake.log" | cut -c1-230 | tail -6
check "2/3 the gateway logged why (wrong signature type / handshake failure)" "grep -qiE 'wrong signature type|signature algorithm|SSL_do_handshake\\(\\) failed' '$W/gateway-handshake.log'"
check "2/3 no request from a t8b classical leaf reached the access log with 200/404" "! grep -E 't8b-(ecdsa|rsa)' '$W/gateway-access.log' | grep -qE '\"status\":(200|404)'"

echo; echo "== 5 the guard is what refuses: a local s_server, same server certificate and CA, without and with the guard"
SPORT=29801
for mode in noguard guard; do
	extra=(); [ $mode = guard ] && extra=(-client_sigalgs ML-DSA-65)
	LD_LIBRARY_PATH=$OSSL_PREFIX/lib64 OPENSSL_CONF=/dev/null timeout 20 "$O" s_server -accept 127.0.0.1:$SPORT \
		-cert "$SSL_DIR/server-mldsa65.crt" -key "$SSL_DIR/server-mldsa65.key" -CAfile "$CA" -Verify 1 \
		-groups X25519MLKEM768 -tls1_3 "${extra[@]}" -www > "$W/s_server-$mode.out" 2>&1 &
	SP=$!; sleep 1
	printf 'GET / HTTP/1.0\r\n\r\n' | env TEST8B_FORCE_CLIENT_SIGALG=1 LD_LIBRARY_PATH=$P8/lib64 OPENSSL_CONF=/dev/null timeout 10 "$P8/bin/openssl" s_client \
		-connect 127.0.0.1:$SPORT -servername "$SNI" -CAfile "$CA" -cert "$W/ecdsa.crt" -key "$W/ecdsa.key" -groups X25519MLKEM768 -ign_eof > "$W/c5-$mode.out" 2>&1
	kill $SP 2>/dev/null; wait $SP 2>/dev/null
	echo "   $mode: client: $(grep -m1 -E '^HTTP/|alert|Verification' "$W/c5-$mode.out" | cut -c1-100); server: $(grep -m1 -iE 'error|ACCEPT|verify' "$W/s_server-$mode.out" | cut -c1-100)"
done
check "5 without the guard the server ACCEPTS the classical ECDSA leaf (HTTP 200 from s_server -www)" "grep -q 'HTTP/1.0 200' '$W/c5-noguard.out'"
check "5 with -client_sigalgs ML-DSA-65 the same server REFUSES it" "! grep -q 'HTTP/1.0 200' '$W/c5-guard.out' && grep -q 'wrong signature type' '$W/s_server-guard.out'"

# Revoke the two classical test leaves through the admin API, the supported
# path (it regenerates the CRL). Best effort: they expire in a day regardless.
for n in ecdsa rsa; do
	[ -f "$W/$n.crt" ] || continue
	ser=$("$O" x509 -in "$W/$n.crt" -noout -serial 2>/dev/null | cut -d= -f2)
	[ -n "$ser" ] || continue
	r=$(curl -sS --max-time 15 --cacert "$CA" --cert "$ADM_C" --key "$ADM_K" -H "X-PQC-CSRF:1" \
		--resolve "$SNI:$TLS_PORT:$HOST" -X POST "https://$SNI:$TLS_PORT/admin/certs/revoke" \
		-H "Content-Type: application/json" -d "{\"serial\":\"$ser\",\"reason\":\"cessationOfOperation\"}" 2>&1)
	echo "   revoke $n leaf $ser: $(echo "$r" | head -c 100)"
done

find "$W" -name '*.key' -exec shred -u {} +
echo "== result: $pass passed, $fail failed"
exit $fail
