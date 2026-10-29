#!/usr/bin/env bash
# internal-tls-key-masking-stand.sh: review finding M2 on the ISOLATED stand.
# The internal TLS CA key (pki/internal-tls/) must not be readable inside any
# container that mounts the CA tree (gateway, ocsp-pq, crl-renewer,
# pqc-ca-custodian), checked as root inside each (docker exec -u 0), with a
# canary read first so a failing exec cannot pass as "not readable". Each
# container may see only the private key it uses.
#
#   source STAND_DIR/stand.env; internal-tls-key-masking-stand.sh WORKDIR
set -uo pipefail
W=${1:?workdir}; mkdir -p "$W"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../item4/stand-env.sh"
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
stand_guard "$W"
check "the host side holds the internal TLS CA key (so the mask is what protects it)" "[ -s '$STAND_DIR/pki/internal-tls/internal-tls-ca.key' ]"
declare -A ALLOWED=(
	[gateway]=""
	[ocsp-pq]="ocsp/ocsp-pq.key"
	[crl-renewer]="intermediate/private/intermediate-ca.key"
	[ca-custodian]="intermediate/private/intermediate-ca.key"
)
for svc in gateway ocsp-pq crl-renewer ca-custodian; do
	c=$STAND_PROJECT-$svc
	ex(){ docker exec -u 0 "$c" sh -c "$1" 2>/dev/null; }
	if ! ex '[ -r /etc/pki/pqc-ca/ca-chain.crt ] && [ -r /etc/pki/pqc-ca/internal-tls-ca.crt ]'; then
		check "$svc: canary (public CA files readable)" false; continue
	fi
	keys=$(ex "grep -rl 'PRIVATE KEY' /etc/pki/pqc-ca 2>/dev/null | sed 's#/etc/pki/pqc-ca/##' | sort | tr '\n' ' '" | sed 's/ $//')
	echo "      $svc (as root): private keys visible: ${keys:-none}; internal-tls/: [$(ex 'ls -A /etc/pki/pqc-ca/internal-tls | tr "\n" " "')]"
	check "$svc: internal-tls/ is empty and internal-tls-ca.key unreadable, as root" \
		"[ -z \"\$(ex 'ls -A /etc/pki/pqc-ca/internal-tls')\" ] && ! ex '[ -r /etc/pki/pqc-ca/internal-tls/internal-tls-ca.key ]' && ! ex '[ -r /etc/pki/pqc-ca/internal-tls/internal-tls-ca-rsa.key ]'"
	check "$svc: sees only its own private key (${ALLOWED[$svc]:-none})" "[ '$keys' = '${ALLOWED[$svc]}' ]"
	check "$svc: cannot write into internal-tls/" "! ex 'touch /etc/pki/pqc-ca/internal-tls/.probe'"
done
check "gateway healthcheck (verifies :8081 with the top-level trust file) still passes" \
	"docker exec $GW sh -c \"printf 'GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -CAfile /etc/pki/pqc-ca/internal-tls-ca.crt -verify_return_error -quiet 2>/dev/null | grep -q '200 OK'\""
check "no private key in the work directory" "! grep -rlq 'PRIVATE KEY' '$W'"
echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
