#!/usr/bin/env bash
# check-cert-expiry.sh: the deployment's own certificates that nothing renews
# automatically, with their end dates. Exit 1 if any ends within WARN_DAYS
# (default 30) or has ended, so cron or monitoring can alert on it. The gateway
# container logs the same warning ([cert-expiry], docker logs) for the
# certificates it serves.
#
#   scripts/check-cert-expiry.sh [CERT...]
#   Env: PKI_DIR (/etc/pki/pqc-ca), SSL_DIR (/etc/ssl/pqc), WARN_DAYS (30), OPENSSL_BIN
#
# Renewal: the :8081 leaf with RENEW_INTERNAL_LEAF=1 scripts/setup-pki.sh and a
# gateway reload (README, "Admin token and :8081 to ML-DSA-65").
set -euo pipefail
PKI_DIR=${PKI_DIR:-/etc/pki/pqc-ca}; SSL_DIR=${SSL_DIR:-/etc/ssl/pqc}; WARN_DAYS=${WARN_DAYS:-30}
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -n "${OPENSSL_BIN:-}" ]; then O=$OPENSSL_BIN; else
	# shellcheck source=lib/pq-openssl.sh
	. "$ROOT_DIR/scripts/lib/pq-openssl.sh"; fi
if [ $# -eq 0 ]; then
	set -- "$SSL_DIR/internal-tls.crt" "$SSL_DIR/internal-tls-mldsa.crt" "$SSL_DIR/server-mldsa65.crt" \
		"$PKI_DIR/ocsp/ocsp-pq.crt" "$PKI_DIR/internal-tls-ca-mldsa.crt" \
		"$PKI_DIR/intermediate/certs/intermediate-ca.crt" "$PKI_DIR/root/certs/root-ca.crt"
fi
rc=0
for c in "$@"; do
	[ -f "$c" ] || continue
	end=$(OPENSSL_CONF=/dev/null "$O" x509 -in "$c" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
	if [ -z "$end" ]; then echo "ERROR  $c: unreadable"; rc=1; continue; fi
	days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
	if ! OPENSSL_CONF=/dev/null "$O" x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1; then
		echo "ERROR  $c: ENDED $end"; rc=1
	elif ! OPENSSL_CONF=/dev/null "$O" x509 -in "$c" -noout -checkend $((WARN_DAYS * 86400)) >/dev/null 2>&1; then
		echo "WARN   $c: ends $end, in $days days"; rc=1
	else
		echo "ok     $c: ends $end, in $days days"
	fi
done
exit $rc
