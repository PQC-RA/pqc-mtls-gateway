#!/usr/bin/env bash
# internal-tls-switch.sh: which certificate the gateway's :8081 control plane
# serves, and which internal CAs management-api trusts (ADR-022).
#
#   internal-tls-switch.sh status     show the trust file, the served leaf, the copies
#   internal-tls-switch.sh mldsa      serve the ML-DSA-65 leaf (reload, no restart)
#   internal-tls-switch.sh rsa        serve the RSA leaf again (rollback)
#   internal-tls-switch.sh drop-rsa   end of the transition: the trust file holds
#                                     the ML-DSA-65 CA only
#
# The trust file ($PKI_DIR/internal-tls-ca.crt) is what management-api pins
# (NODE_EXTRA_CA_CERTS, read only at start). During the transition it is a
# bundle of the ML-DSA-65 and the RSA internal CA, written by
# `REISSUE_INTERNAL_CA=1 scripts/setup-pki.sh`, so once management-api has
# started on it, either leaf verifies and both switches need only a gateway
# reload. The leaf copies are written IN PLACE (bind-mount inode pitfall).
#
# Refuses, and changes nothing, when:
#   mldsa  the trust file lacks the ML-DSA-65 CA, or management-api was started
#          before the trust file was last written (its in-memory CA set predates
#          the bundle: restart it first), or the ML-DSA-65 leaf does not verify
#   rsa    the trust file lacks the RSA CA (after drop-rsa), management-api runs
#          with GATEWAY_TLS_LEAF_ALG set (it would refuse an RSA leaf), or the
#          RSA leaf does not verify
#   drop-rsa  :8081 does not serve the ML-DSA-65 leaf
#
# Env: PKI_DIR (/etc/pki/pqc-ca), SSL_DIR (/etc/ssl/pqc), OPENSSL_BIN,
#      GATEWAY_CONTAINER (pqc-gateway), API_CONTAINER (pqc-mtls-management-api),
#      FORCE=1 skips the management-api start-time check (not the CA checks).
set -euo pipefail
MODE=${1:?status|mldsa|rsa|drop-rsa}
PKI_DIR=${PKI_DIR:-/etc/pki/pqc-ca}
SSL_DIR=${SSL_DIR:-/etc/ssl/pqc}
GW=${GATEWAY_CONTAINER:-pqc-gateway}
API=${API_CONTAINER:-pqc-mtls-management-api}
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -n "${OPENSSL_BIN:-}" ]; then export OPENSSL=$OPENSSL_BIN
else
	# shellcheck source=lib/pq-openssl.sh
	. "$ROOT_DIR/scripts/lib/pq-openssl.sh"; OPENSSL=$O; export OPENSSL
fi
# shellcheck source=lib/internal-tls.sh
. "$ROOT_DIR/scripts/lib/internal-tls.sh"

die() { echo "internal-tls-switch: REFUSED: $*" >&2; exit 1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
api_env() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$API" 2>/dev/null | sed -n "s/^$1=//p"; }

describe() { # describe FILE: "alg, subject" of every certificate in it
	local d c
	d=$(mktemp -d)
	awk -v d="$d" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (d "/" n ".pem")}' "$1" 2>/dev/null
	for c in "$d"/*.pem; do
		[ -f "$c" ] || continue
		echo "      $(itls_alg "$c"): $(itls_ossl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/^subject=//')"
	done
	rm -rf "$d"
}

served() { # what :8081 serves, verified with the trust file, from inside the gateway
	docker exec "$GW" sh -c 'echo | /opt/openssl/bin/openssl s_client -connect 127.0.0.1:8081 -servername gateway -CAfile /etc/pki/pqc-ca/internal-tls-ca.crt -verify_return_error -brief 2>&1' \
		| sed -n 's/^Signature type: //p; s/^Verification: /verification /p' | tr '\n' ' '
}

status() {
	echo "trust file $ITLS_BUNDLE (management-api pins it):"
	describe "$ITLS_BUNDLE"
	echo "served leaf $ITLS_LEAF_CRT: $(itls_alg "$ITLS_LEAF_CRT"), ends $(itls_expiry "$ITLS_LEAF_CRT")"
	local f
	for f in "$ITLS_ML_CRT" "$ITLS_RSA_CRT" "$ITLS_CA_MLDSA" "$ITLS_CA_RSA"; do
		[ -f "$f" ] && echo "  $(basename "$f"): $(itls_alg "$f"), ends $(itls_expiry "$f")"
	done
	if running "$GW"; then echo "  $GW :8081 now: $(served)"; fi
	if running "$API"; then
		echo "  $API started $(docker inspect -f '{{.State.StartedAt}}' "$API"), trust file written $(date -u -d "@$(stat -c %Y "$ITLS_BUNDLE")" +%Y-%m-%dT%H:%M:%SZ), GATEWAY_TLS_LEAF_ALG='$(api_env GATEWAY_TLS_LEAF_ALG)'"
	fi
}

api_started_on_bundle() { # management-api's CA set is read at start: it must postdate the trust file
	[ "${FORCE:-0}" = 1 ] && { echo "  FORCE=1: management-api start-time check skipped"; return 0; }
	running "$API" || die "$API is not running; cannot tell which CAs it trusts (FORCE=1 to skip)"
	local started written
	started=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$API")" +%s)
	written=$(stat -c %Y "$ITLS_BUNDLE")
	[ "$started" -gt "$written" ] \
		|| die "$API started before $ITLS_BUNDLE was last written, so it does not trust the CA added then. Restart it first (docker restart $API), then run this again."
	# The file as the container sees it (single-file mount, inode pitfall).
	docker exec "$API" cat /etc/pki/internal-tls-ca.crt > "$TMP/api-view.crt" 2>/dev/null \
		|| die "cannot read /etc/pki/internal-tls-ca.crt inside $API"
	itls_bundle_has "$TMP/api-view.crt" "$1" \
		|| die "$API's mounted /etc/pki/internal-tls-ca.crt does not hold $(basename "$1") (stale mount? recreate it)"
}

install_leaf() { # install_leaf CRT KEY: write over the served pair in place, test, reload
	cp -p "$ITLS_LEAF_CRT" "$TMP/prev.crt"; ( umask 077; cp -p "$ITLS_LEAF_KEY" "$TMP/prev.key" )
	cat "$2" > "$ITLS_LEAF_KEY"; cat "$1" > "$ITLS_LEAF_CRT"
	if ! running "$GW"; then echo "  $GW is not running: the new leaf is served from its next start"; return 0; fi
	if ! docker exec "$GW" nginx -t -q 2>"$TMP/nginx-t.err"; then
		cat "$TMP/prev.key" > "$ITLS_LEAF_KEY"; cat "$TMP/prev.crt" > "$ITLS_LEAF_CRT"
		cat "$TMP/nginx-t.err" >&2
		die "nginx -t failed with the new leaf; the previous leaf is back in place"
	fi
	docker exec "$GW" nginx -s reload
	sleep 2
	echo "  $GW :8081 now: $(served)"
}

TMP=$(mktemp -d); chmod 700 "$TMP"; trap 'rm -rf "$TMP"' EXIT
case "$MODE" in
status) status ;;
mldsa)
	[ -f "$ITLS_CA_MLDSA" ] && [ "$(itls_alg "$ITLS_CA_MLDSA")" = ML-DSA-65 ] \
		|| die "no ML-DSA-65 internal CA ($ITLS_CA_MLDSA); run REISSUE_INTERNAL_CA=1 scripts/setup-pki.sh first"
	[ -f "$ITLS_ML_CRT" ] && [ -f "$ITLS_ML_KEY" ] || die "no ML-DSA-65 leaf ($ITLS_ML_CRT)"
	itls_ossl verify -CAfile "$ITLS_CA_MLDSA" "$ITLS_ML_CRT" >/dev/null 2>&1 || die "$ITLS_ML_CRT does not verify against the ML-DSA-65 CA"
	itls_key_matches "$ITLS_ML_CRT" "$ITLS_ML_KEY" || die "$ITLS_ML_KEY does not match $ITLS_ML_CRT"
	itls_bundle_has "$ITLS_BUNDLE" "$ITLS_CA_MLDSA" || die "the trust file $ITLS_BUNDLE does not hold the ML-DSA-65 CA"
	api_started_on_bundle "$ITLS_CA_MLDSA"
	install_leaf "$ITLS_ML_CRT" "$ITLS_ML_KEY"
	echo "OK: :8081 serves the ML-DSA-65 leaf. Rollback: $0 rsa" ;;
rsa)
	[ -f "$ITLS_CA_RSA" ] || die "no RSA internal CA kept ($ITLS_CA_RSA)"
	[ -f "$ITLS_RSA_CRT" ] && [ -f "$ITLS_RSA_KEY" ] || die "no RSA leaf kept ($ITLS_RSA_CRT)"
	itls_ossl verify -CAfile "$ITLS_CA_RSA" "$ITLS_RSA_CRT" >/dev/null 2>&1 || die "$ITLS_RSA_CRT does not verify against the RSA CA (expired?)"
	itls_key_matches "$ITLS_RSA_CRT" "$ITLS_RSA_KEY" || die "$ITLS_RSA_KEY does not match $ITLS_RSA_CRT"
	itls_bundle_has "$ITLS_BUNDLE" "$ITLS_CA_RSA" || die "the trust file no longer holds the RSA CA (drop-rsa was run); an RSA :8081 would be refused"
	if running "$API" && [ -n "$(api_env GATEWAY_TLS_LEAF_ALG)" ]; then
		die "$API runs with GATEWAY_TLS_LEAF_ALG=$(api_env GATEWAY_TLS_LEAF_ALG) and would refuse an RSA leaf; unset it and recreate $API first"
	fi
	install_leaf "$ITLS_RSA_CRT" "$ITLS_RSA_KEY"
	echo "OK: :8081 serves the RSA leaf. Forward again: $0 mldsa" ;;
drop-rsa)
	[ -f "$ITLS_ML_CRT" ] && [ "$(itls_fpr "$ITLS_LEAF_CRT")" = "$(itls_fpr "$ITLS_ML_CRT")" ] \
		|| die ":8081 does not serve the ML-DSA-65 leaf; run '$0 mldsa' first"
	itls_ossl x509 -in "$ITLS_CA_MLDSA" -out "$TMP/bundle.crt"
	itls_write_in_place "$TMP/bundle.crt" "$ITLS_BUNDLE"; chmod 644 "$ITLS_BUNDLE"
	echo "OK: the trust file holds the ML-DSA-65 CA only. A running management-api keeps"
	echo "    the RSA CA in memory until its next restart (restart it, or let the release"
	echo "    that removes admin-v1 do it). Then move $ITLS_CA_RSA_KEY and"
	echo "    $ITLS_RSA_KEY into the encrypted keys set and delete them here." ;;
*) echo "usage: $0 status|mldsa|rsa|drop-rsa" >&2; exit 2 ;;
esac
