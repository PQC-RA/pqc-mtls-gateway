# shellcheck shell=bash
# shellcheck disable=SC2034  # the ITLS_* names are used by the scripts that source this
# internal-tls.sh: sourced by scripts/setup-pki.sh and scripts/internal-tls-switch.sh.
# Names and helpers for the internal TLS CA and the gateway's :8081 certificate
# (ADR-022). Needs $PKI_DIR, $SSL_DIR and $OPENSSL (an OpenSSL 3.5+ binary).
#
# Files (the trust file is the only one management-api sees):
#   $PKI_DIR/internal-tls-ca.crt         TRUST FILE: what management-api pins
#                                        (NODE_EXTRA_CA_CERTS, single-file mount)
#                                        and the gateway healthcheck verifies
#                                        with. One CA, or during the ADR-022
#                                        transition a BUNDLE of the ML-DSA-65
#                                        and the RSA internal CA.
#   $PKI_DIR/internal-tls-ca-mldsa.crt   the ML-DSA-65 internal CA
#   $PKI_DIR/internal-tls-ca-rsa.crt     the RSA internal CA of a pre-ADR-022 host
#   $PKI_DIR/internal-tls/               CA private keys (root, 0700; masked in
#                                        every container that mounts the tree):
#       internal-tls-ca.key              the ML-DSA-65 CA key
#       internal-tls-ca-rsa.key          the RSA CA key (encrypted keys set, then delete)
#   $SSL_DIR/internal-tls.{crt,key}      SERVED by :8081 (a copy of one of:)
#   $SSL_DIR/internal-tls-mldsa.{crt,key}  the ML-DSA-65 leaf
#   $SSL_DIR/internal-tls-rsa.{crt,key}    the RSA leaf (rollback only)

ITLS_BUNDLE="$PKI_DIR/internal-tls-ca.crt"
ITLS_CA_MLDSA="$PKI_DIR/internal-tls-ca-mldsa.crt"
ITLS_CA_RSA="$PKI_DIR/internal-tls-ca-rsa.crt"
ITLS_KEY_DIR="$PKI_DIR/internal-tls"
ITLS_CA_KEY="$ITLS_KEY_DIR/internal-tls-ca.key"
ITLS_CA_RSA_KEY="$ITLS_KEY_DIR/internal-tls-ca-rsa.key"
ITLS_LEAF_CRT="$SSL_DIR/internal-tls.crt"
ITLS_LEAF_KEY="$SSL_DIR/internal-tls.key"
ITLS_ML_CRT="$SSL_DIR/internal-tls-mldsa.crt"
ITLS_ML_KEY="$SSL_DIR/internal-tls-mldsa.key"
ITLS_RSA_CRT="$SSL_DIR/internal-tls-rsa.crt"
ITLS_RSA_KEY="$SSL_DIR/internal-tls-rsa.key"
# A leaf this close to its end is reported (30 days).
ITLS_WARN_SECONDS=${ITLS_WARN_SECONDS:-2592000}

itls_ossl() { OPENSSL_CONF=/dev/null "$OPENSSL" "$@"; }

# Public key algorithm of the FIRST certificate in a file ("" if unreadable).
itls_alg() {
	itls_ossl x509 -in "$1" -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -1
}

itls_fpr() { itls_ossl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }

# SHA-256 fingerprints of every certificate in a PEM file, one per line.
itls_bundle_fprs() {
	local d c
	d=$(mktemp -d)
	awk -v d="$d" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (d "/" n ".pem")}' "$1" 2>/dev/null
	for c in "$d"/*.pem; do [ -f "$c" ] && itls_fpr "$c"; done
	rm -rf "$d"
}

# True if the PEM file $1 holds the certificate $2.
itls_bundle_has() {
	local want
	want=$(itls_fpr "$2")
	[ -n "$want" ] && itls_bundle_fprs "$1" | grep -qx "$want"
}

# True if the private key $2 belongs to the certificate $1.
itls_key_matches() {
	local a b
	a=$(itls_ossl x509 -in "$1" -noout -pubkey 2>/dev/null) || return 1
	b=$(itls_ossl pkey -in "$2" -pubout 2>/dev/null) || return 1
	[ -n "$a" ] && [ "$a" = "$b" ]
}

# Write $1 over $2 IN PLACE (same inode), then remove $1. Single-file bind
# mounts (management-api mounts internal-tls-ca.crt as one file) keep pointing
# at the inode they were started with: a rename or `cp --remove-destination`
# would leave a running container with the old content for good.
itls_write_in_place() {
	if [ -e "$2" ]; then cat "$1" > "$2"; else cp "$1" "$2"; fi
	rm -f "$1"
}

# "notAfter (N days)" of a certificate.
itls_expiry() {
	local end secs
	end=$(itls_ossl x509 -in "$1" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
	[ -n "$end" ] || { echo "unreadable"; return; }
	secs=$(( $(date -d "$end" +%s) - $(date +%s) ))
	echo "$end ($(( secs / 86400 )) days)"
}

# True if the certificate is still valid ITLS_WARN_SECONDS from now.
itls_not_expiring() { itls_ossl x509 -in "$1" -noout -checkend "$ITLS_WARN_SECONDS" >/dev/null 2>&1; }
