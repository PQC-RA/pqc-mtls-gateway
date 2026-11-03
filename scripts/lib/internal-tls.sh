# shellcheck shell=bash
# shellcheck disable=SC2034  # the ITLS_* names are used by the scripts that source this
# internal-tls.sh: sourced by scripts/setup-pki.sh and scripts/internal-tls-switch.sh.
# Names and helpers for the internal TLS CA and the gateway's :8081 certificate
# (ADR-022). Needs $PKI_DIR, $SSL_DIR and $OPENSSL (an OpenSSL 3.5+ binary);
# $TRUST_DIR defaults to /etc/pki/pqc-trust.
#
# Files:
#   $TRUST_DIR/                          PUBLIC trust anchors only (ADR-024 §3):
#                                        root, 0755; files 0644. Mounted
#                                        read-only, as a directory, into the
#                                        gateway and management-api.
#       internal-tls-ca.crt              TRUST FILE: what management-api pins
#                                        (NODE_EXTRA_CA_CERTS) and the gateway
#                                        healthcheck verifies :8081 with. One CA,
#                                        or during the ADR-022 transition a
#                                        BUNDLE of the ML-DSA-65 and the RSA
#                                        internal CA.
#       internal-tls-ca-mldsa.crt        the ML-DSA-65 internal CA
#       internal-tls-ca-rsa.crt          the RSA internal CA of a pre-ADR-022 host
#   $PKI_DIR/internal-tls/               CA private keys (root, 0700; host-only,
#                                        no container mounts $PKI_DIR):
#       internal-tls-ca.key              the ML-DSA-65 CA key
#       internal-tls-ca-rsa.key          the RSA CA key (encrypted keys set, then delete)
#   $SSL_DIR/internal-tls.{crt,key}      SERVED by :8081 (a copy of one of:)
#   $SSL_DIR/internal-tls-mldsa.{crt,key}  the ML-DSA-65 leaf
#   $SSL_DIR/internal-tls-rsa.{crt,key}    the RSA leaf (rollback only)
#
# Before ADR-024 the three certificates were in $PKI_DIR (ITLS_LEGACY_*), each
# bind-mounted as a single file. migrate-ca-state.sh forward copies them into
# $TRUST_DIR, and reverse puts them back.

TRUST_DIR="${TRUST_DIR:-/etc/pki/pqc-trust}"
ITLS_BUNDLE="$TRUST_DIR/internal-tls-ca.crt"
ITLS_CA_MLDSA="$TRUST_DIR/internal-tls-ca-mldsa.crt"
ITLS_CA_RSA="$TRUST_DIR/internal-tls-ca-rsa.crt"
ITLS_LEGACY_BUNDLE="$PKI_DIR/internal-tls-ca.crt"
ITLS_LEGACY_CA_MLDSA="$PKI_DIR/internal-tls-ca-mldsa.crt"
ITLS_LEGACY_CA_RSA="$PKI_DIR/internal-tls-ca-rsa.crt"
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

# itls_install SRC DEST MODE: put SRC at DEST atomically, then remove SRC: a
# temporary file in DEST's directory (created 0600, so a key is never readable
# on the way), the mode, then rename(2). Every container mounts these
# directories ($TRUST_DIR, $SSL_DIR), never single files, so a reader sees the
# old file or the new one, never a partly written one. (Node still reads
# NODE_EXTRA_CA_CERTS only at start: a trust change needs a management-api
# restart, which internal-tls-switch.sh checks for.)
itls_install() {
	local tmp
	tmp=$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX")
	if cat "$1" > "$tmp" && chmod "$3" "$tmp" && mv -f "$tmp" "$2"; then
		rm -f "$1"
	else
		rm -f "$tmp"
		echo "ERROR: could not install $2" >&2
		return 1
	fi
}

# The trust directory: root, 0755. Public certificates only.
itls_trust_dir() {
	install -d -o 0 -g 0 -m 0755 "$TRUST_DIR"
}

# A host whose trust files are still where they were before ADR-024 ($PKI_DIR)
# and not yet in $TRUST_DIR: copy them over (the originals stay for a
# rollback). Without this a run would see no trust file and create a NEW
# internal CA over the key the existing bundle depends on.
itls_adopt_legacy_trust() {
	local src dst t
	[ -e "$ITLS_BUNDLE" ] && return 0
	[ -f "$ITLS_LEGACY_BUNDLE" ] || return 0
	itls_trust_dir
	for src in "$ITLS_LEGACY_BUNDLE" "$ITLS_LEGACY_CA_MLDSA" "$ITLS_LEGACY_CA_RSA"; do
		[ -f "$src" ] || continue
		dst="$TRUST_DIR/$(basename "$src")"
		t=$(mktemp)
		cp "$src" "$t" && itls_install "$t" "$dst" 644
		echo "    copied $src to $dst (ADR-024: public trust anchors in $TRUST_DIR)"
	done
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
