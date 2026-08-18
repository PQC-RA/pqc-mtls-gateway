#!/usr/bin/env bash
# gen-enroll-classical-cert.sh
# -----------------------------------------------------------------------------
# Generate a CLASSICAL (ECDSA P-256) CA + enroll-server leaf for the public
# :8443 enrollment bootstrap endpoint.
#
# Why classical server auth here (and ONLY here):
#   Browsers cannot validate the ML-DSA-65 server cert used on :443
#   (SSL_ERROR_NO_CYPHER_OVERLAP), so an operator with no client cert yet cannot
#   even load the enrollment page. This pre-enrollment channel carries no
#   long-term secret, the operator's private key never crosses the wire, the
#   enrollment token is single-use + short-TTL, and the CSR / issued cert are
#   public, and a real-time quantum MITM needs a CRQC that does not exist. So
#   classical SERVER authentication is acceptable on this one bootstrap channel.
#
# The KEY EXCHANGE on :8443 stays post-quantum (nginx keeps
# `ssl_conf_command Groups X25519MLKEM768`). Only the server certificate's
# signature algorithm is classical. :443 (data/admin plane) is untouched:
# ML-DSA-65 server cert + mutual TLS.
#
# ECDSA needs no PQC build, any OpenSSL 1.1.1+/3.x works. We reuse the same
# OPENSSL_BIN as setup-pki.sh only for consistency.
#
# Outputs (keys are gitignored via *.key, generated per-deployment):
#   <SSL_DIR>/enroll-classical.crt   leaf served by nginx on :8443 (mounted :ro)
#   <SSL_DIR>/enroll-classical.key   leaf private key (chmod 600)
#   <PKI_DIR>/enroll-classical-ca.crt  root CA, operators import this to trust :8443
#   <PKI_DIR>/enroll-classical-ca.key  CA private key (chmod 600)
#
# Usage:
#   ./scripts/gen-enroll-classical-cert.sh              # /etc/pki/pqc-ca + /etc/ssl/pqc
#   SERVER_IP=<server-ip> ./scripts/gen-enroll-classical-cert.sh
# Called automatically by setup-pki.sh after the ML-DSA server cert.
# -----------------------------------------------------------------------------
set -euo pipefail

PKI_DIR="${PKI_DIR:-/etc/pki/pqc-ca}"
SSL_DIR="${SSL_DIR:-/etc/ssl/pqc}"
# ECDSA needs no PQC *algorithms*, but we still invoke the repo's OpenSSL 3.6.2
# build: it is the only self-consistent openssl on the gateway host (the distro's
# /usr/bin/openssl has a binary/library ABI mismatch that segfaults). Any plain
# OpenSSL 1.1.1+/3.x works elsewhere, override with OPENSSL_BIN.
OPENSSL="${OPENSSL_BIN:-/opt/openssl/bin/openssl}"
# The /opt build has no readable default openssl.cnf, so `req`/`x509` fail to
# even open it. Point at the host's config (the same one the repo uses for its
# s_client recipes) if the caller hasn't set one.
if [ -z "${OPENSSL_CONF:-}" ] && [ -r /etc/ssl/openssl.cnf ]; then
    export OPENSSL_CONF=/etc/ssl/openssl.cnf
fi
# SERVER_IP is embedded in the leaf SAN so operators can reach :8443 by IP.
# Auto-detected from the primary non-loopback interface; override via env var.
# Mirrors setup-pki.sh so the classical leaf SANs match the ML-DSA server cert.
SERVER_IP="${SERVER_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

command -v "$OPENSSL" >/dev/null 2>&1 || { echo "FATAL: openssl not found at $OPENSSL (set OPENSSL_BIN)"; exit 1; }
mkdir -p "$PKI_DIR" "$SSL_DIR"

CA_KEY="$PKI_DIR/enroll-classical-ca.key"
CA_CRT="$PKI_DIR/enroll-classical-ca.crt"
LEAF_KEY="$SSL_DIR/enroll-classical.key"
LEAF_CRT="$SSL_DIR/enroll-classical.crt"
LEAF_CSR="$(mktemp)"
EXT="$(mktemp)"
trap 'rm -f "$LEAF_CSR" "$EXT"' EXIT

echo "==> Enrollment classical CA + leaf (ECDSA P-256); leaf SAN IP: $SERVER_IP"

# --- Root CA (ECDSA P-256, self-signed) --------------------------------------
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
chmod 600 "$CA_KEY"
"$OPENSSL" req -x509 -new -key "$CA_KEY" -sha256 -days 3650 \
    -subj "/C=BG/O=QS-CAP/OU=Enroll-Bootstrap/CN=enroll-classical-ca" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA_CRT"

# --- Enroll-server leaf (ECDSA P-256), signed by the classical CA ------------
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$LEAF_KEY"
chmod 600 "$LEAF_KEY"
"$OPENSSL" req -new -key "$LEAF_KEY" -sha256 \
    -subj "/C=BG/O=QS-CAP/OU=Enroll-Bootstrap/CN=pqc-gw.local" \
    -out "$LEAF_CSR"

# SANs mirror the ML-DSA server cert (setup-pki.sh / openssl-intermediate.cnf)
# so an operator reaching :8443 by any hostname or IP validates cleanly.
cat > "$EXT" <<EXTEOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
DNS.1 = pqc-gw.local
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = $SERVER_IP
EXTEOF

"$OPENSSL" x509 -req -in "$LEAF_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -CAcreateserial -days 825 -sha256 -extfile "$EXT" -out "$LEAF_CRT"

echo "    Leaf : $LEAF_CRT"
echo "    CA   : $CA_CRT  (import into the operator's browser trust store to reach :8443)"
"$OPENSSL" x509 -in "$LEAF_CRT" -noout -subject -ext subjectAltName 2>/dev/null | sed 's/^/    /'
