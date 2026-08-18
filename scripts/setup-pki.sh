#!/usr/bin/env bash
# setup-pki.sh
# -----------------------------------------------------------------------------
# Bootstrap a fresh post-quantum PKI for the PQC TLS gateway:
#
#   Root CA (ML-DSA-65)  ->  Intermediate CA (ML-DSA-65)  ->  leaf certs
#
# Produces everything the gateway and management-api mount from the host:
#   <PKI_DIR>/root/         root CA (key, cert, db, CRL)
#   <PKI_DIR>/intermediate/ issuing CA (key, cert, db, CRL, issued/)
#   <PKI_DIR>/hybrid-ca-chain.crt       client-auth trust chain (nginx ssl_client_certificate)
#   <PKI_DIR>/hybrid-combined-crl.pem   combined CRL            (nginx ssl_crl)
#   <PKI_DIR>/ca-chain.crt , combined-crl.pem   (compat aliases)
#   <PKI_DIR>/ocsp/ocsp-pq.crt          OCSP responder cert
#   <SSL_DIR>/server-mldsa65.{key,crt}  gateway server certificate
#
# This is a pure-PQC hierarchy (ML-DSA-65 throughout). The filenames use the
# historical `hybrid-*` prefix that the nginx config already references.
#
# Usage:
#   sudo ./scripts/setup-pki.sh                 # provisions /etc/pki/pqc-ca + /etc/ssl/pqc
#   PKI_DIR=/tmp/test-pki SSL_DIR=/tmp/test-ssl ./scripts/setup-pki.sh   # dry location
#
# Idempotency: the root/intermediate CA is bootstrapped exactly once, if it
# already exists at PKI_DIR, this script leaves it untouched rather than
# regenerating it (that would orphan every issued cert). Newer artifacts added
# to this script after a given host was first bootstrapped (currently: the
# internal-tls service-mesh CA) are individually idempotent and ARE still
# generated on a re-run, so re-running this script against an existing PKI is
# always safe and is how a deployment picks up new PKI artifacts.
# -----------------------------------------------------------------------------
set -euo pipefail

PKI_DIR="${PKI_DIR:-/etc/pki/pqc-ca}"
# Organization name written into every certificate this deployment issues.
# The root CA policy requires the intermediate to MATCH it, so it must be the
# same value everywhere; that is why it is one variable rather than a literal
# in each subject line.
PKI_ORG="${PKI_ORG:-PQC-GW}"
SSL_DIR="${SSL_DIR:-/etc/ssl/pqc}"
OPENSSL="${OPENSSL_BIN:-/opt/openssl/bin/openssl}"
KEY_ALG="${KEY_ALG:-ML-DSA-65}"

# KEY_ALG is validated here because this script bootstraps the CLIENT-FACING CA:
# `KEY_ALG=RSA ./scripts/setup-pki.sh` would otherwise build the whole hierarchy
# classically, and nothing downstream re-checks the algorithm. Nothing in this
# repo calls it with a non-PQ algorithm (the bench classical arms build their
# keys directly), so it is strict by default with a deliberate, loud escape
# hatch: PQC_ALLOW_CLASSICAL_CA=1.
if [ "${PQC_ALLOW_CLASSICAL_CA:-0}" != "1" ]; then
    case "$KEY_ALG" in
        ML-DSA-*) ;;
        *)
            echo "ERROR: KEY_ALG='$KEY_ALG' is not a post-quantum signature algorithm." >&2
            echo "  This script bootstraps the client-facing CA; a classical key here" >&2
            echo "  produces a PQC gateway whose chain is not post-quantum at all." >&2
            echo "  If that is genuinely intended (a comparison arm), set" >&2
            echo "  PQC_ALLOW_CLASSICAL_CA=1 to acknowledge it." >&2
            exit 1 ;;
    esac
fi

# Assert the ARTIFACT, not just the input. This runs on BOTH paths, including
# the idempotent skip below, which is the case that matters: a host bootstrapped
# earlier with a classical CA would otherwise keep it forever, silently, because
# the skip path never re-examines what is on disk.
assert_pq_ca() {
    [ "${PQC_ALLOW_CLASSICAL_CA:-0}" = "1" ] && return 0
    local c alg bad=0
    for c in "$PKI_DIR/root/certs/root-ca.crt" "$PKI_DIR/intermediate/certs/intermediate-ca.crt"; do
        [ -f "$c" ] || continue
        alg=$(OPENSSL_CONF=/dev/null "$OPENSSL" x509 -in "$c" -noout -text 2>/dev/null \
              | sed -n 's/^ *Public Key Algorithm: *//p' | head -1)
        case "$alg" in
            ML-DSA-*) ;;
            *) echo "ERROR: $c has a '$alg' key, not ML-DSA." >&2; bad=1 ;;
        esac
    done
    if [ "$bad" -ne 0 ]; then
        echo "  The deployed CA is not post-quantum. Re-bootstrap it, or set" >&2
        echo "  PQC_ALLOW_CLASSICAL_CA=1 if this is a deliberate comparison arm." >&2
        exit 1
    fi
}
# SERVER_IP is embedded in the server cert SAN so clients can connect by IP.
# Auto-detected from the primary non-loopback interface; override via env var.
SERVER_IP="${SERVER_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TPL_DIR="$ROOT_DIR/pki/templates"

# --- Empty dir the gateway edge mounts over key-bearing subdirs -------------
# docker-compose.yml bind-mounts this over intermediate/private
# and ocsp/ in the gateway container, so the internet-facing edge never sees
# any CA private key even though it otherwise mounts the CA tree read-only.
# Created explicitly (not left to Docker's implicit bind-mount auto-create) so
# ownership/permissions are predictable.
#
# Deliberately unconditional and run before the root-CA guard below: it has no
# dependency on PKI state at all, and mkdir -p is naturally idempotent, so
# there is no reason to gate it on a fresh bootstrap vs. a re-run against an
# existing PKI, it always just needs to exist.
mkdir -p /etc/pki/pqc-empty
chmod 555 /etc/pki/pqc-empty

command -v "$OPENSSL" >/dev/null 2>&1 || { echo "FATAL: openssl not found at $OPENSSL (set OPENSSL_BIN)"; exit 1; }
"$OPENSSL" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa" || \
  { echo "FATAL: $OPENSSL has no ML-DSA support, need OpenSSL 3.5+"; exit 1; }

generate_internal_tls() {
    # --- Internal service-mesh TLS CA (classical RSA-2048) -------------------
    # The management-api (Node.js) reaches the gateway's internal control port
    # for the JWKS fetch and the route push. Node's bundled OpenSSL (3.0.x)
    # CANNOT validate ML-DSA certificates, so this ONE internal, private-network
    # channel uses a classical RSA CA. It authenticates gateway<->management-api
    # traffic ONLY; it is NOT part of the public PQC trust chain and never
    # touches the client-facing mTLS (443) or enrollment (8443) listeners. The
    # CA cert is placed at the PKI root so the API (which mounts only this one
    # file, not the CA tree, see docker-compose.yml) can load it via
    # NODE_EXTRA_CA_CERTS; the CA private key stays 600/root and is never
    # readable by the unprivileged API even though it sits inside the mounted
    # tree.
    #
    # Idempotent (skip if already generated), unlike the root/intermediate CA,
    # this is safe to catch up on an EXISTING PKI: a host whose CA predates the
    # internal-TLS leaf must be able to pick it up on a re-run, instead of the
    # whole script hard-failing on the root-CA guard below.
    if [ -f "$PKI_DIR/internal-tls-ca.crt" ]; then
        echo "==> Internal service-mesh TLS CA already exists (skip)."
        return
    fi

    echo "==> Internal service-mesh TLS CA (RSA-2048)"
    INT_TLS_DIR="$PKI_DIR/internal-tls"
    mkdir -p "$INT_TLS_DIR"
    # Self-contained OpenSSL config: the PQC OpenSSL build ships no default
    # openssl.cnf at its compiled-in path, and `req` requires a [req] section,
    # so we provide one inline rather than depend on a system openssl.cnf
    # being present.
    INT_TLS_CNF="$INT_TLS_DIR/internal-tls-openssl.cnf"
    cat > "$INT_TLS_CNF" <<'CNF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:gateway, DNS:pqc-gateway, DNS:localhost, IP:127.0.0.1
CNF
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$INT_TLS_DIR/internal-tls-ca.key"
    chmod 600 "$INT_TLS_DIR/internal-tls-ca.key"
    "$OPENSSL" req -config "$INT_TLS_CNF" -new -x509 -days 3650 -extensions v3_ca \
        -key "$INT_TLS_DIR/internal-tls-ca.key" \
        -subj "/C=BG/O=${PKI_ORG}/OU=Internal Service Mesh/CN=PQC-GW Internal TLS CA" \
        -out "$PKI_DIR/internal-tls-ca.crt"
    chmod 644 "$PKI_DIR/internal-tls-ca.crt"

    echo "==> Gateway internal-TLS server certificate (SAN: gateway)"
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$SSL_DIR/internal-tls.key"
    chmod 600 "$SSL_DIR/internal-tls.key"
    "$OPENSSL" req -config "$INT_TLS_CNF" -new -key "$SSL_DIR/internal-tls.key" \
        -subj "/C=BG/O=${PKI_ORG}/OU=Internal Service Mesh/CN=gateway" \
        -out "$INT_TLS_DIR/internal-tls.csr"
    "$OPENSSL" x509 -req -days 825 -in "$INT_TLS_DIR/internal-tls.csr" \
        -CA "$PKI_DIR/internal-tls-ca.crt" -CAkey "$INT_TLS_DIR/internal-tls-ca.key" \
        -CAcreateserial -extfile "$INT_TLS_CNF" -extensions v3_server \
        -out "$SSL_DIR/internal-tls.crt"
    rm -f "$INT_TLS_DIR/internal-tls.csr"
}

if [ -f "$PKI_DIR/root/certs/root-ca.crt" ]; then
    echo "Root CA already exists at $PKI_DIR, leaving the CA untouched."
    echo "==> Catching up any newer artifacts introduced after initial bootstrap..."
    generate_internal_tls
    # Check the CA that is already on disk, not just the one this run would
    # create. A host bootstrapped elsewhere, or with KEY_ALG overridden, is
    # caught here rather than
    # silently carried forward.
    assert_pq_ca
    echo ""
    echo "==> Nothing else to do."
    exit 0
fi

echo "==> Bootstrapping PQC PKI ($KEY_ALG) at $PKI_DIR (server certs at $SSL_DIR)"

# --- directory skeleton ------------------------------------------------------
mkdir -p "$PKI_DIR"/root/{certs,crl,newcerts,db,private}
mkdir -p "$PKI_DIR"/intermediate/{certs,crl,issued,db,private}
mkdir -p "$PKI_DIR"/ocsp "$SSL_DIR"
chmod 700 "$PKI_DIR"/root/private "$PKI_DIR"/intermediate/private

for ca in root intermediate; do
    : > "$PKI_DIR/$ca/db/index.txt"
    echo 1000 > "$PKI_DIR/$ca/db/serial"
    echo 1000 > "$PKI_DIR/$ca/db/crlnumber"
done
echo "unique_subject = yes" > "$PKI_DIR/root/db/index.txt.attr"
echo "unique_subject = yes" > "$PKI_DIR/intermediate/db/index.txt.attr"

# --- render CA configs (substitute the base dir) -----------------------------
ROOT_CNF="$PKI_DIR/root/openssl-root.cnf"
INT_CNF="$PKI_DIR/intermediate/openssl-intermediate.cnf"
# O and the CA CommonNames carry the organization name. The root policy is
# `organizationName = match`, so the intermediate MUST end up with the same O
# as the root or every signing fails; both are rendered from $PKI_ORG here.
sed "s#/etc/pki/pqc-ca#$PKI_DIR#g; s#^O  *=.*#O                   = $PKI_ORG#; s#^CN  *= .* PQC Root CA G1#CN                  = $PKI_ORG PQC Root CA G1#" \
    "$TPL_DIR/openssl-root.cnf" > "$ROOT_CNF"
sed "s#/etc/pki/pqc-ca#$PKI_DIR#g; s#IP\.2  *=.*#IP.2  = $SERVER_IP#; s#^O  *=.*#O  = $PKI_ORG#; s#^CN *= .* PQC Intermediate CA G1#CN = $PKI_ORG PQC Intermediate CA G1#" \
    "$TPL_DIR/openssl-intermediate.cnf" > "$INT_CNF"

# Assert the substitutions landed. A sed whose anchor has been edited away
# matches nothing and reports success, which is how a template silently loses
# a field; fail here instead of at the first signing.
for _cnf in "$ROOT_CNF" "$INT_CNF"; do
    grep -qE "^O +=[[:space:]]*$PKI_ORG\$" "$_cnf" \
        || { echo "ERROR: organization did not render into $_cnf" >&2; exit 1; }
    grep -qE "^CN +=.*$PKI_ORG" "$_cnf" \
        || { echo "ERROR: CA CommonName did not render into $_cnf" >&2; exit 1; }
done
echo "    Server cert SAN will include IP: $SERVER_IP"

# --- Root CA -----------------------------------------------------------------
echo "==> Root CA"
"$OPENSSL" genpkey -algorithm "$KEY_ALG" -out "$PKI_DIR/root/private/root-ca.key"
chmod 600 "$PKI_DIR/root/private/root-ca.key"
"$OPENSSL" req -config "$ROOT_CNF" -new -x509 -days 3650 \
    -key "$PKI_DIR/root/private/root-ca.key" \
    -extensions v3_root_ca \
    -out "$PKI_DIR/root/certs/root-ca.crt"

# --- Intermediate CA ---------------------------------------------------------
echo "==> Intermediate CA"
"$OPENSSL" genpkey -algorithm "$KEY_ALG" -out "$PKI_DIR/intermediate/private/intermediate-ca.key"
chmod 600 "$PKI_DIR/intermediate/private/intermediate-ca.key"
"$OPENSSL" req -config "$INT_CNF" -new \
    -key "$PKI_DIR/intermediate/private/intermediate-ca.key" \
    -out "$PKI_DIR/intermediate/intermediate-ca.csr"
"$OPENSSL" ca -config "$ROOT_CNF" -batch -notext -days 1825 \
    -extensions v3_intermediate_ca \
    -in  "$PKI_DIR/intermediate/intermediate-ca.csr" \
    -out "$PKI_DIR/intermediate/certs/intermediate-ca.crt"

# --- Gateway server certificate (ML-DSA-65) ----------------------------------
echo "==> Gateway server certificate"
"$OPENSSL" genpkey -algorithm "$KEY_ALG" -out "$SSL_DIR/server-mldsa65.key"
chmod 600 "$SSL_DIR/server-mldsa65.key"
"$OPENSSL" req -config "$INT_CNF" -new \
    -key "$SSL_DIR/server-mldsa65.key" \
    -subj "/C=BG/O=${PKI_ORG}/OU=PQC-Gateway/CN=pqc-gw.local" \
    -out "$SSL_DIR/server-mldsa65.csr"
"$OPENSSL" ca -config "$INT_CNF" -batch -notext -days 365 \
    -extensions v3_server \
    -in  "$SSL_DIR/server-mldsa65.csr" \
    -out "$SSL_DIR/server-mldsa65.crt"

# --- Classical enroll-server certificate (:8443 browser bootstrap) -----------
# The :8443 enrollment endpoint must be browser-reachable, and browsers cannot
# validate the ML-DSA-65 leaf above. Generate a classical ECDSA P-256 CA + leaf
# for :8443 SERVER auth only (key exchange stays post-quantum). See the script
# header for the full rationale. SANs mirror the ML-DSA server cert.
echo "==> Enrollment classical server certificate (:8443)"
# Intentionally NOT passing OPENSSL_BIN: ECDSA needs no PQC build, so the helper
# uses the plain system openssl (with its working default config).
SERVER_IP="$SERVER_IP" PKI_DIR="$PKI_DIR" SSL_DIR="$SSL_DIR" \
    "$ROOT_DIR/scripts/gen-enroll-classical-cert.sh"

# --- OCSP responder certificate ----------------------------------------------
echo "==> OCSP responder certificate"
"$OPENSSL" genpkey -algorithm "$KEY_ALG" -out "$PKI_DIR/ocsp/ocsp-pq.key"
chmod 600 "$PKI_DIR/ocsp/ocsp-pq.key"
"$OPENSSL" req -config "$INT_CNF" -new \
    -key "$PKI_DIR/ocsp/ocsp-pq.key" \
    -subj "/C=BG/O=${PKI_ORG}/OU=OCSP Responder/CN=ocsp.pqc-gw.local" \
    -out "$PKI_DIR/ocsp/ocsp-pq.csr"
"$OPENSSL" ca -config "$INT_CNF" -batch -notext -days 365 \
    -extensions v3_ocsp_responder \
    -in  "$PKI_DIR/ocsp/ocsp-pq.csr" \
    -out "$PKI_DIR/ocsp/ocsp-pq.crt"

generate_internal_tls

# --- CRLs --------------------------------------------------------------------
echo "==> Generating CRLs"
"$OPENSSL" ca -config "$ROOT_CNF" -gencrl -out "$PKI_DIR/root/crl/root-ca.crl"
"$OPENSSL" ca -config "$INT_CNF"  -gencrl -out "$PKI_DIR/intermediate/crl/intermediate-ca.crl"

# --- Trust chain + combined CRL the gateway mounts ---------------------------
echo "==> Assembling trust chain + combined CRL"
cat "$PKI_DIR/intermediate/certs/intermediate-ca.crt" \
    "$PKI_DIR/root/certs/root-ca.crt"            > "$PKI_DIR/hybrid-ca-chain.crt"
cat "$PKI_DIR/root/crl/root-ca.crl" \
    "$PKI_DIR/intermediate/crl/intermediate-ca.crl" > "$PKI_DIR/hybrid-combined-crl.pem"
cp "$PKI_DIR/hybrid-ca-chain.crt"     "$PKI_DIR/ca-chain.crt"
cp "$PKI_DIR/hybrid-combined-crl.pem" "$PKI_DIR/combined-crl.pem"

# --- Least-privilege ownership for the unprivileged management-api runtime ----
# The API container runs as a dedicated non-root account (uid:gid 1001:1001,
# baked into the published pqc-mtls-management-api image). Grant it exactly what
# certificate issuance
# and revocation need, and nothing more:
#   * READ, never write, the intermediate signing key   (sign CSRs / revoke)
#   * READ-WRITE the CA database (db/) and issued/         (update index, new certs)
# Everything else under $PKI_DIR, the root CA, every private key, the CRLs,
# stays owned by root. The Docker bind-mount additionally pins the key read-only.
APP_UID="${APP_UID:-1001}"
APP_GID="${APP_GID:-1001}"
if [ "${SKIP_APP_PERMS:-0}" != "1" ]; then
    echo "==> Applying least-privilege permissions for app uid:gid $APP_UID:$APP_GID"
    INT_KEY="$PKI_DIR/intermediate/private/intermediate-ca.key"
    INT_PRIV="$PKI_DIR/intermediate/private"
    if chown "root:$APP_GID" "$INT_KEY" 2>/dev/null && chmod 640 "$INT_KEY" 2>/dev/null; then
        # 'private' dir: owner rwx, group --x (traverse to the key, no listing).
        chgrp "$APP_GID" "$INT_PRIV" 2>/dev/null || true
        chmod 710 "$INT_PRIV" 2>/dev/null || true
        echo "    intermediate signing key -> root:$APP_GID mode 640 (app reads, cannot write)"
    else
        echo "    WARN: could not set key ownership (run as root for /etc/pki). Ensure uid $APP_UID" >&2
        echo "          can READ $INT_KEY (read-only) before starting the API container." >&2
    fi
    for d in db issued; do
        if chown -R "$APP_UID:$APP_GID" "$PKI_DIR/intermediate/$d" 2>/dev/null; then
            chmod -R u+rwX,g+rwX "$PKI_DIR/intermediate/$d" 2>/dev/null || true
            echo "    intermediate/$d -> $APP_UID:$APP_GID (app read-write)"
        else
            echo "    WARN: could not chown intermediate/$d to $APP_UID:$APP_GID (run as root)" >&2
        fi
    done
fi

assert_pq_ca

echo ""
echo "==> PKI bootstrap complete."
echo "    Root CA      : $($OPENSSL x509 -in "$PKI_DIR/root/certs/root-ca.crt" -noout -subject | sed 's/subject=//')"
echo "    Intermediate : $($OPENSSL x509 -in "$PKI_DIR/intermediate/certs/intermediate-ca.crt" -noout -subject | sed 's/subject=//')"
echo "    Server cert  : $($OPENSSL x509 -in "$SSL_DIR/server-mldsa65.crt" -noout -subject | sed 's/subject=//')"
echo ""
echo "Next: scripts/generate-gateway-secrets.sh  (JWT signing key + control-plane HMAC)"
