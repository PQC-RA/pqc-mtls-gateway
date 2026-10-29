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
# to this script after a given host was first bootstrapped are individually
# idempotent and ARE still generated on a re-run, so re-running this script
# against an existing PKI is always safe and is how a deployment picks up new
# PKI artifacts. One exception, by design: an existing RSA internal TLS CA (the
# :8081 control plane) is NOT replaced by a plain re-run, because management-api
# pins that CA and reads it only at start. Its move to ML-DSA-65 is explicit:
#   REISSUE_INTERNAL_CA=1 ./scripts/setup-pki.sh    (see generate_internal_tls)
# and RENEW_INTERNAL_LEAF=1 renews an ML-DSA-65 :8081 leaf near its end.
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

# gid that owns the delegated OCSP key by group, so the responder container can
# read it without running as root. Must match `user:` on ocsp-pq in
# docker-compose.yml. Deliberately NOT the custodian's 1001.
OCSP_GID="${OCSP_GID:-1002}"

# --- Empty dir every CA-tree consumer mounts over key-bearing subdirs -------
# docker-compose.yml bind-mounts this over the key-bearing subdirectories of
# every service that mounts the CA tree, so each one holds at most the single
# private key it actually uses and none of them holds the root CA key or the
# internal TLS CA key (internal-tls/, ADR-022):
#   gateway      -> intermediate/private, ocsp/, root/private, internal-tls masked (no key)
#   ocsp-pq      -> intermediate/private, root/private, internal-tls masked (keeps ocsp/)
#   crl-renewer  -> ocsp/, root/private, internal-tls masked (keeps intermediate/private)
#   pqc-ca-custodian -> ocsp/, root/private, internal-tls masked (keeps intermediate/private)
# The invariant to re-check whenever a service gains this mount: root/private and
# internal-tls are masked on ALL of them, and this list matches the mount list. Verify against the
# mount list, never against a comment: a comment like this one can assert a
# property that a service mounting the tree does not implement, and nothing
# fails. bench/verify-suite.sh section 6 enumerates the mounters at runtime, so it
# cannot go stale the way this list can.
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

# Group read on the delegated OCSP key for the responder's own uid/gid
# (docker-compose.yml runs ocsp-pq as 1002:1002), so the responder does not have
# to run as root to sign with its own key. 640 root:$OCSP_GID, not 600
# root:root: the key stays unreadable to every other identity in the stack,
# including the custodian's 1001, while root/private stays 0700 root:root so a
# non-root responder cannot traverse it at all even if its mask were dropped.
#
# A separate function, and called from the catch-up branch below as well as from
# the bootstrap path, because the root-CA guard exits early on an existing PKI:
# a host whose PKI predates the non-root responder would otherwise keep the key
# at 600 root:root and ocsp-pq would fail to start after an upgrade.
set_ocsp_key_perms() {
    local key="$PKI_DIR/ocsp/ocsp-pq.key"
    [ -f "$key" ] || return 0
    chown "root:$OCSP_GID" "$key"
    chmod 640 "$key"
    echo "==> OCSP responder key: 640 root:$OCSP_GID (readable by the ocsp-pq container's gid)"
}

# Internal TLS CA and :8081 leaf: names and helpers (ITLS_*), shared with
# scripts/internal-tls-switch.sh.
# shellcheck source=lib/internal-tls.sh
. "$ROOT_DIR/scripts/lib/internal-tls.sh"

# Issue an ML-DSA-65 :8081 leaf signed by CA cert $1 / key $2 into $3 (dir):
# writes $3/leaf.key and $3/leaf.crt, verified and key-matched.
itls_issue_leaf() {
    local ca_crt=$1 ca_key=$2 out=$3
    itls_ossl genpkey -algorithm ML-DSA-65 -out "$out/leaf.key"
    "$OPENSSL" req -config "$INT_TLS_CNF" -new -key "$out/leaf.key" \
        -subj "/C=BG/O=${PKI_ORG}/OU=Internal Service Mesh/CN=gateway" \
        -out "$out/leaf.csr"
    itls_ossl x509 -req -days 365 -in "$out/leaf.csr" \
        -CA "$ca_crt" -CAkey "$ca_key" -set_serial "0x$("$OPENSSL" rand -hex 16)" \
        -extfile "$INT_TLS_CNF" -extensions v3_server \
        -out "$out/leaf.crt"
    itls_ossl verify -CAfile "$ca_crt" "$out/leaf.crt" >/dev/null \
        || { echo "ERROR: new :8081 leaf does not verify against the internal CA" >&2; exit 1; }
    itls_key_matches "$out/leaf.crt" "$out/leaf.key" \
        || { echo "ERROR: new :8081 leaf key and certificate do not match" >&2; exit 1; }
    rm -f "$out/leaf.csr"
}

itls_write_cnf() {
    # Self-contained OpenSSL config: the PQC OpenSSL build ships no default
    # openssl.cnf at its compiled-in path, and `req` requires a [req] section.
    INT_TLS_CNF="$ITLS_KEY_DIR/internal-tls-openssl.cnf"
    cat > "$INT_TLS_CNF" <<'CNF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:gateway, DNS:pqc-gateway, DNS:localhost, IP:127.0.0.1
CNF
}

generate_internal_tls() {
    # --- Internal service-mesh TLS CA and :8081 leaf (ML-DSA-65, ADR-022) ----
    # management-api reaches the gateway's internal control port for the JWKS
    # fetch and the route push. Node 22 bundles OpenSSL 3.5, which validates
    # ML-DSA certificates, so this channel is post-quantum like the rest: an
    # ML-DSA-65 CA (its own, NOT the client-facing root) and an ML-DSA-65 leaf
    # with keyUsage digitalSignature only (RFC 9881 permits no keyEncipherment
    # for ML-DSA). The file names are in scripts/lib/internal-tls.sh.
    #
    # Three cases:
    #   fresh host        ML-DSA-65 CA and leaf are created; the trust file
    #                     holds the ML-DSA-65 CA; :8081 serves the ML-DSA leaf.
    #   ML-DSA-65 present nothing is written. A leaf within 30 days of its end
    #                     is reported (WARNING), and renewed in place only with
    #                     RENEW_INTERNAL_LEAF=1.
    #   RSA (pre-ADR-022) nothing is written unless REISSUE_INTERNAL_CA=1. A
    #                     deploy must never change the CA management-api pins
    #                     behind its back: Node reads NODE_EXTRA_CA_CERTS only at
    #                     start. With REISSUE_INTERNAL_CA=1 the ML-DSA-65 CA and
    #                     leaf are created NEXT TO the RSA ones, the trust file
    #                     becomes a bundle of both CAs (written in place), and
    #                     :8081 keeps serving the RSA leaf. The served leaf is
    #                     switched only by scripts/internal-tls-switch.sh, after
    #                     management-api has been restarted on the bundle.
    mkdir -p "$ITLS_KEY_DIR" "$SSL_DIR"
    chmod 700 "$ITLS_KEY_DIR"

    # A draft of this change (never released) kept the ML-DSA-65 CA only in
    # the trust file; adopt that layout.
    if [ ! -e "$ITLS_CA_MLDSA" ] && [ -f "$ITLS_BUNDLE" ] && [ "$(itls_alg "$ITLS_BUNDLE")" = "ML-DSA-65" ] \
       && [ -f "$ITLS_CA_KEY" ] && itls_key_matches "$ITLS_BUNDLE" "$ITLS_CA_KEY"; then
        itls_ossl x509 -in "$ITLS_BUNDLE" -out "$ITLS_CA_MLDSA"; chmod 644 "$ITLS_CA_MLDSA"
        if [ ! -e "$ITLS_ML_CRT" ] && [ -f "$ITLS_LEAF_CRT" ] && [ "$(itls_alg "$ITLS_LEAF_CRT")" = "ML-DSA-65" ] \
           && itls_key_matches "$ITLS_LEAF_CRT" "$ITLS_LEAF_KEY"; then
            ( umask 077; cp "$ITLS_LEAF_KEY" "$ITLS_ML_KEY" ); cp "$ITLS_LEAF_CRT" "$ITLS_ML_CRT"
        fi
        echo "    adopted the ML-DSA-65 internal CA as internal-tls-ca-mldsa.crt"
    fi

    local have_mldsa=0
    if [ -f "$ITLS_CA_MLDSA" ] && [ "$(itls_alg "$ITLS_CA_MLDSA")" = "ML-DSA-65" ] \
       && [ -f "$ITLS_CA_KEY" ] && itls_key_matches "$ITLS_CA_MLDSA" "$ITLS_CA_KEY"; then
        have_mldsa=1
    fi
    local tmp
    tmp=$(mktemp -d "$ITLS_KEY_DIR/.work.XXXXXX")
    chmod 700 "$tmp"
    # Private keys live in $tmp until installed: removed on any exit.
    trap 'rm -rf "'"$tmp"'"' EXIT

    if [ "$have_mldsa" = 1 ]; then
        itls_write_cnf
        local status=current
        if ! [ -f "$ITLS_ML_CRT" ] || ! [ -f "$ITLS_ML_KEY" ] \
           || ! itls_ossl verify -CAfile "$ITLS_CA_MLDSA" "$ITLS_ML_CRT" >/dev/null 2>&1 \
           || ! itls_key_matches "$ITLS_ML_CRT" "$ITLS_ML_KEY"; then
            status=missing
        elif ! itls_not_expiring "$ITLS_ML_CRT"; then
            status=expiring
        fi
        if ! itls_bundle_has "$ITLS_BUNDLE" "$ITLS_CA_MLDSA" && [ "${REISSUE_INTERNAL_CA:-}" = 1 ]; then
            # A reissue interrupted after the ML-DSA-65 CA was written but before
            # the trust file: finish it (ML-DSA-65 CA, plus the classical one if kept).
            cp "$ITLS_CA_MLDSA" "$tmp/bundle.crt"
            [ -f "$ITLS_CA_RSA" ] && cat "$ITLS_CA_RSA" >> "$tmp/bundle.crt"
            itls_write_in_place "$tmp/bundle.crt" "$ITLS_BUNDLE"; chmod 644 "$ITLS_BUNDLE"
            echo "==> Trust file completed: $(itls_bundle_fprs "$ITLS_BUNDLE" | wc -l) CA(s). Restart management-api next."
        fi
        if ! itls_bundle_has "$ITLS_BUNDLE" "$ITLS_CA_MLDSA"; then
            echo "WARNING: $ITLS_BUNDLE (the CA file management-api pins) does not hold the" >&2
            echo "  ML-DSA-65 internal CA. A :8081 serving the ML-DSA-65 leaf is then refused by" >&2
            echo "  management-api. See scripts/internal-tls-switch.sh status." >&2
        fi
        if [ "$status" = current ]; then
            echo "==> Internal TLS CA and :8081 leaf are ML-DSA-65 and current (skip)."
            echo "    ML-DSA-65 leaf valid until $(itls_expiry "$ITLS_ML_CRT"); :8081 serves $(itls_alg "$ITLS_LEAF_CRT")"
            rm -rf "$tmp"; trap - EXIT
            return
        fi
        if [ "$status" = expiring ] && [ "${RENEW_INTERNAL_LEAF:-0}" != 1 ]; then
            echo "WARNING: the ML-DSA-65 :8081 certificate $ITLS_ML_CRT ends $(itls_expiry "$ITLS_ML_CRT")." >&2
            echo "  Renew it: RENEW_INTERNAL_LEAF=1 scripts/setup-pki.sh, then reload the gateway" >&2
            echo "  (same CA, so management-api needs no restart)." >&2
            rm -rf "$tmp"; trap - EXIT
            return
        fi
        echo "==> :8081 ML-DSA-65 leaf ($status): issuing a new one from the ML-DSA-65 internal CA"
        local was_served=0
        if [ -f "$ITLS_ML_CRT" ] && [ -f "$ITLS_LEAF_CRT" ] && [ "$(itls_fpr "$ITLS_ML_CRT")" = "$(itls_fpr "$ITLS_LEAF_CRT")" ]; then
            was_served=1
        fi
        [ -e "$ITLS_LEAF_CRT" ] || was_served=1
        itls_issue_leaf "$ITLS_CA_MLDSA" "$ITLS_CA_KEY" "$tmp"
        ( umask 077; cp "$tmp/leaf.key" "$tmp/served.key" ); cp "$tmp/leaf.crt" "$tmp/served.crt"
        itls_write_in_place "$tmp/leaf.key" "$ITLS_ML_KEY"; chmod 600 "$ITLS_ML_KEY"
        itls_write_in_place "$tmp/leaf.crt" "$ITLS_ML_CRT"; chmod 644 "$ITLS_ML_CRT"
        if [ "$was_served" = 1 ]; then
            itls_write_in_place "$tmp/served.key" "$ITLS_LEAF_KEY"; chmod 600 "$ITLS_LEAF_KEY"
            itls_write_in_place "$tmp/served.crt" "$ITLS_LEAF_CRT"; chmod 644 "$ITLS_LEAF_CRT"
            echo "    :8081 serves the new leaf after a gateway reload (docker exec pqc-gateway nginx -s reload)."
        fi
        rm -rf "$tmp"; trap - EXIT
        return
    fi

    if [ -f "$ITLS_BUNDLE" ]; then
        # An internal CA exists and it is not (yet) ML-DSA-65: a pre-ADR-022 host.
        local alg
        alg=$(itls_alg "$ITLS_BUNDLE")
        if [ "${REISSUE_INTERNAL_CA:-0}" != 1 ]; then
            echo "WARNING: the internal TLS CA ($ITLS_BUNDLE) is $alg, not ML-DSA-65." >&2
            echo "  Left unchanged: moving :8081 to ML-DSA-65 is an explicit, ordered step" >&2
            echo "  (README, \"Admin token and :8081 to ML-DSA-65\"):" >&2
            echo "    REISSUE_INTERNAL_CA=1 scripts/setup-pki.sh   (adds the ML-DSA-65 CA; :8081 unchanged)" >&2
            echo "    restart management-api                         (it reads the CA bundle at start)" >&2
            echo "    scripts/internal-tls-switch.sh mldsa           (switches :8081, reversible)" >&2
            rm -rf "$tmp"; trap - EXIT
            return
        fi
        echo "==> Internal TLS: adding an ML-DSA-65 CA and leaf next to the $alg ones (REISSUE_INTERNAL_CA=1)"
        # Keep the classical CA and leaf, once (rollback; never a second ssl_certificate).
        if [ ! -e "$ITLS_CA_RSA" ]; then
            itls_ossl x509 -in "$ITLS_BUNDLE" -out "$ITLS_CA_RSA"; chmod 644 "$ITLS_CA_RSA"
            echo "    kept the $alg internal CA as internal-tls-ca-rsa.crt"
        fi
        # The key copy is decided by the KEY file, not the certificate, so a run
        # interrupted between the two still keeps the classical CA key.
        if [ ! -e "$ITLS_CA_RSA_KEY" ] && [ -f "$ITLS_CA_KEY" ] && itls_key_matches "$ITLS_CA_RSA" "$ITLS_CA_KEY"; then
            ( umask 077; cp "$ITLS_CA_KEY" "$ITLS_CA_RSA_KEY.tmp" ); chmod 600 "$ITLS_CA_RSA_KEY.tmp"
            mv "$ITLS_CA_RSA_KEY.tmp" "$ITLS_CA_RSA_KEY"
            echo "    kept the $alg internal CA key as internal-tls-ca-rsa.key"
        fi
        if [ -f "$ITLS_CA_KEY" ] && itls_key_matches "$ITLS_CA_RSA" "$ITLS_CA_KEY" && [ ! -s "$ITLS_CA_RSA_KEY" ]; then
            echo "ERROR: the classical internal CA key could not be kept; refusing to overwrite it" >&2; exit 1
        fi
        if [ ! -e "$ITLS_RSA_CRT" ] && [ -f "$ITLS_LEAF_CRT" ] && [ "$(itls_alg "$ITLS_LEAF_CRT")" != "ML-DSA-65" ]; then
            ( umask 077; cp "$ITLS_LEAF_KEY" "$ITLS_RSA_KEY" ); chmod 600 "$ITLS_RSA_KEY"
            cp "$ITLS_LEAF_CRT" "$ITLS_RSA_CRT"; chmod 644 "$ITLS_RSA_CRT"
            echo "    kept the $(itls_alg "$ITLS_LEAF_CRT") :8081 leaf as internal-tls-rsa.crt"
        fi
    else
        echo "==> Internal service-mesh TLS CA and :8081 leaf (ML-DSA-65)"
    fi

    itls_write_cnf
    itls_ossl genpkey -algorithm ML-DSA-65 -out "$tmp/ca.key"
    "$OPENSSL" req -config "$INT_TLS_CNF" -new -x509 -days 3650 -extensions v3_ca \
        -key "$tmp/ca.key" \
        -subj "/C=BG/O=${PKI_ORG}/OU=Internal Service Mesh/CN=PQC-GW Internal TLS CA ML-DSA-65" \
        -out "$tmp/ca.crt"
    itls_key_matches "$tmp/ca.crt" "$tmp/ca.key" \
        || { echo "ERROR: internal CA key and certificate do not match" >&2; exit 1; }
    itls_issue_leaf "$tmp/ca.crt" "$tmp/ca.key" "$tmp"
    # The trust file: the ML-DSA-65 CA, plus the RSA CA while :8081 can still
    # be switched back to the RSA leaf.
    cp "$tmp/ca.crt" "$tmp/bundle.crt"
    [ -f "$ITLS_CA_RSA" ] && cat "$ITLS_CA_RSA" >> "$tmp/bundle.crt"

    # Install: keys first (600), then certificates (644), all in place. The
    # served leaf is written only on a fresh host; on an RSA host it is
    # switched by scripts/internal-tls-switch.sh.
    local fresh=1
    [ -f "$ITLS_LEAF_CRT" ] && fresh=0
    if [ "$fresh" = 1 ]; then
        ( umask 077; cp "$tmp/leaf.key" "$tmp/served.key" ); cp "$tmp/leaf.crt" "$tmp/served.crt"
    fi
    itls_write_in_place "$tmp/ca.key" "$ITLS_CA_KEY"; chmod 600 "$ITLS_CA_KEY"
    itls_write_in_place "$tmp/leaf.key" "$ITLS_ML_KEY"; chmod 600 "$ITLS_ML_KEY"
    itls_write_in_place "$tmp/ca.crt" "$ITLS_CA_MLDSA"; chmod 644 "$ITLS_CA_MLDSA"
    itls_write_in_place "$tmp/leaf.crt" "$ITLS_ML_CRT"; chmod 644 "$ITLS_ML_CRT"
    if [ "$fresh" = 1 ]; then
        itls_write_in_place "$tmp/served.key" "$ITLS_LEAF_KEY"; chmod 600 "$ITLS_LEAF_KEY"
        itls_write_in_place "$tmp/served.crt" "$ITLS_LEAF_CRT"; chmod 644 "$ITLS_LEAF_CRT"
    fi
    itls_write_in_place "$tmp/bundle.crt" "$ITLS_BUNDLE"; chmod 644 "$ITLS_BUNDLE"
    rm -rf "$tmp"
    trap - EXIT
    echo "    trust file $ITLS_BUNDLE: $(itls_bundle_fprs "$ITLS_BUNDLE" | wc -l) CA(s); :8081 serves $(itls_alg "$ITLS_LEAF_CRT")"
    if [ "$fresh" = 0 ]; then
        echo "    NEXT: restart management-api (Node reads the CA bundle only at start), then"
        echo "          scripts/internal-tls-switch.sh mldsa. :8081 is unchanged until then."
    fi
}

# The rendered intermediate config is written once, at bootstrap, so a template
# fix never reaches an existing CA by itself. The leaf profile is a security
# property (a CA that copies CSR extensions lets a token holder obtain CA:TRUE
# or a server SAN), so say so loudly rather than edit an existing CA config here.
warn_leaf_profile() {
    local cnf="$PKI_DIR/intermediate/openssl-intermediate.cnf"
    [ -f "$cnf" ] || return 0
    if grep -Eq '^[[:space:]]*copy_extensions[[:space:]]*=[[:space:]]*copy' "$cnf" \
       || ! grep -Eq '^[[:space:]]*x509_extensions[[:space:]]*=' "$cnf"; then
        echo "WARNING: $cnf predates the leaf-profile fix:" >&2
        echo "  it copies extensions from CSRs and/or has no default x509_extensions." >&2
        echo "  Set 'copy_extensions = none' and 'x509_extensions = v3_m2m_leaf' in [ CA_default ]" >&2
        echo "  and add the [ v3_m2m_leaf ] section from pki/templates/openssl-intermediate.cnf." >&2
    fi
}

if [ -f "$PKI_DIR/root/certs/root-ca.crt" ]; then
    echo "Root CA already exists at $PKI_DIR, leaving the CA untouched."
    echo "==> Catching up any newer artifacts introduced after initial bootstrap..."
    generate_internal_tls
    set_ocsp_key_perms
    # Check the CA that is already on disk, not just the one this run would
    # create. A host bootstrapped elsewhere, or with KEY_ALG overridden, is
    # caught here rather than
    # silently carried forward.
    assert_pq_ca
    warn_leaf_profile
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
# The intermediate allows a renewal to overlap its predecessor; the custodian
# enforces one active certificate per CN (plus one named successor) under its
# CA lock. index.txt.attr overrides the cnf, so both say the same.
echo "unique_subject = no" > "$PKI_DIR/intermediate/db/index.txt.attr"

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

# --- Classical enroll-server certificate (optional :8443 browser bootstrap) ---
# The default nginx.conf serves :8443 with the ML-DSA-65 leaf above
# (post-quantum-only), so this certificate is not used by it. It is still
# generated so that a deployment that needs browser enrollment can switch
# :8443 back to the classical server certificate (the :8443 TLS lines of
# config/nginx/nginx.conf at commit 87ad02a) without re-running the PKI bootstrap, and so bench/ can report
# its size. Classical ECDSA P-256 CA + leaf for :8443 SERVER auth only; see the
# script header. SANs mirror the ML-DSA server cert.
echo "==> Enrollment classical server certificate (:8443)"
# Intentionally NOT passing OPENSSL_BIN: ECDSA needs no PQC build, so the helper
# uses the plain system openssl (with its working default config).
SERVER_IP="$SERVER_IP" PKI_DIR="$PKI_DIR" SSL_DIR="$SSL_DIR" \
    "$ROOT_DIR/scripts/gen-enroll-classical-cert.sh"

# --- OCSP responder certificate ----------------------------------------------
echo "==> OCSP responder certificate"
"$OPENSSL" genpkey -algorithm "$KEY_ALG" -out "$PKI_DIR/ocsp/ocsp-pq.key"
set_ocsp_key_perms
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
