#!/usr/bin/env bash
# bringup.sh: a throwaway copy of the gateway stack from the public repository, on the test
# stand, beside clean1 and without touching it.
#
# It follows the repository's own bring-up, scripts/deploy.sh steps 3 to 9, with three changes:
#   * every host path the stack uses is under $H (the env names setup-pki.sh and
#     scripts/lib/ca-layout.sh already read), not /etc/pki, /etc/ssl or /var/lib;
#   * compose project rs1107 with loopback ports 39443 (:443), 38443 (:8443), 33000 (:3000),
#     and image tags rs1107-<service>:<commit>, so no shared tag is built over;
#   * scripts/init-volumes.sh is not run (it would create volumes outside the project);
#     the compose one-shots gateway-volume-init and mgmt-volume-init do the same work.
# Inside the containers every path is the live one (/var/lib/pqc-ca/..., /etc/pki/pqc-ca, ...).
# The custodian's CA configuration names its paths, so after the host-side bootstrap admin
# signing (deploy.sh step 4) its two path lines are pointed at the container paths.
set -euo pipefail
D=/root/rerun-stack-20261107; R=$D/repo; H=$D/host; P=rs1107
TP=39443; EP=38443; AP=33000
export PKI_DIR=$H/etc-pki-pqc-ca SSL_DIR=$H/etc-ssl-pqc TRUST_DIR=$H/etc-pki-pqc-trust \
  CA_ROOT=$H/var-lib-pqc-ca CA_PUBLIC_DIR=$H/var-lib-pqc-ca-public CA_STATUS_DIR=$H/var-lib-pqc-ca-status \
  OCSP_KEY_DIR=$H/var-lib-pqc-ocsp
OSSL=/opt/openssl/bin/openssl
COMMIT=$(git -C "$R" rev-parse --short HEAD)
mkdir -p "$D/logs"
log(){ echo "$(date -u +%FT%TZ) $*"; }
die(){ echo "ABORT: $*" >&2; exit 1; }

# ── refusals: nothing of clean1, nothing live, nothing left from an earlier run ──
for p in $TP $EP $AP; do ss -ltn "( sport = :$p )" | grep -q LISTEN && die "port $p is in use"; done
docker ps -a --format '{{.Names}}' | grep -qE '^pqc-' && die "containers named pqc-* exist"
[ -z "$(docker ps -aq --filter label=com.docker.compose.project=$P)" ] || die "project $P has containers"
[ ! -e "$H" ] || die "$H exists (tear down first)"
[ ! -e "$R/admin-cert" ] || die "$R/admin-cert exists"
ls "$R/secrets" | grep -q . && die "$R/secrets is not empty"

# ── step 3: PKI (setup-pki.sh, all paths under $H) ──
mkdir -p "$H"
log "setup-pki.sh"
( cd "$R" && OPENSSL_BIN=$OSSL SERVER_IP=$(hostname -I | awk '{print $1}') ./scripts/setup-pki.sh ) > "$D/logs/setup-pki.log" 2>&1 \
  || { tail -30 "$D/logs/setup-pki.log"; die "setup-pki.sh"; }

# ── step 4: bootstrap admin certificate, exactly as deploy.sh signs it ──
. "$R/scripts/lib/ca-layout.sh"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
ADMIN_CN=gateway-admin; PKI_ORG=PQC-GW
A=$R/admin-cert; mkdir -p "$A"; chmod 700 "$A"
"$OSSL" genpkey -algorithm ML-DSA-65 -out "$A/$ADMIN_CN.key" 2>/dev/null; chmod 600 "$A/$ADMIN_CN.key"
"$OSSL" req -new -key "$A/$ADMIN_CN.key" -subj "/C=BG/O=${PKI_ORG}/OU=Admin/CN=$ADMIN_CN" -out "$A/$ADMIN_CN.csr" 2>/dev/null
ca_take_writer_lock || die "writer lock"
ca_run_as_root_writer "$OSSL" ca -config "$CA_CNF_FILE" -batch -notext -days 365 -extensions v3_client \
  -in "$A/$ADMIN_CN.csr" -out "$A/$ADMIN_CN.crt" > "$D/logs/admin-sign.log" 2>&1 || die "admin signing (logs/admin-sign.log)"
exec 9>&-
rm -f /root/rerun-stack-20261107/repo/admin-cert/gateway-admin.csr
ADMIN_FPR=$("$OSSL" x509 -in "$A/$ADMIN_CN.crt" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
log "admin certificate issued, sha256 ${ADMIN_FPR:0:16}..."
unset OPENSSL_CONF

# The CA configuration in the custodian's state: container paths (the live ones).
sed -i -e "s#^dir[[:space:]]*=.*#dir               = /var/lib/pqc-ca/state#" \
       -e "s#^private_key[[:space:]]*=.*#private_key       = /var/lib/pqc-ca/key/intermediate-ca.key#" "$CA_CNF_FILE"
grep -qx "dir               = /var/lib/pqc-ca/state" "$CA_CNF_FILE" || die "dir not rewritten"
grep -qx "private_key       = /var/lib/pqc-ca/key/intermediate-ca.key" "$CA_CNF_FILE" || die "private_key not rewritten"
if grep -rqs "$D" "$CA_STATE_DIR" "$CA_PUBLIC_DIR" "$CA_STATUS_DIR"; then die "a host path is left in the CA state or public files"; fi
ca_layout_file_perms
ca_layout_check || die "CA layout owners or modes"

# ── step 7: gateway secrets (into repo/secrets, where docker-compose.yml reads them) ──
log "generate-gateway-secrets.sh"
( cd "$R" && ./scripts/generate-gateway-secrets.sh ) > "$D/logs/secrets.log" 2>&1 || { tail "$D/logs/secrets.log"; die "secrets"; }
PIN=$(sed -n 's/.*ADMIN_V2_PUB_SHA256): *\([0-9a-f]\{64\}\).*/\1/p' "$D/logs/secrets.log" | head -1)
[ -n "$PIN" ] || die "no admin-v2 pin in logs/secrets.log"
( cd "$R" && ./scripts/check-secrets.sh ) || die "check-secrets.sh"

# ── step 5: env (ADR-022 end state and item-4 switches as on live) ──
LEAF_ALG=$("$OSSL" x509 -in "$SSL_DIR/internal-tls.crt" -noout -text | sed -n 's/^ *Public Key Algorithm: *//p' | head -1)
[ "$LEAF_ALG" = ML-DSA-65 ] || die ":8081 leaf is $LEAF_ALG"
set -a; . "$R/docker/base/versions.env"; set +a
cat > "$D/env" <<ENV
OPENSSL_VERSION=$OPENSSL_VERSION
OPENRESTY_VERSION=$OPENRESTY_VERSION
ADMIN_CERT_FINGERPRINTS=$ADMIN_FPR
AUDITOR_CERT_FINGERPRINTS=
CORS_ALLOWED_ORIGINS=https://127.0.0.1
CONSOLE_ORIGIN=https://127.0.0.1
CERT_VALIDITY_DAYS=365
RENEWAL_ENABLED=1
CUSTODIAN_DEMO_PROFILE=1
DEFAULT_ENROLLMENT_PROFILE=client-30d
ADMIN_JWT_KID=admin-v2
ADMIN_JWKS_KIDS=admin-v2
JWT_EXPECTED_KID=admin-v2
ADMIN_V2_PUB_SHA256=$PIN
GATEWAY_TLS_LEAF_ALG=ML-DSA-65
ENV

# ── override: host sources under $H, own ports and image tags; container paths unchanged ──
cat > "$D/compose.override.yml" <<YML
# Throwaway stack $P from $COMMIT (tools/bringup.sh). Every list is !override.
name: $P
services:
 gateway:
  image: $P-gateway:$COMMIT
  ports: !override
   - "127.0.0.1:$TP:443"
   - "127.0.0.1:$EP:8443"
  volumes: !override
   - $CA_PUBLIC_DIR:/etc/pki/pqc-ca:ro
   - $TRUST_DIR:/etc/pki/pqc-trust:ro
   - $SSL_DIR:/etc/ssl/pqc:ro
   - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
   - ./config/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro
   - ./config/nginx/lua:/etc/nginx/lua:ro
   - ./config/nginx/migration:/etc/nginx/migration:ro
   - ./config/nginx/stream:/etc/nginx/stream:ro
   - ./config/enroll-ui:/etc/nginx/enroll-ui:ro
   - ./docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro
   - ./secrets/enroll-hmac.key:/run/secrets/enroll-hmac:ro
   - ./secrets/renew-hmac.key:/run/secrets/renew-hmac:ro
   - pqc-logs-audit:/var/log/pqc-gw:rw
   - pqc-routes-cache:/var/cache/pqc-gw/routes:rw
   - pqc-logs-nginx:/var/log/nginx:rw
 ocsp-pq:
  image: $P-ocsp-pq:$COMMIT
  volumes: !override
   - $OCSP_KEY_DIR:/var/lib/pqc-ocsp:ro
   - $CA_STATUS_DIR:/var/lib/pqc-ca-status:ro
   - $CA_PUBLIC_DIR:/var/lib/pqc-ca-public:ro
 pki-dist:
  image: $P-pki-dist:$COMMIT
  volumes: !override
   - $CA_PUBLIC_DIR:/var/www/pki:ro
 pqc-ca-custodian:
  image: $P-ca-custodian:$COMMIT
  volumes: !override
   - $CA_ROOT/key:/var/lib/pqc-ca/key:ro
   - $CA_ROOT/state:/var/lib/pqc-ca/state:rw
   - $CA_ROOT/inbox:/var/lib/pqc-ca/inbox:ro
   - $CA_PUBLIC_DIR:/var/lib/pqc-ca-public:rw
   - $CA_STATUS_DIR:/var/lib/pqc-ca-status:rw
   - ./secrets/custodian-hmac.key:/run/secrets/custodian-hmac:ro
 management-api:
  ports: !override
   - "127.0.0.1:$AP:3000"
  volumes: !override
   - pqc-mgmt-data:/var/lib/pqc-mgmt:rw
   - pqc-logs-audit:/var/log/pqc-gw:ro
   - ./secrets/control-plane-hmac.key:/run/secrets/control-plane-hmac:ro
   - ./secrets/custodian-hmac.key:/run/secrets/custodian-hmac:ro
   - ./secrets/enroll-hmac.key:/run/secrets/enroll-hmac:ro
   - ./secrets/renew-hmac.key:/run/secrets/renew-hmac:ro
   - $TRUST_DIR:/etc/pki/pqc-trust:ro
YML

# ── compose wrapper: refuses another project, a live or clean1 host path, another port ──
cat > "$D/compose" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
cd "$R"
ARGS=(-p $P --env-file "$D/env" -f docker-compose.yml -f "$D/compose.override.yml")
CFG=\$(docker compose "\${ARGS[@]}" config 2>/dev/null)
echo "\$CFG" | grep -q '^name: $P\$' || { echo "compose: ABORT: project is not $P" >&2; exit 1; }
if echo "\$CFG" | grep -E 'source: (/var/lib/pqc|/etc/pki|/etc/ssl|/srv/)' >&2; then echo "compose: ABORT: live or clean1 host path" >&2; exit 1; fi
if echo "\$CFG" | grep -E 'published: "?[0-9]+"?\$' | grep -vE '"?($TP|$EP|$AP)"?\$' >&2; then echo "compose: ABORT: unexpected port" >&2; exit 1; fi
exec docker compose "\${ARGS[@]}" "\$@"
WRAP
chmod +x "$D/compose"
"$D/compose" config > "$D/logs/compose-config.yml"

# ── step 8: images. Bases from base.lock (present locally, versions asserted), the rest built here ──
docker run --rm --entrypoint /opt/openssl/bin/openssl pqc-mtls-openssl-base:local version | grep -qF "OpenSSL $OPENSSL_VERSION " || die "openssl base is not $OPENSSL_VERSION"
docker run --rm --entrypoint grep pqc-mtls-openresty-base:local -aoE "openresty/[0-9.]+" /usr/sbin/nginx | grep -qxF "openresty/$OPENRESTY_VERSION" || die "openresty base is not $OPENRESTY_VERSION"
( cd "$R" && ./scripts/check-version-consistency.sh ) > "$D/logs/version-consistency.log" 2>&1 || { tail "$D/logs/version-consistency.log"; die "version consistency"; }
log "building images"
"$D/compose" build gateway ocsp-pq pki-dist pqc-ca-custodian > "$D/logs/build.log" 2>&1 || { tail -30 "$D/logs/build.log"; die "build"; }
API_IMG=$(sed -n 's/^  image: \(ghcr.io\/[^ ]*management-api@sha256:[0-9a-f]*\).*/\1/p' "$R/docker-compose.yml" | head -1)
log "pulling $API_IMG"
docker pull -q "$API_IMG" > "$D/logs/pull-api.log" 2>&1 || { cat "$D/logs/pull-api.log"; die "pull"; }

# ── step 9: start ──
log "compose up"
"$D/compose" up -d > "$D/logs/up.log" 2>&1 || { tail -30 "$D/logs/up.log"; die "compose up"; }
for i in $(seq 1 90); do ok=1
  for c in pqc-ca-custodian pqc-gateway pqc-mtls-management-api; do
    [ "$(docker inspect -f '{{.State.Health.Status}}' $c 2>/dev/null)" = healthy ] || ok=0; done
  [ $ok = 1 ] && break; sleep 2; done
[ $ok = 1 ] || die "not healthy after 180 s"
log "stack $P healthy"
"$D/compose" ps
