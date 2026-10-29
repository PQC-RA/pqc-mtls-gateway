#!/usr/bin/env bash
# stand-up.sh: bring up an ISOLATED item-4 stand from one commit of this
# repository, with its own throwaway PKI, secrets, admin identity, compose
# project name, container names, volumes and loopback ports. Nothing it creates
# touches a live deployment: it refuses live project names, live ports and live
# paths, and the compose wrapper it writes re-checks that on every call.
#
#   stand-up.sh STAND_DIR PROJECT TLS_PORT ENROLL_PORT API_PORT
#
# Needs: docker with compose, git, root (the PKI and the empty mount point
# /etc/pki/pqc-empty), an OpenSSL 3.5+ (scripts/lib/pq-openssl.sh finds it).
#
# Images: every image this repository builds is built from COMMIT with tags of
# the stand's own ($PROJECT-<service>:<commit>), so no shared tag such as
# pqc-gateway:1.0.0 is ever overwritten; the base images come from base.lock
# (scripts/build-all.sh BASES_ONLY=1). management-api is the image pinned in
# docker-compose.yml, pulled from GHCR. The rollback rehearsal's "old code" is
# ROLLBACK_COMMIT (default: the commit before item 4): its custodian is built
# too, its management-api is the one pinned there.
#
# Env:
#   COMMIT           commit of this repository to stand up (default HEAD)
#   ROLLBACK_COMMIT  the pre-item-4 commit for the rollback rehearsal
#   API_SRC          build management-api from this source checkout instead
#   IMG_CUSTODIAN, IMG_API, IMG_GATEWAY, IMG_RENEWER, IMG_OCSP, IMG_PKIDIST
#                    use these images instead of building or pulling them
#   ADMIN_JWT_KID, ADMIN_JWKS_KIDS, JWT_EXPECTED_KID
#                    admin token kids (ADR-022), written to STAND_DIR/env;
#                    the admin-v2 pin (ADMIN_V2_PUB_SHA256) is always written
#   LIVE_PROJECTS    compose projects never to touch (default pqc-gw pqc-mtls-gateway,
#                    plus the project of a running pqc-gateway container)
#
# Writes STAND_DIR/:
#   tree/      the repository at COMMIT (git archive: no .git, no local edits)
#   pki/ ssl/  throwaway PKI (scripts/setup-pki.sh), intermediate unique_subject = no
#   admin/     the stand's admin identity (OU=Admin), fingerprint in env
#   env, compose.override.yml, compose (the wrapper), rollback/ (the gateway
#   config of ROLLBACK_COMMIT, for the rollback rehearsal)
#   stand.env  `source` it, then run bench/item4/*.sh against this stand
set -euo pipefail
SD=${1:?STAND_DIR}; P=${2:?PROJECT}; TP=${3:?TLS_PORT}; EP=${4:?ENROLL_PORT}; AP=${5:?API_PORT}
REPO=$(cd "$(dirname "$0")/.." && pwd); COMMIT=$(git -C "$REPO" rev-parse --short "${COMMIT:-HEAD}")
FIRST_ITEM4=$(git -C "$REPO" log --format=%h --grep='^custodian: renewal profiles' "$COMMIT" | tail -1)
ROLLBACK_COMMIT=$(git -C "$REPO" rev-parse --short "${ROLLBACK_COMMIT:-${FIRST_ITEM4}^}")
# An OpenSSL 3.5+ on the host; on a clean host, the one deploy.sh would install.
( . "$REPO/scripts/lib/pq-openssl.sh" ) >/dev/null 2>&1 || "$REPO/scripts/install-host-openssl.sh"
. "$REPO/scripts/lib/pq-openssl.sh"
LIVE_PROJECTS="${LIVE_PROJECTS:-pqc-gw pqc-mtls-gateway} $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' pqc-gateway 2>/dev/null || true)"
die(){ echo "stand-up: ABORT: $*" >&2; exit 1; }
log(){ echo "$(date -u +%H:%M:%S) $*"; }

# ── refusals ──────────────────────────────────────────────────────────────────
case " $LIVE_PROJECTS " in *" $P "*) die "project '$P' is a live deployment";; esac
[[ "$P" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "project name must be lowercase letters, digits, dashes"
for p in $TP $EP $AP; do case $p in 80|443|3000|8081|8443) die "port $p is a live port";; esac
	ss -ltn "( sport = :$p )" | grep -q LISTEN && die "port $p is in use"; done
[ -e "$SD" ] && die "$SD exists"
case "$SD" in /etc/*|"$REPO"|"$REPO"/*) die "$SD is a live path or inside this repository";; esac
docker ps -a --format '{{.Names}}' | grep -q "^$P-" && die "containers named $P-* exist"

mkdir -p "$SD"/{tree,admin,secrets}; chmod 700 "$SD"
log "stand $P in $SD from $COMMIT"

# ── tree ──────────────────────────────────────────────────────────────────────
git -C "$REPO" archive "$COMMIT" | tar -x -C "$SD/tree"
mkdir -p "$SD/rollback-tree"; git -C "$REPO" archive "$ROLLBACK_COMMIT" | tar -x -C "$SD/rollback-tree"
mkdir -p "$SD/rollback"; (cd "$SD/rollback-tree" && cp -r --parents config docker/gateway/entrypoint.sh scripts/pqc-crl-renew.sh "$SD/rollback/")
echo "$ROLLBACK_COMMIT" > "$SD/rollback/COMMIT"

# ── secrets (in the tree, where docker-compose.yml expects them) ──────────────
(cd "$SD/tree" && bash scripts/generate-gateway-secrets.sh > "$SD/secrets.log" 2>&1)
[ -s "$SD/tree/secrets/renew-hmac.key" ] || { $O rand -hex 32 > "$SD/tree/secrets/renew-hmac.key"; chown root:1001 "$SD/tree/secrets/renew-hmac.key"; chmod 640 "$SD/tree/secrets/renew-hmac.key"; }
log "secrets generated"

# ── PKI ───────────────────────────────────────────────────────────────────────
PKI_DIR="$SD/pki" SSL_DIR="$SD/ssl" OPENSSL_BIN=$O bash "$SD/tree/scripts/setup-pki.sh" > "$SD/pki.log" 2>&1 || { tail -20 "$SD/pki.log"; die "setup-pki.sh failed"; }
grep -q '^unique_subject = no' "$SD/pki/intermediate/db/index.txt.attr" || die "intermediate unique_subject is not no"
# setup-pki.sh writes PKI_DIR into the CA configs; the containers see the PKI at
# /etc/pki/pqc-ca. Keep host-path copies for signing on the host (admin below).
cp "$SD/pki/intermediate/openssl-intermediate.cnf" "$SD/admin/int-host.cnf"
sed -i "s#$SD/pki/#/etc/pki/pqc-ca/#g" "$SD/pki/intermediate/openssl-intermediate.cnf" "$SD/pki/root/openssl-root.cnf"
! grep -rqs "$SD" "$SD/pki/intermediate/openssl-intermediate.cnf" "$SD/pki/root/openssl-root.cnf" || die "host path left in a CA config"
# The classical bootstrap CA: only its certificate is used, by the enrollment
# acceptance test 3 (a client still trusting it must fail against :8443).
PKI_DIR="$SD/pki" SSL_DIR="$SD/ssl" OPENSSL_BIN=$O bash "$SD/tree/scripts/gen-enroll-classical-cert.sh" > "$SD/classical.log" 2>&1 || echo "stand-up: classical bootstrap CA not generated (acceptance test 3 will fail); see $SD/classical.log"
mkdir -p /etc/pki/pqc-empty
log "PKI ready: $($O x509 -in "$SD/pki/intermediate/certs/intermediate-ca.crt" -noout -subject)"

# ── admin identity, signed by the stand's intermediate with a host-path cnf ───
$O req -new -newkey ML-DSA-65 -nodes -keyout "$SD/admin/stand-admin.key" -out "$SD/admin/stand-admin.csr" -subj "/C=BG/O=QS-CAP/OU=Admin/CN=$P-admin" 2>/dev/null
$O ca -config "$SD/admin/int-host.cnf" -batch -notext -days 30 -in "$SD/admin/stand-admin.csr" -out "$SD/admin/stand-admin.crt" 2> "$SD/admin/ca.err" || { cat "$SD/admin/ca.err"; die "admin certificate"; }
chmod 600 "$SD/admin/stand-admin.key"
chown -R 1001:1001 "$SD/pki/intermediate/db" "$SD/pki/intermediate/issued" 2>/dev/null || true
FPR=$($O x509 -in "$SD/admin/stand-admin.crt" -outform DER | sha256sum | cut -d' ' -f1)
log "admin identity $P-admin, sha256 ${FPR:0:16}…"

# ── env and override ──────────────────────────────────────────────────────────
cat > "$SD/env" <<EOF
ADMIN_CERT_FINGERPRINTS=$FPR
AUDITOR_CERT_FINGERPRINTS=
CORS_ALLOWED_ORIGINS=https://127.0.0.1
CONSOLE_ORIGIN=https://127.0.0.1
RENEWAL_ENABLED=1
CUSTODIAN_DEMO_PROFILE=1
EOF
# Admin token (ADR-022). The pin is the SHA-256 of the admin-v2 raw public key;
# the kids come from the caller (defaults: the upgrade-safe admin-v1). The ADR's
# stand end state is ADMIN_JWT_KID=admin-v2 ADMIN_JWKS_KIDS=admin-v2 JWT_EXPECTED_KID=admin-v2.
ADMIN_V2_KEY="$SD/tree/secrets/gateway-signing-key-admin-v2.key"
[ -s "$ADMIN_V2_KEY" ] || die "no admin-v2 key in the stand's secrets (see $SD/secrets.log)"
ADMIN_V2_PIN=$($O pkey -in "$ADMIN_V2_KEY" -pubout -outform DER | tail -c 1952 | sha256sum | cut -d' ' -f1)
cat >> "$SD/env" <<EOF
ADMIN_V2_PUB_SHA256=$ADMIN_V2_PIN
ADMIN_JWT_KID=${ADMIN_JWT_KID:-admin-v1}
ADMIN_JWKS_KIDS=${ADMIN_JWKS_KIDS:-}
JWT_EXPECTED_KID=${JWT_EXPECTED_KID:-admin-v1}
EOF
# ── images ────────────────────────────────────────────────────────────────────
pinned_api(){ sed -n 's/^  image: \(ghcr.io\/[^ ]*management-api@sha256:[0-9a-f]*\).*/\1/p' "$1/docker-compose.yml" | head -1; }
build_img(){ # build_img TAG CONTEXT DOCKERFILE LOG
	docker build -q -t "$1" --label org.opencontainers.image.revision=$COMMIT \
		--build-arg "OPENSSL_VERSION=$(sed -n 's/^OPENSSL_VERSION=//p' "$SD/tree/docker/base/versions.env")" \
		--build-arg "OPENRESTY_VERSION=$(sed -n 's/^OPENRESTY_VERSION=//p' "$SD/tree/docker/base/versions.env")" \
		--build-arg BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local --build-arg BASE_OPENRESTY_IMAGE=pqc-mtls-openresty-base:local \
		-f "$3" "$2" > "$4" 2>&1 || { tail -20 "$4"; die "build of $1 failed (see $4)"; }
}
log "base images (base.lock; kept if present)"
(cd "$SD/tree" && BASES_ONLY=1 bash scripts/build-all.sh) > "$SD/build-bases.log" 2>&1 || { tail -20 "$SD/build-bases.log"; die "base images"; }
T=$SD/tree
[ -n "${IMG_GATEWAY:-}" ]   || { IMG_GATEWAY=$P-gateway:$COMMIT;     log "building $IMG_GATEWAY";   build_img "$IMG_GATEWAY"   "$T/docker" "$T/docker/gateway/Dockerfile"          "$SD/build-gateway.log"; }
[ -n "${IMG_CUSTODIAN:-}" ] || { IMG_CUSTODIAN=$P-ca-custodian:$COMMIT; log "building $IMG_CUSTODIAN"; build_img "$IMG_CUSTODIAN" "$T" "$T/docker/pqc-ca-custodian/Dockerfile" "$SD/build-custodian.log"; }
[ -n "${IMG_RENEWER:-}" ]   || { IMG_RENEWER=$P-crl-renewer:$COMMIT; log "building $IMG_RENEWER";   build_img "$IMG_RENEWER"   "$T/docker/crl-renewer" "$T/docker/crl-renewer/Dockerfile" "$SD/build-renewer.log"; }
[ -n "${IMG_OCSP:-}" ]      || { IMG_OCSP=$P-ocsp-pq:$COMMIT;        log "building $IMG_OCSP";      build_img "$IMG_OCSP"      "$T/docker/ocsp-pq" "$T/docker/ocsp-pq/Dockerfile"         "$SD/build-ocsp.log"; }
[ -n "${IMG_PKIDIST:-}" ]   || { IMG_PKIDIST=$P-pki-dist:$COMMIT;    log "building $IMG_PKIDIST";   build_img "$IMG_PKIDIST"   "$T/docker/pki-dist" "$T/docker/pki-dist/Dockerfile"        "$SD/build-pkidist.log"; }
if [ -z "${IMG_API:-}" ]; then
	if [ -n "${API_SRC:-}" ]; then
		IMG_API=$P-management-api:$(git -C "$API_SRC" rev-parse --short HEAD); log "building $IMG_API from $API_SRC"
		# On the OpenSSL base its own base.lock pins (not the gateway's local base).
		API_BASE=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["image"]+"@"+d["digest"])' "$API_SRC/base.lock" 2>/dev/null || true)
		docker build -q -t "$IMG_API" ${API_BASE:+--build-arg "BASE_OPENSSL_IMAGE=$API_BASE"} "$API_SRC" > "$SD/build-api.log" 2>&1 || { tail "$SD/build-api.log"; die "management-api build"; }
	else
		IMG_API=$(pinned_api "$T"); [ -n "$IMG_API" ] || die "no pinned management-api image in docker-compose.yml"
		log "pulling $IMG_API"; docker pull -q "$IMG_API" > "$SD/pull-api.log" 2>&1 || { cat "$SD/pull-api.log"; die "pull of $IMG_API"; }
	fi
fi
# the rollback rehearsal's old code: custodian built from ROLLBACK_COMMIT, its pinned API
OLD_CUST=$P-ca-custodian:rollback-$ROLLBACK_COMMIT; OLD_API=$(pinned_api "$SD/rollback-tree")
log "building $OLD_CUST (rollback)"; build_img "$OLD_CUST" "$SD/rollback-tree" "$SD/rollback-tree/docker/pqc-ca-custodian/Dockerfile" "$SD/build-custodian-rollback.log"
docker pull -q "$OLD_API" > "$SD/pull-api-rollback.log" 2>&1 || die "pull of $OLD_API (rollback)"
for i in "$IMG_CUSTODIAN" "$IMG_API" "$IMG_GATEWAY" "$IMG_RENEWER" "$IMG_OCSP" "$IMG_PKIDIST" "$OLD_CUST" "$OLD_API"; do docker image inspect "$i" >/dev/null 2>&1 || die "image $i missing"; done

cat > "$SD/compose.override.yml" <<EOF
# Isolated item-4 stand "$P", written by scripts/stand-up.sh from $COMMIT.
# Every volumes/ports list is !override so nothing from the base file merges in.
name: $P
services:
 shadow-mock:
  container_name: $P-shadow-mock
 gateway-volume-init:
  container_name: $P-gateway-volume-init
 gateway:
  image: $IMG_GATEWAY
  pull_policy: never
  container_name: $P-gateway
  ports: !override
   - "127.0.0.1:$TP:443"
   - "127.0.0.1:$EP:8443"
  volumes: !override
   - $SD/pki:/etc/pki/pqc-ca:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/intermediate/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/ocsp:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/internal-tls:ro
   - $SD/ssl:/etc/ssl/pqc:ro
   - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
   - ./config/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro
   - ./config/nginx/lua:/etc/nginx/lua:ro
   - ./config/enroll-ui:/etc/nginx/enroll-ui:ro
   - ./docker/gateway/entrypoint.sh:/usr/local/bin/entrypoint.sh:ro
   - ./secrets/enroll-hmac.key:/run/secrets/enroll-hmac:ro
   - ./secrets/renew-hmac.key:/run/secrets/renew-hmac:ro
   - pqc-logs-audit:/var/log/pqc-gw:rw
   - pqc-routes-cache:/var/cache/pqc-gw/routes:rw
   - pqc-signals:/signals:ro
   - pqc-logs-nginx:/var/log/nginx:rw
 ocsp-pq:
  image: $IMG_OCSP
  pull_policy: never
  container_name: $P-ocsp-pq
  volumes: !override
   - $SD/pki:/etc/pki/pqc-ca:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/intermediate/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/internal-tls:ro
 pki-dist:
  image: $IMG_PKIDIST
  pull_policy: never
  container_name: $P-pki-dist
 crl-renewer:
  image: $IMG_RENEWER
  pull_policy: never
  container_name: $P-crl-renewer
  volumes: !override
   - $SD/pki:/etc/pki/pqc-ca:rw
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/ocsp:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/internal-tls:ro
   - ./scripts/pqc-crl-renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro
   - pqc-www-pki:/var/www/pki:rw
   - pqc-logs-crl:/var/log/pqc-gw:rw
   - pqc-signals:/signals:rw
 pqc-ca-custodian:
  image: $IMG_CUSTODIAN
  pull_policy: never
  container_name: $P-ca-custodian
  volumes: !override
   - $SD/pki:/etc/pki/pqc-ca:rw
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/ocsp:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/root/private:ro
   - /etc/pki/pqc-empty:/etc/pki/pqc-ca/internal-tls:ro
   - ./secrets/custodian-hmac.key:/run/secrets/custodian-hmac:ro
 mgmt-volume-init:
  container_name: $P-mgmt-volume-init
 redis:
  container_name: $P-redis
 management-api:
  image: $IMG_API
  pull_policy: never
  container_name: $P-management-api
  ports: !override
   - "127.0.0.1:$AP:3000"
  volumes: !override
   - pqc-signals:/signals:rw
   - pqc-mgmt-data:/var/lib/pqc-mgmt:rw
   - pqc-logs-audit:/var/log/pqc-gw:ro
   - ./secrets/control-plane-hmac.key:/run/secrets/control-plane-hmac:ro
   - ./secrets/custodian-hmac.key:/run/secrets/custodian-hmac:ro
   - ./secrets/enroll-hmac.key:/run/secrets/enroll-hmac:ro
   - ./secrets/renew-hmac.key:/run/secrets/renew-hmac:ro
   - $SD/pki/internal-tls-ca.crt:/etc/pki/internal-tls-ca.crt:ro
EOF

# ── compose wrapper with the live guards ──────────────────────────────────────
cat > "$SD/compose" <<EOF
#!/usr/bin/env bash
# Compose wrapper for stand "$P" (written by scripts/stand-up.sh). Refuses to run if
# the resolved config names another project, a live host path or a live port.
set -euo pipefail
cd "$SD/tree"
ARGS=(-p $P --env-file "$SD/env" -f docker-compose.yml -f "$SD/compose.override.yml")
CFG=\$(docker compose "\${ARGS[@]}" config 2>/dev/null)
echo "\$CFG" | grep -q '^name: $P\$' || { echo "compose: ABORT: project is not $P" >&2; exit 1; }
if echo "\$CFG" | grep -qE 'source: /etc/pki/pqc-ca\$|source: /etc/pki/pqc-ca/|source: /etc/ssl/pqc|source: $REPO/'; then echo "compose: ABORT: live host path" >&2; exit 1; fi
if echo "\$CFG" | grep -E 'published: "?(80|443|3000|8081|8443)"?\$' >/dev/null; then echo "compose: ABORT: live port" >&2; exit 1; fi
exec docker compose "\${ARGS[@]}" "\$@"
EOF
chmod +x "$SD/compose"

# ── up ────────────────────────────────────────────────────────────────────────
"$SD/compose" up -d > "$SD/up.log" 2>&1 || { tail -20 "$SD/up.log"; die "compose up failed"; }
for i in $(seq 1 90); do ok=1
	for c in ca-custodian gateway; do [ "$(docker inspect -f '{{.State.Health.Status}}' "$P-$c" 2>/dev/null)" = healthy ] || ok=0; done
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:$AP/api/admin/health)" != 000 ] || ok=0
	[ $ok = 1 ] && break; sleep 2; done
[ $ok = 1 ] || die "stand not healthy after 180 s (see $SD/up.log, docker logs $P-gateway)"

cat > "$SD/stand.env" <<EOF
# source this, then run the bench/item4 tests (from this tree) against stand $P
export STAND_PROJECT=$P STAND_DIR=$SD STAND_TLS_PORT=$TP STAND_ENROLL_PORT=$EP STAND_API_PORT=$AP
export STAND_ADMIN_CERT=$SD/admin/stand-admin.crt STAND_ADMIN_KEY=$SD/admin/stand-admin.key STAND_COMPOSE=$SD/compose
export STAND_COMMIT=$COMMIT STAND_OLD_CUSTODIAN=$OLD_CUST STAND_OLD_API=$OLD_API
EOF
{
	echo "stand $P from $COMMIT, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	docker ps --filter label=com.docker.compose.project=$P --format '{{.Names}} {{.Image}} {{.Status}}'
} | tee "$SD/STAND.txt"
log "ready: source $SD/stand.env; bash $SD/tree/bench/item4/run-stand-pass.sh <outdir>"
