#!/usr/bin/env bash
# run-custodian-crl-unit.sh: offline unit test of the custodian as the CRL
# issuer (ADR-024). Everything happens in one throwaway container with no
# network: setup-pki.sh makes a fresh PKI inside it (and, from ADR-024 PR 4b,
# already moves the intermediate into the custodian's layout; on an older
# setup-pki.sh migrate-ca-state.sh forward does it here), and the test starts
# custodian.js from this checkout as the custodian's own uid 1003. Nothing is
# kept. Never point it at a real CA; it does not touch one.
#
# Usage: run-custodian-crl-unit.sh <custodian-image>
#   The image is built from docker/pqc-ca-custodian/Dockerfile; its custodian.js
#   is not used (this checkout's is), only Node, OpenSSL, flock and setpriv.
set -euo pipefail
IMG=${1:?usage: run-custodian-crl-unit.sh <custodian-image>}
repo=$(cd "$(dirname "$0")/../.." && pwd)
docker run --rm --network none --user 0:0 -v "$repo:/repo:ro" --entrypoint bash "$IMG" -c '
set -euo pipefail
cp -r /repo /tmp/r
( cd /tmp/r && PKI_DIR=/etc/pki/pqc-ca SSL_DIR=/etc/ssl/pqc SERVER_IP=127.0.0.1 ./scripts/setup-pki.sh ) > /tmp/setup-pki.log 2>&1 \
  || { tail -20 /tmp/setup-pki.log; exit 1; }
[ -d /var/lib/pqc-ca/state ] || /tmp/r/scripts/migrate-ca-state.sh forward > /tmp/migrate.log 2>&1 \
  || { tail -20 /tmp/migrate.log; exit 1; }
install -d -o 0 -g 0 -m 0755 /t
# The custodian HMAC secret exactly as scripts/generate-gateway-secrets.sh
# leaves it (owner, group, mode), so a regression there fails here: a custodian
# that cannot read its secret refuses to start (#9, run 41625438530).
( cd /tmp/r && ./scripts/generate-gateway-secrets.sh ) > /tmp/secrets.log 2>&1 || { tail -20 /tmp/secrets.log; exit 1; }
cp -p /tmp/r/secrets/custodian-hmac.key /t/hmac
node /repo/bench/adr024/custodian-crl-unit.js'
