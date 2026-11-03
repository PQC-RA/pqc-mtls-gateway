#!/usr/bin/env bash
# run-custodian-crl-unit.sh: offline unit test of the custodian as CRL issuer
# (ADR-024 PR 2). Everything happens in one throwaway container with no
# network: setup-pki.sh makes a fresh PKI inside it, the test starts
# custodian.js from this checkout as uid 1001 (the image's own user), and
# nothing is kept. Never point it at a real CA; it does not touch one.
#
# Usage: run-custodian-crl-unit.sh <custodian-image>
#   The image is built from docker/pqc-ca-custodian/Dockerfile; its custodian.js
#   is not used (this checkout's is), only Node, OpenSSL, flock and setpriv.
#
# The layout imitates ADR-024's target: the intermediate's crl/ owned by the
# custodian, and separate public, status and root-CRL inbox directories.
set -euo pipefail
IMG=${1:?usage: run-custodian-crl-unit.sh <custodian-image>}
repo=$(cd "$(dirname "$0")/../.." && pwd)
docker run --rm --network none --user 0:0 -v "$repo:/repo:ro" --entrypoint bash "$IMG" -c '
set -euo pipefail
cp -r /repo /tmp/r
( cd /tmp/r && PKI_DIR=/tmp/pki SSL_DIR=/tmp/ssl SERVER_IP=127.0.0.1 ./scripts/setup-pki.sh ) > /tmp/setup-pki.log 2>&1 \
  || { tail -20 /tmp/setup-pki.log; exit 1; }
chown 1001:1001 /tmp/pki/intermediate/crl
install -d -o 1001 -g 1001 -m 0755 /pub
install -d -o 1001 -g 1002 -m 2750 /status   # setgid: files keep group 1002 (ocsp-pq)
install -d -o 0 -g 1001 -m 0750 /inbox
install -d -o 0 -g 1001 -m 0750 /t
head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > /t/hmac; chmod 0640 /t/hmac; chgrp 1001 /t/hmac
node /repo/bench/adr024/custodian-crl-unit.js'
