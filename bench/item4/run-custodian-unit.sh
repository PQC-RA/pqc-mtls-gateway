#!/usr/bin/env bash
# Offline unit test of custodian.js: a throwaway copy of a test CA, no network
# (docker --network none), the custodian and the client in one container.
# Usage: run-custodian-unit.sh <throwaway-pki-dir> <custodian-image>
# The pki directory is modified (unique_subject = no); never point it at a real CA.
set -euo pipefail
P=$1; IMG=$2; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp "$(dirname "$0")/custodian-unit.js" "$T/client.js"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$T/hmac"; chmod -R a+rX "$T"
sed -i 's/^unique_subject *=.*/unique_subject = no/' "$P/intermediate/openssl-intermediate.cnf"
echo 'unique_subject = no' > "$P/intermediate/db/index.txt.attr"
docker run --rm --network none -v "$P:/etc/pki/pqc-ca" -v "$T:/t" \
  -v "$(cd "$(dirname "$0")/../.." && pwd)/docker/pqc-ca-custodian/custodian.js:/c.js:ro" \
  -e CUSTODIAN_HMAC_SECRET_FILE=/t/hmac -e RENEWAL_ENABLED=1 -e CUSTODIAN_DEMO_PROFILE=1 \
  -e CRL_FILE=/etc/pki/pqc-ca/hybrid-combined-crl.pem --entrypoint sh "$IMG" \
  -c 'node /c.js > /t/cust.log 2>&1 & sleep 1.5; node /t/client.js'
