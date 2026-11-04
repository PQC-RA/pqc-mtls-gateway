#!/bin/bash
# usage: start_api.sh orig|patched
A=/root/talk-campaign-20261104/a24; V=$1; docker rm -f a24-api >/dev/null 2>&1
M=$A/api/main.orig.js; [ "$V" = patched ] && M=$A/api/main.patched.js
docker run -d --rm --name a24-api --network host -v $M:/usr/src/app/dist/main.js:ro -v $A/sec/enroll:/run/secrets/enroll-hmac:ro -v $A/sec/h:/run/secrets/custodian-hmac:ro \
 -e NODE_ENV=production -e PORT=13777 -e HOST=127.0.0.1 -e REDIS_URL=redis://127.0.0.1:16379 -e CUSTODIAN_URL=http://127.0.0.1:18091 \
 -e ADMIN_CERT_FINGERPRINTS=$(printf a%.0s $(seq 64)) -e ADMIN_V2_PUB_SHA256=$(printf b%.0s $(seq 64)) -e JWT_EXPECTED_KID=admin-v2 \
 -e JWT_EXPECTED_ISSUER=pqc-gateway -e JWT_EXPECTED_AUDIENCE=pqc-mtls-management-api -e GATEWAY_JWKS_URI=http://127.0.0.1:1/jwks \
 1056f30855bd >/dev/null; for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:13777/api/admin/health | grep -qE "^(200|401|503)" && break; done; docker logs a24-api 2>&1 | tail -4 | cut -c1-220
