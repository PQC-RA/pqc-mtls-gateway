#!/usr/bin/env bash
# re-apply-route.sh: (re)create the bench-client route.
#
# With the shipped compose the management-api stores routing in Redis, so a
# route survives a restart and this is only needed after a teardown or on a
# deployment with REDIS_URL unset, where the store falls back to memory and
# the route is lost when the container restarts. preflight.sh points here when
# it finds the route missing. Idempotent; safe to re-run.
#
# Usage: ./re-apply-route.sh [cn] [backend]
set -euo pipefail
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
CN="${1:-bench-client}"
BACKEND="${2:-http://shadow-mock:80}"

timeout 25 curl -sk --cacert /etc/pki/pqc-ca/ca-chain.crt \
  --cert "$REPO/admin-cert/gateway-admin.crt" \
  --key  "$REPO/admin-cert/gateway-admin.key" \
  -H "X-PQC-CSRF:1" \
  -X PUT "https://127.0.0.1/admin/policy/routes/$CN" \
  -H "Content-Type: application/json" \
  -d "{\"backend\":\"$BACKEND\",\"rate_limit\":{\"rps\":100000,\"burst\":200000},\"allowed_paths\":[\"/api/\",\"/status/\"]}" \
  -o /dev/null -w "PUT $CN -> %{http_code}\n"
