#!/usr/bin/env bash
# collect_logs.sh: copies the stack's logs into results/logs/, key-free and token-free.
# admin-actions.log is reduced to ts, action, target and HTTP status (its params carry token-id
# prefixes and reservation ids, its actor the admin fingerprint).
set -euo pipefail
D=/root/rerun-stack-20261107; L=$D/results/logs; mkdir -p "$L"
V=/var/lib/docker/volumes
docker logs -t pqc-ca-custodian > "$L/custodian.log" 2>&1
docker logs -t pqc-mtls-management-api 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$L/management-api.log"
docker logs -t pqc-gateway > "$L/gateway-stdout.log" 2>&1
for f in pqc-enroll-access.log pqc-mtls-access.log error.log pqc-enroll-error.log pqc-enroll-handshake.log; do
  cp "$V/rs1107_pqc-logs-nginx/_data/$f" "$L/$f"; done
cp "$V/rs1107_pqc-logs-audit/_data/enroll-audit.log" "$L/enroll-audit.log"
python3 -I -c 'import json,sys
for l in open(sys.argv[1]):
    d=json.loads(l)
    print(json.dumps({"seq":d.get("seq"),"ts":d.get("ts"),"action":d.get("action"),"target":d.get("target"),
                      "status":(d.get("result") or {}).get("status"),"httpStatus":(d.get("result") or {}).get("httpStatus")}))' \
  "$V/rs1107_pqc-mgmt-data/_data/admin-actions.log" > "$L/admin-actions.sanitized.ndjson"
# refuse anything that looks like key material or a token
if grep -rlE 'PRIVATE KEY|enroll_[A-Za-z0-9_-]{6,}|"token"|enrollmentToken|Bearer |eyJ[A-Za-z0-9_-]{20,}' "$L"; then
  echo "collect_logs: ABORT: secret-like content in the files above" >&2; exit 1; fi
echo "logs in $L"
