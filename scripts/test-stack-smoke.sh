#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

required_services=(
  "gateway"
  "management-api"
  "ocsp-pq"
  "pki-dist"
  "crl-renewer"
  "shadow-mock"
)

echo "[smoke] Checking required service containers are running..."
for svc in "${required_services[@]}"; do
  cid=$(docker compose ps -q "$svc")
  if [ -z "$cid" ]; then
    echo "[smoke] Service has no container: $svc"
    exit 1
  fi

  state=$(docker inspect -f '{{.State.Status}}' "$cid")
  if [ "$state" != "running" ]; then
    echo "[smoke] Service is not running: $svc (state=$state)"
    exit 1
  fi

done

echo "[smoke] Checking gateway health status (if healthcheck is defined)..."
gateway_cid=$(docker compose ps -q gateway)
gateway_health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$gateway_cid")
if [ "$gateway_health" = "unhealthy" ]; then
  echo "[smoke] gateway healthcheck is unhealthy"
  exit 1
fi

echo "[smoke] OK"
