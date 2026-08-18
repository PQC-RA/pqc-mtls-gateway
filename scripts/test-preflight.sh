#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

echo "[preflight] Checking Docker CLI..."
command -v docker >/dev/null || {
  echo "[preflight] docker is not installed or not in PATH"
  exit 1
}

echo "[preflight] Checking Docker daemon..."
docker info >/dev/null 2>&1 || {
  echo "[preflight] Docker daemon is not reachable"
  exit 1
}

echo "[preflight] Checking Docker Compose..."
docker compose version >/dev/null || {
  echo "[preflight] docker compose plugin is unavailable"
  exit 1
}

echo "[preflight] Checking required files..."
required_files=(
  "docker-compose.yml"
  "docker/base/openssl/Dockerfile"
  "scripts/build-all.sh"
  "scripts/init-volumes.sh"
)

for f in "${required_files[@]}"; do
  if [ ! -e "$f" ]; then
    echo "[preflight] Missing required file: $f"
    exit 1
  fi
done

echo "[preflight] Validating compose config..."
docker compose config >/dev/null

echo "[preflight] OK"
