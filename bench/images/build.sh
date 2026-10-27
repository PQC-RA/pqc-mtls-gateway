#!/usr/bin/env bash
# build.sh: the test-only images the edge and migration tests use.
#   pqc-test-modbus:local    bench/edge/edge-link-test.sh
#   pqc-test-chromium:local  bench/migration/real-clients.sh (REAL_CLIENTS=1)
# The other real-client images (python, eclipse-temurin, curlimages/curl) are
# pulled from Docker Hub as named in real-clients.sh.
set -euo pipefail
cd "$(dirname "$0")"
docker build -t pqc-test-modbus:local modbus
docker build -t pqc-test-chromium:local chromium
