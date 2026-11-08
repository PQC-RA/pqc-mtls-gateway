#!/usr/bin/env bash
# teardown.sh: removes the throwaway stack rs1107 and its key material; keeps tools/ and results/.
# Touches only project rs1107 (its containers, networks, volumes), the image tags it built,
# the management-api image it pulled, and files under /root/rerun-stack-20261107.
set -euo pipefail
cd /root/rerun-stack-20261107
./compose down -v --remove-orphans
docker image rm rs1107-gateway:83a4f60 rs1107-ocsp-pq:83a4f60 rs1107-pki-dist:83a4f60 rs1107-ca-custodian:83a4f60 || true
docker image rm ghcr.io/pqc-ra/pqc-mtls-management-api@sha256:7787047a71a85e758abea267f69b062d48a366ebce1b5c73bb45244883f276d4 || true
# key material: overwrite every key file, then remove the trees that held it
find /root/rerun-stack-20261107/host /root/rerun-stack-20261107/devices /root/rerun-stack-20261107/repo/secrets \
     /root/rerun-stack-20261107/repo/admin-cert -type f \( -name '*.key' -o -name '*.pem' \) -exec shred -u {} +
rm -rf /root/rerun-stack-20261107/host /root/rerun-stack-20261107/devices /root/rerun-stack-20261107/repo/admin-cert
find /root/rerun-stack-20261107/repo/secrets -mindepth 1 ! -name .gitignore -delete
echo "left: $(find /root/rerun-stack-20261107 -name '*.key' | wc -l) key files"
docker ps -a --filter label=com.docker.compose.project=rs1107 --format '{{.Names}}'
docker volume ls --filter label=com.docker.compose.project=rs1107 --format '{{.Name}}'
docker network ls --filter label=com.docker.compose.project=rs1107 --format '{{.Name}}'
