#!/bin/bash
# Initialize Docker named volumes used by docker-compose.yml.
# (The CA directories are host directories made by scripts/setup-pki.sh,
# ADR-024; nothing here touches them.)

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

echo "Starting volume initialization..."

echo "Seeding log volumes with initial files (create-if-missing)..."
docker run --rm -v pqc-logs-audit:/var/log/audit alpine sh -c \
	"touch /var/log/audit/enroll-audit.log && \
	 chown 65534:65534 /var/log/audit/enroll-audit.log && \
	 chmod 644 /var/log/audit/enroll-audit.log"

echo "Setting ownership on management-api volumes..."
docker run --rm \
	-v pqc-mgmt-data:/var/lib/pqc-mgmt \
	alpine sh -c "chown -R 1001:1001 /var/lib/pqc-mgmt && chmod 775 /var/lib/pqc-mgmt"

echo "Done initializing volumes."
