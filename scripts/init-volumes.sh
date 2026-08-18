#!/bin/bash
# Initialize Docker named volumes used by docker-compose.yml.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

echo "Starting volume initialization..."

CONTAINER_NAME="pqc-volume-init"

cleanup() {
	docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

cleanup

docker container create \
	--name "$CONTAINER_NAME" \
	-v pqc-www-pki:/var/www/pki \
	-v pqc-logs-audit:/var/log/audit \
	-v pqc-logs-crl:/var/log/crl \
	-v pqc-mgmt-data:/var/lib/pqc-mgmt \
	-v pqc-signals:/signals \
	alpine >/dev/null

if [ -d /var/www/pki ]; then
	echo "Seeding pqc-www-pki from /var/www/pki..."
	docker cp /var/www/pki/. "$CONTAINER_NAME":/var/www/pki/
else
	echo "Skipping /var/www/pki seed (directory not found on host)."
fi

cleanup

# Seed initial log files CREATE-IF-MISSING. `touch` creates a missing file but
# never truncates an existing one, so re-running this script (e.g. via deploy.sh)
# can never wipe audit or log history. Done with `docker run` per volume rather
# than `docker cp` (which OVERWRITES the destination and would erase history).
#
# The gateway's nginx workers run as uid 65534 (nobody) under a read-only rootfs.
# They APPEND audit lines (the njs data-plane logger and the :8443/enroll
# log_by_lua hook) but cannot CREATE files, because /var/log/pqc-gw is
# root-owned. Pre-seeding the files owned by 65534 lets them append without
# directory write or running as root. (docker-compose's gateway-volume-init does
# the same self-heal on every `up`; this keeps a standalone path too.)
echo "Seeding log volumes with initial files (create-if-missing)..."
docker run --rm -v pqc-logs-audit:/var/log/audit alpine sh -c \
	"touch /var/log/audit/enroll-audit.log && \
	 chown 65534:65534 /var/log/audit/enroll-audit.log && \
	 chmod 644 /var/log/audit/enroll-audit.log"
docker run --rm -v pqc-logs-crl:/var/log/crl alpine sh -c \
	"touch /var/log/crl/crl-renewal.log"
# management-api runs as uid:gid 1001:1001, it must be able to write
# routes.json and the CRL renew sentinel to these two volumes.
echo "Setting ownership on management-api volumes..."
docker run --rm \
	-v pqc-mgmt-data:/var/lib/pqc-mgmt \
	-v pqc-signals:/signals \
	alpine sh -c "chown -R 1001:1001 /var/lib/pqc-mgmt /signals && chmod 775 /var/lib/pqc-mgmt /signals"

echo "Done initializing volumes."
