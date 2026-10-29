#!/usr/bin/env bash
# check-secrets.sh: every secret file docker-compose.yml names (its `secrets:`
# files and the ./secrets/* bind mounts) exists and is not empty. Run it before
# `docker compose up`; deploy.sh does. Compose itself stops on a missing secret
# file with a message that does not say how to create it.
#
#   scripts/check-secrets.sh [COMPOSE_FILE]
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
F=${1:-$ROOT_DIR/docker-compose.yml}
cd "$(dirname "$F")"
missing=0
for s in $( { sed -n 's/^[[:space:]]*file:[[:space:]]*\(\.\/secrets\/[^[:space:]]*\).*/\1/p' "$F"
             sed -n 's/^[[:space:]]*-[[:space:]]*\(\.\/secrets\/[^:]*\):.*/\1/p' "$F"; } | sort -u); do
	if [ ! -s "$s" ]; then
		echo "MISSING: $s" >&2; missing=1
	fi
done
if [ "$missing" = 1 ]; then
	echo "" >&2
	echo "docker-compose.yml needs the secret files above and will not start without them." >&2
	echo "Create them with scripts/generate-gateway-secrets.sh (it keeps every existing key;" >&2
	echo "gateway-signing-key-admin-v2.key needs an OpenSSL 3.5+). New keys join the encrypted" >&2
	echo "keys set together with the internal TLS CA and :8081 keys." >&2
	exit 1
fi
echo "secrets: all files named by $(basename "$F") are present"
