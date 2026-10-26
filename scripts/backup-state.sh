#!/usr/bin/env bash
# backup-state.sh: key-free state backup of the gateway stack, with a test
# restore into a scratch directory (item 4, ADR-019 decision 7).
#
# It NEVER writes a private key. Keys live only in the encrypted keys set
# (ADR-018). Everything that can hold one is excluded by path and name, and
# every file is scanned for a PEM private-key header BEFORE it is archived; one
# hit aborts the run with nothing archived.
#
# What it saves (state, not secrets):
#   pki/        the CA tree without private/ and *.key: index, serial, crlnumber,
#               index.txt.attr, lineage.json, idempotency.json, fingerprint index,
#               issued certificates, CRLs, chains, CA configs
#   ssl/        public certificates only
#   redis.rdb   a consistent snapshot over the protocol (it holds bootstrap
#               tokens, so the backup directory is 0700)
#   volumes     routes, admin audit, signals, audit/CRL logs, pki-dist
#   compose     the resolved compose config and its sha256, image IDs, git heads
#
# Test restore (into a scratch directory, never over the stack):
#   archives extract; the index parses; each CRL verifies against the restored
#   chain; redis-check-rdb passes; the recorded compose hash equals a fresh one.
#
# Usage: backup-state.sh live|stand OUTDIR
#   stand  the isolated pqcfix stack (/root/pqcfix, containers pqcfix-*)
#   live   the pqc-gw stack (/etc/pki/pqc-ca, containers pqc-*); run only with
#          the owner's yes for the stage it precedes
set -euo pipefail
TARGET=${1:?live|stand}; OUT=${2:?outdir}
O=${OPENSSL:-/opt/openssl-3.6.2/bin/openssl}; export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-/opt/openssl-3.6.2/lib64} OPENSSL_CONF=/dev/null
case "$TARGET" in
stand)
	PKI=/root/pqcfix/pki; SSL=/root/pqcfix/ssl; PREFIX=pqcfix; VOLP=pqcfix
	COMPOSE=(/root/pqcfix/fixc) ;;
live)
	PKI=/etc/pki/pqc-ca; SSL=/etc/ssl/pqc; PREFIX=pqc; VOLP=pqc-gw
	COMPOSE=(docker compose -p pqc-gw --project-directory /root/pqc-tls-gateway) ;;
*) echo "target must be live or stand" >&2; exit 2 ;;
esac
TS=$(date -u +%Y%m%dT%H%M%SZ)
B="$OUT/state-$TARGET-$TS"
umask 077; mkdir -p "$B"; chmod 700 "$B"
echo "backup dir: $B"

# Names and paths that may hold key material; excluded from every archive.
EXCL=(--exclude='*/private' --exclude='*/private/*' --exclude='*.key' --exclude='*.key.*' --exclude='secrets' --exclude='*.p12' --exclude='*.pfx')

scan() { # scan DIR...: abort if any file outside the exclusions holds a private key
	local hits
	hits=$(find "$@" \( -name private -o -name '*.key' -o -name '*.key.*' -o -name secrets -o -name '*.p12' -o -name '*.pfx' \) -prune -o -type f -print0 \
		| xargs -0 -r grep -l -E -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN ENCRYPTED PRIVATE KEY-----' 2>/dev/null || true)
	if [ -n "$hits" ]; then
		echo "ABORT: private key material outside the excluded paths (nothing archived for this set):" >&2
		echo "$hits" >&2
		exit 3
	fi
}

# 1. CA tree and public server certificates
scan "$PKI" "$SSL"
tar -C "$(dirname "$PKI")" --numeric-owner "${EXCL[@]}" -czpf "$B/pki.tgz" "$(basename "$PKI")"
tar -C "$(dirname "$SSL")" --numeric-owner "${EXCL[@]}" -czpf "$B/ssl.tgz" "$(basename "$SSL")"

# 2. Redis, consistent snapshot over the protocol
docker exec "$PREFIX-redis" redis-cli --rdb - > "$B/redis.rdb" 2>/dev/null

# 3. Small named volumes (logs and state, no keys); nginx logs included
for v in pqc-mgmt-data pqc-routes-cache pqc-signals pqc-logs-audit pqc-logs-crl pqc-www-pki pqc-logs-nginx; do
	d="/var/lib/docker/volumes/${VOLP}_$v"
	[ -d "$d" ] || continue
	scan "$d/_data"
	tar -C "$d" --numeric-owner "${EXCL[@]}" -czpf "$B/vol-$v.tgz" _data
done

# 4. What was running: resolved compose config, image IDs, git heads
"${COMPOSE[@]}" config > "$B/compose-config.yml" 2>/dev/null
sha256sum < "$B/compose-config.yml" | cut -d' ' -f1 > "$B/compose-config.sha256"
docker ps -a --filter "label=com.docker.compose.project=$( [ "$TARGET" = stand ] && echo pqcfix || echo pqc-gw )" \
	--format '{{.Names}} {{.Image}} {{.ID}}' > "$B/containers.txt"
while read -r name image _; do echo "$name $(docker inspect -f '{{.Image}}' "$name")"; done < "$B/containers.txt" > "$B/image-ids.txt"
for r in /root/pqc-tls-gateway /root/pqc-tls-gateway-fix /root/mgmt-api-src /root/pqc-mtls-gateway; do
	[ -d "$r/.git" ] || [ -f "$r/.git" ] || continue
	echo "$r $(git -C "$r" rev-parse HEAD) $(git -C "$r" branch --show-current)"
done > "$B/git-heads.txt"

# 5. Final guard over the archives themselves
for t in "$B"/*.tgz; do
	if tar -xzOf "$t" 2>/dev/null | grep -q -E -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'; then
		echo "ABORT: $t contains private key material" >&2; exit 3
	fi
	if tar -tzf "$t" | grep -E '(^|/)private(/|$)|\.key$' >/dev/null; then
		echo "ABORT: $t lists a key path" >&2; exit 3
	fi
done

# 6. Test restore into a scratch directory
R=$(mktemp -d "$OUT/restore-test-XXXX"); fail=0
for t in "$B"/*.tgz; do mkdir -p "$R/$(basename "$t" .tgz)"; tar -C "$R/$(basename "$t" .tgz)" -xzf "$t" || { echo "EXTRACT FAILED: $t"; fail=1; }; done
IDX="$R/pki/$(basename "$PKI")/intermediate/db/index.txt"
if awk -F'\t' 'NF != 6 || $1 !~ /^[VRE]$/ { bad++ } END { exit bad > 0 }' "$IDX"; then
	echo "index parses: $(wc -l < "$IDX") rows ($(awk -F'\t' '$1=="V"' "$IDX" | wc -l) V, $(awk -F'\t' '$1=="R"' "$IDX" | wc -l) R, $(awk -F'\t' '$1=="E"' "$IDX" | wc -l) E)"
else echo "INDEX DOES NOT PARSE"; fail=1; fi
CHAIN="$R/pki/$(basename "$PKI")/ca-chain.crt"
for crl in "$R/pki/$(basename "$PKI")/intermediate/crl/intermediate-ca.crl" "$R/pki/$(basename "$PKI")/root/crl/root-ca.crl"; do
	[ -f "$crl" ] || continue
	if "$O" crl -in "$crl" -noout -CAfile "$CHAIN" 2>&1 | grep -q "verify OK"; then echo "CRL verifies: ${crl#$R/pki/}"; else echo "CRL DOES NOT VERIFY: $crl"; fail=1; fi
done
for j in lineage.json idempotency.json fingerprint-index.json; do
	f="$R/pki/$(basename "$PKI")/intermediate/db/$j"; [ -f "$f" ] || continue
	python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$f" && echo "$j parses" || { echo "$j DOES NOT PARSE"; fail=1; }
done
docker run --rm --network none -v "$B/redis.rdb:/b/redis.rdb:ro" redis:7.4-alpine redis-check-rdb /b/redis.rdb > "$B/redis-check.txt" 2>&1 || true
grep -q "RDB looks OK" "$B/redis-check.txt" && echo "redis rdb OK" || { echo "REDIS RDB CHECK FAILED"; fail=1; }
[ "$("${COMPOSE[@]}" config 2>/dev/null | sha256sum | cut -d' ' -f1)" = "$(cat "$B/compose-config.sha256")" ] && echo "compose config hash matches" || { echo "COMPOSE CONFIG CHANGED DURING BACKUP"; fail=1; }
grep -r -l -E -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$R" >/dev/null 2>&1 && { echo "PRIVATE KEY FOUND IN RESTORE"; fail=1; } || echo "no private key in the restored tree"
echo "restore test dir: $R (left for inspection)"

(cd "$B" && sha256sum -- * > SHA256SUMS)
du -sh "$B" | cut -f1 | sed 's/^/size: /'
[ "$fail" = 0 ] && echo "STATE BACKUP OK: $B" || { echo "*** STATE BACKUP VERIFICATION FAILED: $B ***"; exit 1; }
