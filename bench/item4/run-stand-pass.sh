#!/usr/bin/env bash
# run-stand-pass.sh: the whole item-4 stand pass in one run, on the ISOLATED
# stand only, with provenance and a key-free results bundle.
#
# What it records before anything runs:
#   git commit (and whether the tree is dirty) of the gateway tree this file is
#   in; image IDs, digests and revisions of every stand container;
#   hashes of the stand's compose config, nginx.conf and Lua tree as the
#   gateway container sees them; OpenSSL version; the live counters
#   (bench/item4/live-snapshot.sh), read only.
# Then it runs every test in sequence, with gaps for the enrollment rate limit,
# stores each output and exit code, takes the live counters again, writes
# SUMMARY.txt and SHA256SUMS, and packs everything into one tarball. It aborts
# the bundle if any file in it holds a private key.
#
# Usage: run-stand-pass.sh OUTDIR [quick]
#   quick: skip the long runs (concurrency x10, latency x25, keep-alive norevoke)
set -uo pipefail
OUT=${1:?outdir}; MODE=${2:-full}
[ -e "$OUT" ] && { echo "$OUT exists"; exit 2; }
mkdir -p "$OUT/logs"; HERE=$(cd "$(dirname "$0")" && pwd); TREE=$(cd "$HERE/../.." && pwd)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
FIX=$STAND_DIR
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── provenance ────────────────────────────────────────────────────────────────
{
	echo "started            $T0"
	echo "host               $(hostname)"
	if git -C "$TREE" rev-parse --git-dir >/dev/null 2>&1; then
		echo "gateway tree       $TREE $(git -C "$TREE" rev-parse --short HEAD) $(git -C "$TREE" rev-parse --abbrev-ref HEAD) $( [ -z "$(git -C "$TREE" status --porcelain -- . ':!*.out')" ] && echo clean || echo DIRTY)"
	else
		echo "gateway tree       $TREE ${STAND_COMMIT:-unknown} (git archive by stand-up.sh, no local edits possible to record)"
	fi
	[ -n "${API_SRC:-}" ] && echo "management-api src $API_SRC $(git -C "$API_SRC" rev-parse --short HEAD) $( [ -z "$(git -C "$API_SRC" status --porcelain)" ] && echo clean || echo DIRTY)"
	echo "management-api     $(docker inspect -f '{{.Config.Image}}' "$API") (image as pinned or built; see the container line)"
	echo "tree content hash  $(cd "$TREE" && find . -type f ! -path './.git/*' ! -path './secrets/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16) (files under the tree, secrets excluded)"
	echo "openssl            $($O version)"
	for c in $(docker ps --filter label=com.docker.compose.project=$STAND_PROJECT --format '{{.Names}}' | sort); do
		echo "container          $c $(docker inspect -f '{{.Config.Image}} {{.Image}}' "$c" | cut -c1-90) revision=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$(docker inspect -f '{{.Image}}' "$c")" 2>/dev/null)"
	done
	echo "compose config     $($STAND_COMPOSE config 2>/dev/null | sha256sum | cut -c1-16)"
	echo "gateway nginx.conf $(docker exec $GW sha256sum /etc/nginx/nginx.conf | cut -c1-16)"
	echo "gateway lua tree   $(docker exec $GW sh -c 'cd /etc/nginx/lua && cat $(ls *.lua | sort) | sha256sum' | cut -c1-16)"
	echo "stand env          $(tr '\n' ' ' < $FIX/env | sed 's/SECRET[^ ]*//g')"
} > "$OUT/PROVENANCE.txt"
bash "$HERE/live-snapshot.sh" > "$OUT/live-before.txt"
cat "$OUT/PROVENANCE.txt"

# ── runner ────────────────────────────────────────────────────────────────────
printf 'test\texit\tseconds\tsummary\n' > "$OUT/results.tsv"
run(){ # run NAME CMD...
	local n=$1; shift; local t=$(date +%s) rc
	echo "$(date -u +%H:%M:%S) ── $n"
	"$@" > "$OUT/logs/$n.out" 2>&1; rc=$?
	local sum; sum=$(grep -E '== result|^RESULT|result:|passed|Tests:|TESTS OK|CHECK\(S\) FAILED|SKIPPED' "$OUT/logs/$n.out" | tail -1 | tr '\t' ' ' | cut -c1-120)
	printf '%s\t%s\t%s\t%s\n' "$n" "$rc" "$(( $(date +%s) - t ))" "$sum" >> "$OUT/results.tsv"
	echo "      exit $rc  $sum"
}
gap(){ sleep 65; }   # the /enroll limit (5 a minute, burst 3) recovers between tests
waitup(){ for i in $(seq 1 90); do local ok=1
	[ "$(docker inspect -f '{{.State.Health.Status}}' $CUST)" = healthy ] || ok=0
	[ "$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:$STAND_API_PORT/api/admin/health)" != 000 ] || ok=0
	[ $ok = 1 ] && return 0; sleep 2; done; return 1; }
switch(){ # switch on|off: the stand's renewal switch (stage 2 / stage 1 settings)
	if [ "$1" = off ]; then cp -p $FIX/env "$OUT/env.saved"; sed -i 's/^RENEWAL_ENABLED=.*/RENEWAL_ENABLED=/; s/^CUSTODIAN_DEMO_PROFILE=.*/CUSTODIAN_DEMO_PROFILE=/' $FIX/env
	else cp -p "$OUT/env.saved" $FIX/env; fi
	$STAND_COMPOSE up -d --no-deps pqc-ca-custodian management-api > "$OUT/logs/switch-$1.out" 2>&1; waitup
	echo "      switch $1: RENEWAL_ENABLED=[$(docker exec $API printenv RENEWAL_ENABLED)]"
}
custodian_unit(){ local p; p=$(mktemp -d); cp -a $FIX/pki/. "$p/"; bash "$HERE/run-custodian-unit.sh" "$p" "$(docker inspect -f '{{.Config.Image}}' $CUST)"; local rc=$?
	find "$p" -name '*.key' -exec shred -u {} + 2>/dev/null; rm -rf "$p"; return $rc; }
# management-api's own unit tests run in its repository's CI (pqc-mtls-management-api);
# with API_SRC set to a checkout of it they run here too, in a stock Node image.
api_unit(){ [ -n "${API_SRC:-}" ] || { echo "SKIPPED: management-api unit tests run in pqc-mtls-management-api's CI; set API_SRC to run them here"; return 2; }
	docker run --rm -v "$API_SRC:/src:ro" node:22-bookworm-slim sh -c \
		'cp -r /src /w && cd /w && rm -rf node_modules && corepack enable >/dev/null 2>&1 && pnpm install --frozen-lockfile >/dev/null 2>&1 && pnpm exec jest --ci 2>&1 | tail -6'; }

W="$OUT/work"; mkdir -p "$W"
run unit-lua-expiry      bash "$HERE/client-cert-expiry-unit.sh"
run unit-custodian       custodian_unit
run unit-management-api  api_unit
run e2e-renew            bash "$HERE/e2e-renew-stand.sh" "$W/e2e1";                 gap
run e2e-failures         bash "$HERE/e2e-renew-stand-2.sh" "$W/e2e2";               gap
run enroll-acceptance   env ENROLL8443_I_UNDERSTAND=1 ENROLL_PORT=$STAND_ENROLL_PORT ADMIN_PORT=$STAND_TLS_PORT CA=$CA OLD_CA=$STAND_DIR/pki/enroll-classical-ca.crt PKI=$STAND_DIR/pki \
	ADMIN_CRT=$ADM_C ADMIN_KEY=$ADM_K LOG_DIR=$NGINX_LOGS CUSTODIAN=$CUST CN_PREFIX=pass-enroll- bash "$HERE/../test-enroll-8443.sh"; gap
run enroll-reserve-on    bash "$HERE/enroll-reserve-commit-stand.sh" "$W/rc-on" demo-120s; gap
switch off
run enroll-reserve-off   bash "$HERE/enroll-reserve-commit-stand.sh" "$W/rc-off" "";       gap
switch on
run extensions-expiry    bash "$HERE/extensions-expiry-renew-stand.sh" "$W/ext";   gap
run clock-skew           bash "$HERE/clock-skew-stand.sh" "$W/skew";               gap
run keepalive-revoke     bash "$HERE/keepalive-stand.sh" "$W/ka" 200;              gap
run keepalive-expiry     bash "$HERE/keepalive-expiry-stand.sh" "$W/kx" 200;       gap
run keepalive-expiry-h2  bash "$HERE/keepalive-expiry-h2-stand.sh" "$W/kh2" 200;   gap
if [ "$MODE" != quick ]; then
	run keepalive-norevoke bash "$HERE/keepalive-stand.sh" "$W/kan" 320 norevoke;  gap
	run concurrency-x10    bash "$HERE/concurrency-repeat-stand.sh" "$W/cc" 10;     gap
	run renew-ambiguous    bash "$HERE/renew-ambiguous-stand.sh" "$W/amb" 2;        gap
	run latency-25         bash "$HERE/renew-latency-stand.sh" "$W/lat" 25;         gap
fi
run unique-subject       bash "$HERE/unique-subject-rehearsal.sh" "/var/tmp/stand-pass-us-$(date +%s)"
run rollback             bash "$HERE/rollback-rehearsal-stand.sh" "$W/rb"

# ── close ─────────────────────────────────────────────────────────────────────
bash "$HERE/live-snapshot.sh" > "$OUT/live-after.txt"
python3 -I - "$OUT/live-before.txt" "$OUT/live-after.txt" > "$OUT/live-check.txt" <<'PY'
import sys
def parse(p):
    d = {}
    for l in open(p):
        f = l.split()
        if f[0] == "live": d[" ".join(f[:2])] = " ".join(f[2:])
        elif "local" in f: d[f[0] + " local"] = f[f.index("local") + 1]
        elif f[0] in ("audit", "created"): d[" ".join(f[:2])] = " ".join(f[2:])
    return d
if open(sys.argv[1]).read().startswith("no live"): print("no live gateway on this host"); sys.exit()
a, b = parse(sys.argv[1]), parse(sys.argv[2])
bad = [k for k in a if a[k] != b.get(k)]
print("LIVE UNCHANGED (index, attr, serial, audit, containers, log lines from this host)" if not bad else "LIVE CHANGED: " + ", ".join(bad))
PY
{
	echo "item-4 stand pass, $T0 to $(date -u +%Y-%m-%dT%H:%M:%SZ), mode $MODE"
	echo; cat "$OUT/PROVENANCE.txt"; echo
	column -t -s $'\t' "$OUT/results.tsv"; echo
	echo "tests with exit 0: $(awk -F'\t' 'NR>1 && $2==0' "$OUT/results.tsv" | wc -l) of $(( $(wc -l < "$OUT/results.tsv") - 1 ))"
	cat "$OUT/live-check.txt"
} > "$OUT/SUMMARY.txt"
# Bundle: logs, summary, provenance, live snapshots; work dirs without keys.
find "$W" -type f \( -name '*.key' -o -name 'identity.pem*' -o -name 'pending.key*' \) -exec shred -u {} + 2>/dev/null
# Anything else in the work tree that still holds a private key is shredded too, and listed.
grep -rlE 'BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY' "$W" 2>/dev/null | tee "$OUT/shredded-extra.txt" | xargs -r shred -u
# Nested archives (the rollback's key-free state backup) are opened and scanned too.
NEST=$(mktemp -d); find "$OUT" -type f \( -name '*.tgz' -o -name '*.tar.gz' \) | while read -r a; do
	d="$NEST/$(echo "$a" | sha256sum | cut -c1-12)"; mkdir -p "$d"; tar -xzf "$a" -C "$d" 2>/dev/null || true; done
if grep -rlE 'BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY' "$OUT" "$NEST" > "$OUT/key-scan.txt" 2>/dev/null; then
	rm -rf "$NEST"
	echo "BUNDLE ABORTED: private key material found:"; cat "$OUT/key-scan.txt"; exit 3
fi
rm -rf "$NEST"; rm -f "$OUT/key-scan.txt"
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")"
echo; cat "$OUT/SUMMARY.txt"; echo; echo "bundle: $OUT.tar.gz ($(du -h "$OUT.tar.gz" | cut -f1)), sha256 $(sha256sum "$OUT.tar.gz" | cut -c1-16)"
