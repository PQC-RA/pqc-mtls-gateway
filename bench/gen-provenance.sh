#!/usr/bin/env bash
# gen-provenance.sh: capture the testbed state into PROVENANCE.md.
# Re-run this at the START of every campaign; the file is the citation record.
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
# Where this harness reads and writes its own working files. Defaults to the
# directory the scripts live in, so the tree works wherever it is checked out.
WORKDIR="${WORKDIR:-$BENCH_HOME}"
# The issued client identity for the live-gateway arms (see bench/README.md).
EXPORT_DIR="${EXPORT:-/root/measure-export}"
cd "$(dirname "$0")"
# The repository this harness lives in: admin-cert/, scripts/ and secrets/.
REPO=${REPO:-$(cd "$BENCH_HOME/.." && pwd)}
OSSL=/opt/openssl/bin/openssl
OUT=PROVENANCE.md

CPU=$(lscpu | grep '^Model name' | sed 's/.*:  *//')
CORES=$(nproc)
MEM=$(free -m | awk '/Mem:/{print $2}')
SWAPT=$(free -m | awk '/Swap:/{print $2}')
SWAPU=$(free -m | awk '/Swap:/{print $3}')
AVX=$(grep -qo avx512f /proc/cpuinfo && echo present || echo absent)
OSN=$(grep PRETTY /etc/os-release | cut -d'"' -f2)
KERN=$(uname -r)
SSLV=$($OSSL version)
CURLV=$(/usr/bin/curl -V | head -1 | cut -d' ' -f1-4)
HEAD=$(cd $REPO && git log -1 --pretty=%H)
BR=$(cd $REPO && git branch --show-current)
TREE=$(cd $REPO && [ -z "$(git status --porcelain)" ] && echo clean || echo DIRTY)
CTRS=$(docker ps --format '{{.Names}}' | sort | tr '\n' ' ')
CAFP=$($OSSL x509 -in /etc/pki/pqc-ca/ca-chain.crt -noout -fingerprint -sha256 | sed 's/.*=//')
SER=$($OSSL x509 -in $EXPORT_DIR/client.crt -noout -serial | sed 's/.*=//')
IDX=/etc/pki/pqc-ca/intermediate/db/index.txt
NR=$(grep -c '^R' $IDX 2>/dev/null || echo 0)
NV=$(grep -c '^V' $IDX 2>/dev/null || echo 0)

{
printf '# Benchmark Provenance, %s\n\n' "$(hostname)"
printf '**Generated:** %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '> Every figure produced on this host MUST be cited with this host and date. Do not\n'
printf '> merge it into a table carrying numbers from different hardware without attribution.\n\n'
printf '## Testbed\n\n| Field | Value |\n|---|---|\n'
printf '| Host | %s |\n' "$(hostname)"
printf '| CPU | %s |\n| Cores visible | %s |\n| RAM | %s MiB |\n' "$CPU" "$CORES" "$MEM"
printf '| Swap | %s MiB total, %s MiB in use |\n' "$SWAPT" "$SWAPU"
printf '| AVX-512 | %s |\n| OS | %s |\n| Kernel | %s |\n' "$AVX" "$OSN" "$KERN"
printf '| Virtualization | %s |\n\n' "$(systemd-detect-virt 2>/dev/null || echo unknown)"
printf '## Software\n\n| Field | Value |\n|---|---|\n'
printf '| PQ OpenSSL | %s |\n| curl | %s |\n' "$SSLV" "$CURLV"
printf '| Repo HEAD | `%s` |\n| Branch | %s |\n| Working tree | %s |\n' "$HEAD" "$BR" "$TREE"
printf '| Containers | %s |\n\n' "$CTRS"
printf '## Cryptographic configuration\n\n'
printf '| Arm | Group | Server auth | Client auth |\n|---|---|---|---|\n'
printf '| PQC, live gateway :443 | X25519MLKEM768 | ML-DSA-65 | ML-DSA-65 |\n'
printf '| PQC, hermetic :4433 | X25519MLKEM768 | ML-DSA-65 | ML-DSA-65 |\n'
printf '| Classical, hermetic :4434 | X25519 | ECDSA P-256 | RSA-2048 |\n\n'
printf 'Resumption is DISABLED on every arm: servers run `-no_ticket -no_cache`; the latency probe\n'
printf 'spawns a fresh curl per handshake. Verified, `s_client -reconnect` reports 0 Reused.\n\n'
printf '## PKI\n\n| Field | Value |\n|---|---|\n'
printf '| Intermediate CA SHA-256 | `%s` |\n' "$CAFP"
printf '| Bench client | CN=bench-client, serial %s |\n' "$SER"
printf '| CA index | %s revoked, %s valid |\n\n' "$NR" "$NV"
printf '> This CA is unique to this deployment. Certificates from .22/.23/.24 carry an identical\n'
printf '> subject DN (`CN=PQC-GW PQC Intermediate CA G1`) but a different key, they will NOT\n'
printf '> validate here. Mint client identities against this CA only.\n\n'
printf '## Metric definitions\n\n'
printf '%s\n' '- **Handshake latency** = `time_appconnect - time_connect`, ms (TLS only, TCP excluded).'
printf '  N=220, first 20 discarded -> N=200. 95%% CI = mean +/- 1.96*(sd/sqrt(N)).\n'
printf '%s\n' '- **Throughput** = `openssl s_time -new`. conn/USER-sec is single-core CPU-normalised;'
printf '  conn/REAL-sec is wall-clock wrapped with `date +%%s.%%N` (s_time'"'"'s own real-seconds is\n'
printf '  integer-rounded and too coarse for short windows).\n\n'
printf '## Known caveats for this host\n\n'
# Derive the policy-durability caveat instead of asserting it: the dev compose
# gained a redis service on 2026-07-29, so a hardcoded "no Redis" line is now
# false on any deployment built after that and would misdescribe the testbed.
if docker inspect -f '{{.State.Status}}' pqc-redis 2>/dev/null | grep -q running; then
  printf '%s\n' '- Routing policy is **durable** (`pqc-redis` running) - it survives a management-api restart.'
else
  printf '%s\n' '- Routing policy is **in-memory** (no Redis) - lost on management-api restart.'
fi
printf '%s\n' '- `pqc-shadow-mock` has `restart: no` by design (test-only backend) - it does **not** come'
printf '%s\n' '  back after a reboot, and every request then 502s.'
printf '%s\n' '- Both are checked by `./preflight.sh`. Run it before every campaign.'
} > "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") lines)"
