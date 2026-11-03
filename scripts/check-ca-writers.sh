#!/usr/bin/env bash
# check-ca-writers.sh: one writer of CA state (ADR-024). Every shell script in
# this repository that runs `openssl ca` against the deployment's own CA (it
# names the custodian's state or configuration, or the pre-ADR-024 tree's
# intermediate) must take the custodian's writer lock (ca_take_writer_lock),
# so it refuses while the custodian runs. Exceptions are named below, each
# with its reason. Fails, naming the script, otherwise.
#
# Usage: check-ca-writers.sh [FILE...]   (default: every *.sh git tracks)
set -euo pipefail
cd "$(dirname "$0")/.."

# Not held to the rule, and why.
declare -A EXCEPT=(
    ["scripts/setup-pki.sh"]="the bootstrap: runs before any custodian exists, and refuses on a deployment that has one"
    ["scripts/migrate-ca-state.sh"]="the migration tool: takes the writer lock itself (take_writer_lock), and the old system's lock"
    ["bench/adr024/run-migrate-ca-state-unit.sh"]="offline test: a throwaway container with no custodian"
    ["scripts/stand-up.sh"]="refuses to run (TEMPORARY, stand tooling not ported; its own exit criterion)"
    ["bench/edge/edge-link-test.sh"]="openssl ca only on a CA of its own under its work directory; the live tree is a read-only mount"
    ["bench/migration/migration-listener-test.sh"]="openssl ca only on CAs of its own under its work directory; the live tree is a read-only mount"
    ["bench/item4/unique-subject-rehearsal.sh"]="openssl ca only on scratch copies; the live state is hashed, read-only, to prove it unchanged"
)
LIVE='CA_CNF_FILE|CA_STATE_DIR|/var/lib/pqc-ca/state|\$PKI/intermediate|\$PKI_DIR/intermediate|/etc/pki/pqc-ca/intermediate'
bad=0
while IFS= read -r f; do
    grep -qE '(^|[^[:alnum:]_-])ca -config|"ca", "-config"' "$f" || continue
    grep -qE "$LIVE" "$f" || continue
    if [ -n "${EXCEPT[$f]:-}" ]; then echo "  exception  $f: ${EXCEPT[$f]}"; continue; fi
    if grep -q 'ca_take_writer_lock' "$f"; then echo "  ok         $f (takes the writer lock)"; continue; fi
    echo "  VIOLATION  $f runs openssl ca on the live CA without the writer lock"
    bad=1
done < <(if [ $# -gt 0 ]; then printf '%s\n' "$@"; else git ls-files '*.sh'; fi)
exit "$bad"
