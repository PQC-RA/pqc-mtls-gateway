#!/usr/bin/env bash
# stand-down.sh: remove a stand made by scripts/stand-up.sh: its containers,
# networks and named volumes, then its directory (private keys shredded first).
# Refuses a live project (LIVE_PROJECTS, and that of a running pqc-gateway) and
# any directory without the stand.env that stand-up.sh writes.
#   stand-down.sh STAND_DIR
set -euo pipefail
SD=${1:?STAND_DIR}
[ -f "$SD/stand.env" ] || [ -f "$SD/compose" ] || { echo "stand-down: $SD is not a stand-up.sh stand" >&2; exit 1; }
P=$(sed -n 's/^name: //p' "$SD/compose.override.yml" | head -1)
LIVE="${LIVE_PROJECTS:-pqc-gw pqc-mtls-gateway} $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' pqc-gateway 2>/dev/null || true)"
case " $LIVE " in *" $P "*) echo "stand-down: refusing live project '$P'" >&2; exit 1;; esac
[ -n "$P" ] || { echo "stand-down: no project in $SD" >&2; exit 1; }
"$SD/compose" down -v --remove-orphans > "/tmp/stand-down-$P.log" 2>&1 || { tail -20 "/tmp/stand-down-$P.log"; exit 1; }
find "$SD" -name '*.key' -type f -exec shred -u {} + 2>/dev/null || true
rm -rf "$SD"
echo "stand $P removed"
