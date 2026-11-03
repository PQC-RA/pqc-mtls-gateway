#!/usr/bin/env bash
# Offline unit test of custodian.js (item 4). Since ADR-024 the custodian runs on
# its own layout, so bench/item4/custodian-unit.js is run by
# bench/adr024/run-custodian-crl-unit.sh, which builds that layout with
# setup-pki.sh and checks the CRL issuer as well. This wrapper is kept so the
# old entry point still works.
# Usage: run-custodian-unit.sh [ignored-pki-dir] <custodian-image>
set -euo pipefail
IMG=${2:-${1:?usage: run-custodian-unit.sh [pki-dir] <custodian-image>}}
exec "$(dirname "$0")/../adr024/run-custodian-crl-unit.sh" "$IMG"
