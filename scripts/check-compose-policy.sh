#!/usr/bin/env bash
# check-compose-policy.sh: static checks of the resolved compose file against
# ADR-024 (test 4). Fails if:
#   - a service other than pqc-ca-custodian mounts the custodian's key, state
#     or inbox directory;
#   - any service mounts anything from the CA tree /etc/pki/pqc-ca (not even a
#     single public certificate), an empty-directory mask (/etc/pki/pqc-empty)
#     or a /signals volume;
#   - any service mounts the trust directory /etc/pki/pqc-trust other than
#     whole and read-only (ADR-024 §3: public certificates only, replaced by
#     rename, so never a single file);
#   - any service sets CUSTODIAN_TEST_FAULT (test-only fault injection);
#   - a service runs as root, without a read-only rootfs, without cap_drop ALL,
#     with an added capability or without no-new-privileges, unless it is a
#     named exception below. The CA path (custodian, ocsp-pq, pki-dist) never is.
#
# Usage: check-compose-policy.sh [compose file ...]   (default docker-compose.yml)
# Needs docker compose (no images are pulled) and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
FILES=("$@"); [ ${#FILES[@]} -gt 0 ] || FILES=(docker-compose.yml)
ARGS=(); for f in "${FILES[@]}"; do ARGS+=(-f "$f"); done
# Unset variables only produce warnings; their values do not matter here.
docker compose "${ARGS[@]}" config --format json 2>/dev/null | python3 -I -c '
import json, sys
cfg = json.load(sys.stdin)
CA_PATH = {"pqc-ca-custodian", "ocsp-pq", "pki-dist"}
CUSTODIAN_ONLY = ("/var/lib/pqc-ca/key", "/var/lib/pqc-ca/state", "/var/lib/pqc-ca/inbox")
# Services that do not meet the non-root / read-only / no-capability rule yet.
# Each one is a named exception with its exit criterion; a new service cannot
# join this list without a reviewer seeing it.
EXCEPTIONS = {
    "gateway": "nginx master as root with added capabilities; its own ADR (ADR-024 owner decision 2)",
    "redis": "added capabilities; its own ADR (ADR-024 owner decision 2)",
    "gateway-volume-init": "one-shot root helper that chowns a volume; its own ADR (ADR-024 owner decision 2)",
    "mgmt-volume-init": "one-shot root helper that chowns a volume; its own ADR (ADR-024 owner decision 2)",
    "shadow-mock": "a test backend, not part of a deployment",
}
bad = []
for name, svc in sorted(cfg.get("services", {}).items()):
    for v in svc.get("volumes", []):
        src, dst = v.get("source", ""), v.get("target", "")
        if src.startswith(CUSTODIAN_ONLY) and name != "pqc-ca-custodian":
            bad.append(f"{name}: mounts the custodian\x27s {src}")
        if src == "/etc/pki/pqc-ca" or src.startswith("/etc/pki/pqc-ca/"):
            bad.append(f"{name}: mounts from the CA tree: {src}")
        if src == "/etc/pki/pqc-trust" or src.startswith("/etc/pki/pqc-trust/"):
            if src != "/etc/pki/pqc-trust":
                bad.append(f"{name}: mounts a single file from the trust directory: {src} (mount the directory)")
            if not v.get("read_only"):
                bad.append(f"{name}: mounts the trust directory {src} writable")
        if src.startswith("/etc/pki/pqc-empty"):
            bad.append(f"{name}: empty-directory mask {src} -> {dst}")
        if dst == "/signals" or v.get("source") == "pqc-signals":
            bad.append(f"{name}: /signals volume")
    if "CUSTODIAN_TEST_FAULT" in (svc.get("environment") or {}):
        bad.append(f"{name}: sets CUSTODIAN_TEST_FAULT (test-only)")
    user = str(svc.get("user", ""))
    problems = []
    if not user or user.split(":")[0] in ("0", "root"):
        problems.append("runs as root")
    if not svc.get("read_only"):
        problems.append("rootfs not read-only")
    if "ALL" not in (svc.get("cap_drop") or []):
        problems.append("no cap_drop ALL")
    if svc.get("cap_add"):
        problems.append("cap_add " + ",".join(svc["cap_add"]))
    if "no-new-privileges:true" not in (svc.get("security_opt") or []):
        problems.append("no no-new-privileges")
    if problems:
        if name in CA_PATH or name not in EXCEPTIONS:
            bad.append(f"{name}: " + "; ".join(problems))
        else:
            joined = "; ".join(problems)
            print(f"  exception  {name}: {joined}  [{EXCEPTIONS[name]}]")
    elif name in EXCEPTIONS:
        bad.append(f"{name}: meets the rule now; remove it from EXCEPTIONS")
    else:
        print(f"  ok         {name}")
for b in bad:
    print(f"  VIOLATION  {b}")
sys.exit(1 if bad else 0)
'
