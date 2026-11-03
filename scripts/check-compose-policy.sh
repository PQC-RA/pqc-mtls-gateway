#!/usr/bin/env bash
# check-compose-policy.sh: static checks of the resolved compose file against
# ADR-024 (test 4). Fails if:
#   - a service other than pqc-ca-custodian mounts the custodian's key, state
#     or inbox directory, the custodian mounts its key directory writable, or
#     any service mounts a PARENT of a protected directory (the custodian's,
#     the CA tree, the OCSP key directory, /etc/ssl/pqc); bind sources are
#     normalised first (//, /./, trailing /);
#   - any service mounts anything from the CA tree /etc/pki/pqc-ca (not even a
#     single public certificate), an empty-directory mask (/etc/pki/pqc-empty)
#     or a /signals volume;
#   - any service mounts the trust directory /etc/pki/pqc-trust other than
#     whole and read-only (ADR-024 §3: public certificates only, replaced by
#     rename, so never a single file);
#   - any service sets CUSTODIAN_TEST_FAULT (test-only fault injection);
#   - a built service has no image: with an explicit tag other than latest (a
#     rollback would otherwise rerun this release's build);
#   - a service runs as root, without a read-only rootfs, without cap_drop ALL,
#     with an added capability or without no-new-privileges, unless it is a
#     named exception below. The CA path (custodian, ocsp-pq, pki-dist) never is;
#   - a named volume binds (o=bind or rbind) a protected path, a parent of one,
#     or a relative device it cannot resolve; a mount uses an external volume;
#   - a top-level secret or config file is under or above a protected path;
#   - a service uses volumes_from the custodian, runs privileged, or shares a
#     PID namespace with the host or the custodian (/proc/<pid>/root reaches
#     the custodian's filesystem).
#
# What it cannot see: a symbolic link on the host (an innocent-looking source
# that points into a protected directory) is resolved by Docker at run time,
# not in the compose file. The runtime check, bench/check-key-isolation.sh
# (verify-suite.sh section 6), scans every container's filesystem and is the
# backstop for that.
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
import os.path
# Directories no container may reach through a mount of a PARENT directory
# (a mount of /var/lib/pqc-ca exposes key/, one of /etc/pki the CA tree).
PROTECTED = CUSTODIAN_ONLY + ("/etc/pki/pqc-ca", "/var/lib/pqc-ocsp", "/etc/ssl/pqc")
def under(p, d):
    return p == d or p.startswith(d + "/")
def parent_of(p, d):
    return p != d and (p == "/" or d.startswith(p + "/"))
import re
VOLS = cfg.get("volumes") or {}
def host_path(v):
    # The host path a mount reads, normalised: a bind source, or the device
    # of a named volume that is a bind (driver_opts o=bind), so neither
    # //var/lib/pqc-ca/key nor a volume with device /var/lib/pqc-ca/key gets
    # past the checks below. normpath keeps exactly two leading slashes
    # (POSIX leaves their meaning to the system), so they are collapsed first.
    # None for an external volume: compose cannot show what it binds.
    src = v.get("source", "")
    if v.get("type") == "volume" and src:
        vol = VOLS.get(src) or {}
        opts = vol.get("driver_opts") or {}
        # bind, rbind, or either among other options: the device is a host path.
        if any("bind" in o.strip() for o in str(opts.get("o", "")).split(",")) and opts.get("device"):
            src = str(opts["device"])
            if not src.startswith("/"):
                return "RELATIVE:" + src
        elif vol.get("external"):
            return None
    if src.startswith("/"):
        src = os.path.normpath(re.sub(r"^/+", "/", src))
    return src
bad = []
# Secrets and configs with file: are bind-mounted into the services that use them.
for kind in ("secrets", "configs"):
    for sname, sdef in sorted((cfg.get(kind) or {}).items()):
        f = str((sdef or {}).get("file") or "")
        if not f:
            continue
        f = os.path.normpath(re.sub(r"^/+", "/", f)) if f.startswith("/") else f
        for d in PROTECTED:
            if under(f, d) or parent_of(f, d):
                bad.append(f"{kind[:-1]} {sname}: file {f} is under or above the protected {d}")
CUSTODIAN = "pqc-ca-custodian"
for name, svc in sorted(cfg.get("services", {}).items()):
    # Ways into another container that are not mounts: its volumes, its
    # processes (/proc/<pid>/root reaches its filesystem, key included), or
    # everything (privileged).
    for vf in svc.get("volumes_from") or []:
        ref = str(vf).split(":")
        target = ref[1] if len(ref) > 1 and ref[0] in ("service", "container") else ref[0]
        if target == CUSTODIAN:
            bad.append(f"{name}: volumes_from the custodian ({vf})")
    if svc.get("privileged"):
        bad.append(f"{name}: privileged")
    pid = str(svc.get("pid") or "")
    if pid == "host" or (pid.split(":", 1)[-1] == CUSTODIAN and name != CUSTODIAN):
        bad.append(f"{name}: shares a PID namespace ({pid}), which reaches the custodian through /proc/<pid>/root")
    for v in svc.get("volumes", []):
        src, dst = host_path(v), v.get("target", "")
        if src is None:
            ext = v.get("source")
            bad.append(f"{name}: mounts the external volume {ext}, whose host path cannot be checked")
            continue
        if src.startswith("RELATIVE:"):
            vs = v.get("source")
            bad.append(f"{name}: the volume {vs} binds the relative device {src[9:]}, which this check cannot resolve")
            continue
        # Compared normalised: /var/lib/pqc-ca//key, //var/lib/pqc-ca/key and
        # /var/lib/pqc-ca/./key are /var/lib/pqc-ca/key.
        if src.startswith("/"):
            for d in PROTECTED:
                if parent_of(src, d):
                    bad.append(f"{name}: mounts {src}, a parent of {d}")
        if any(under(src, d) for d in CUSTODIAN_ONLY) and name != "pqc-ca-custodian":
            bad.append(f"{name}: mounts the custodian\x27s {src}")
        if under(src, "/var/lib/pqc-ca/key") and not v.get("read_only"):
            bad.append(f"{name}: mounts the CA key directory {src} writable")
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
    # A built image is named and tagged by its release, so a rollback to the
    # previous release finds the images of that release, not these (9-2).
    if "build" in svc:
        img = svc.get("image", "")
        tag = img.rsplit("/", 1)[-1].partition("@")[0].partition(":")[2]
        if not tag or tag == "latest":
            bad.append(f"{name}: built without an explicit release tag (image: {img or "none"})")
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
