#!/bin/bash
# fetch-base-image.sh: reuse the published PQ-OpenSSL base instead of compiling it.
#
# base-images.yml already builds, signs and publishes ghcr.io/pqc-ra/pqc-mtls-openssl-base
# and records its manifest digest in base.lock on the orphan `deploy-locks` branch.
#
# Never fails the build. Offline, unauthenticated, no base.lock, or version drift
# all fall back to compiling from source, because an air-gapped build must keep
# working. The fallbacks are quiet EXCEPT version drift, which warns loudly: that
# one is a stale-base signal rather than an environment condition, and a silent
# fallback would let the published base drift further on every build while
# everything still looked fine. Set PQC_SKIP_BASE_PULL=1 to force from-source
# (e.g. when changing docker/base/ itself).
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"
BASE_DIR="docker/base"
# shellcheck disable=SC1091  # sourced at runtime; not resolvable at lint time
source "$BASE_DIR/versions.env"
OPENSSL_VER="$OPENSSL_VERSION"

# A true skip is now only possible when NOTHING can be done, i.e. no docker.
# Every other condition falls through to a local from-source build, because
# docker/base/openssl/Dockerfile is the only thing that compiles OpenSSL any more.
# Returning early on, say, a missing base.lock would leave the deploy with no
# image and nothing to compile from, so every path must fall through to the
# from-source build instead.
skip() { echo "    (base image unavailable: $1)" >&2; exit 1; }

build_from_source() {
  echo "    $1, building docker/base from source"
  # Pass the version from versions.env, exactly as base-images.yml does. Without
  # it the local build falls back to docker/base/openssl/Dockerfile's ARG default,
  # making versions.env authoritative in CI and the Dockerfile default
  # authoritative locally: two sources of truth that agree only by coincidence.
  docker build -t pqc-mtls-openssl-base:local \
    --build-arg "OPENSSL_VERSION=$OPENSSL_VER" \
    "$ROOT_DIR/docker/base/openssl" \
    || skip "from-source build of docker/base failed"
  PULLED=0
}
PULLED=1

command -v docker >/dev/null 2>&1 || skip "docker not found"

LOCK=""
if [ "${PQC_SKIP_BASE_PULL:-0}" = "1" ]; then
  build_from_source "PQC_SKIP_BASE_PULL=1"
else
  # Prefer the in-tree base.lock. The git fallbacks below cover a checkout that
  # keeps the lock on a deploy-locks branch instead.
  if [ -f "$ROOT_DIR/base.lock" ]; then
    LOCK=$(cat "$ROOT_DIR/base.lock")
  else
    LOCK=$(git show origin/deploy-locks:base.lock 2>/dev/null) \
      || LOCK=$(git show deploy-locks:base.lock 2>/dev/null) \
      || { build_from_source "base.lock not found (fetch the deploy-locks branch to enable the pull)"; LOCK=""; }
  fi
fi

if [ "$PULLED" -eq 1 ]; then
jsonval() { printf '%s' "$LOCK" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"; }
IMAGE=$(jsonval image); DIGEST=$(jsonval digest); LOCK_VER=$(jsonval openssl_version)
[ -n "$IMAGE" ] && [ -n "$DIGEST" ] \
  || { build_from_source "base.lock is missing image or digest"; IMAGE=""; }
fi

# Version drift is not an environment condition, it means base.lock is STALE:
# versions.env was bumped and the base image has not been rebuilt since. The
# build still proceeds from source (versions.env is the declared source of truth
# for the compile, so compiling yields the right version), but say so loudly,
# because the quiet path would let the published base drift further behind on
# every build while everything still appeared to work.
if [ "$PULLED" -eq 1 ] && [ -n "${LOCK_VER:-}" ] && [ "$LOCK_VER" != "$OPENSSL_VER" ]; then
  echo "     WARNING: base.lock publishes OpenSSL $LOCK_VER, versions.env pins $OPENSSL_VER."
  echo "             The published base is STALE. Compiling $OPENSSL_VER from source instead."
  echo "             Re-run the base-images workflow to refresh it (it watches versions.env)."
  build_from_source "stale base.lock"
fi

if [ "$PULLED" -eq 1 ]; then
REF="${IMAGE}@${DIGEST}"
echo "    pulling $REF"
if docker pull --quiet "$REF" >/dev/null 2>&1; then
  # The consumers' BASE_OPENSSL_IMAGE default resolves to this tag.
  docker tag "$REF" pqc-mtls-openssl-base:local
else
  # No published base reachable (offline, first deploy before any base exists, or
  # no packages:read). Build it from source instead, docker/base/openssl/Dockerfile now
  # compiles OpenSSL itself from a checksummed upstream tarball.
  #
  # This must NOT fall through to "skip". The Dockerfile is the only thing that
  # compiles OpenSSL, deliberately: a second script-side compile would mean
  # compiling twice on this path.
  build_from_source "pull failed (offline, or no packages:read on the GHCR package)"
fi
fi

if [ "$PULLED" -eq 1 ]; then
  echo "    using the PUBLISHED base image"
else
  echo "    using a LOCALLY BUILT base image (from source)"
fi
