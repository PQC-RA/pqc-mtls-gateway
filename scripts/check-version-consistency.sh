#!/usr/bin/env bash
# check-version-consistency.sh
# -----------------------------------------------------------------------------
# Drift guard for the OpenSSL version.
#
# docker/base/versions.env is the single source of the compile version
# (OPENSSL_VERSION). Everything that can read it does, including deploy.sh and
# teardown.sh, so no script keeps its own `OPENSSL_VER=` copy.
#
# What is left, and why this script still exists: a Dockerfile cannot source a
# .env, and the compiled tree's path, /opt/openssl-<ver>, is baked into the
# OpenSSL binary at configure time, so it CANNOT be de-versioned. The build
# recipes therefore still name it literally. /opt/openssl is a symlink to that
# tree, published by docker/base/openssl/Dockerfile and, host-side, by deploy.sh; it is
# what every consumer addresses.
#
# So this asserts two things:
#   1. every literal /opt/openssl-<ver> in the build recipes matches versions.env
#   2. nothing outside versions.env keeps its own OPENSSL_VER= copy of the value
#
# A bump that forgets one fails LOUDLY here instead of producing an image whose
# ldconfig / LD_LIBRARY_PATH / symlink target points at a directory that is not
# there.
#
# Run by scripts/build-all.sh before building; also safe standalone or in CI.
# -----------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# shellcheck disable=SC1091
source "$ROOT_DIR/docker/base/versions.env"
expected="$OPENSSL_VERSION"

# bench/ is EXEMPT, deliberately. Those are measurement harnesses whose recorded
# numbers belong to the OpenSSL they were run against, so they stay pinned to it.
# After a bump they should fail loudly with "no such file" rather than silently
# re-measure a different OpenSSL and file the results under the same campaign,
# bench/README.md already documents one baseline lost to exactly that kind of
# unrecorded condition. The live pieces (verify-suite.sh, preflight.sh,
# gen-provenance.sh, the diag scripts) address /opt/openssl and are checked.
# Scan the WHOLE tree and subtract, rather than listing the directories to look
# in. The first version of this listed docker/ scripts/ config/ .github/ and so
# never saw docker-compose.yml, whose healthcheck ran
# /opt/openssl-<ver>/bin/openssl at the repo root. A bump would have left those
# containers permanently unhealthy, and this check would have reported OK.
#
# An allowlist of directories silently stops covering anything added outside it;
# an exclusion list fails the other way, which is the direction that gets
# noticed.
SCAN_DIRS=("$ROOT_DIR")
INCLUDES=(--include='Dockerfile' --include='*.js' --include='*.sh'
          --include='*.py' --include='*.conf' --include='*.cnf' --include='*.lua'
          --include='*.yml' --include='*.yaml'
          --exclude-dir='bench' --exclude-dir='.git' --exclude-dir='node_modules')

scan() { grep -rhoE "$1" "${SCAN_DIRS[@]}" "${INCLUDES[@]}" 2>/dev/null | grep -v 'check-version-consistency' || true; }

bad=0

# ── 0. The anchor: versions.env is the ONLY place the version appears ────────
# Deliberately does NOT assert an `ARG OPENSSL_VERSION=<ver>` default in
# docker/base/openssl/Dockerfile. Such a default would be a second copy of the
# value, agreeing with versions.env only because this script forced it to, which
# is not the same as having one copy.
#
# So the assertion inverts. The Dockerfile must declare the ARG *without* a
# default, and must guard against it being unset, Docker expands an unset ARG to
# the empty string rather than failing, so without the guard a hand-run
# `docker build` silently fetches "openssl-.tar.gz".
BASE_DF="$ROOT_DIR/docker/base/openssl/Dockerfile"

if grep -qE '^ARG[[:space:]]+OPENSSL_VERSION=' "$BASE_DF"; then
  echo "ERROR: docker/base/openssl/Dockerfile reintroduced a default for ARG OPENSSL_VERSION." >&2
  echo "  That is a second source of truth. The version belongs only in" >&2
  echo "  docker/base/versions.env, which every build path passes as --build-arg." >&2
  bad=1
fi

if ! grep -qE '^ARG[[:space:]]+OPENSSL_VERSION[[:space:]]*$' "$BASE_DF"; then
  echo "ERROR: docker/base/openssl/Dockerfile does not declare 'ARG OPENSSL_VERSION'." >&2
  exit 1
fi

if ! grep -q 'test -n "${OPENSSL_VERSION}"' "$BASE_DF"; then
  echo "ERROR: docker/base/openssl/Dockerfile lost its unset-OPENSSL_VERSION guard." >&2
  echo "  Without it an unset ARG expands to \"\" and the build silently produces" >&2
  echo "  a broken image instead of failing." >&2
  bad=1
fi

# Every build path must actually pass the value, or versions.env is decorative.
for caller in scripts/build-all.sh scripts/fetch-base-image.sh; do
  if ! grep -q 'build-arg "OPENSSL_VERSION=' "$ROOT_DIR/$caller"; then
    echo "ERROR: $caller builds docker/base without --build-arg OPENSSL_VERSION." >&2
    echo "  versions.env would be ignored and the build would fail on the guard." >&2
    bad=1
  fi
done

# ── 1. Any remaining versioned tree paths ────────────────────────────────────
# Expected to be EMPTY now. Kept because a new one can appear at any time, and
# it costs nothing to keep sweeping for it.
paths=$(scan '/opt/openssl-[0-9]+\.[0-9]+\.[0-9]+' | sed -E 's#/opt/openssl-##' | sort -u)

while IFS= read -r v; do
  [[ -z "$v" ]] && continue
  if [[ "$v" != "$expected" ]]; then
    echo "  DRIFT: a build recipe hardcodes /opt/openssl-$v but versions.env says $expected" >&2
    grep -rlE "/opt/openssl-${v//./\\.}(/|\b)" "${SCAN_DIRS[@]}" "${INCLUDES[@]}" 2>/dev/null \
      | grep -v 'check-version-consistency' | sed 's#'"$ROOT_DIR"'/#    - #' >&2
    bad=1
  fi
done <<< "$paths"

# ── 2. Second copies of the version itself ───────────────────────────────────
# deploy.sh and teardown.sh each carried `OPENSSL_VER=3.6.2` while the rest of
# the repo sourced versions.env. Nothing caught it, because the old check only
# looked at /opt/openssl-<ver> paths. A bump would have left them docker-cp'ing
# a tree the new base image does not contain.
assigns=$(scan 'OPENSSL_VER[A-Z]*=["'"'"']?[0-9]+\.[0-9]+\.[0-9]+' \
          | sed -E 's#.*=["'"'"']?##' | sort -u)
while IFS= read -r v; do
  [[ -z "$v" ]] && continue
  if [[ "$v" != "$expected" ]]; then
    echo "  DRIFT: a file assigns OPENSSL_VER*=$v but versions.env says $expected" >&2
    grep -rlE "OPENSSL_VER[A-Z]*=[\"']?${v//./\\.}" "${SCAN_DIRS[@]}" "${INCLUDES[@]}" 2>/dev/null \
      | grep -v 'check-version-consistency' | sed 's#'"$ROOT_DIR"'/#    - #' >&2
    bad=1
  fi
done <<< "$assigns"

if [[ "$bad" -ne 0 ]]; then
  echo "OpenSSL version drift: bring the paths/assignments above in line with" >&2
  echo "docker/base/versions.env (OPENSSL_VERSION=$expected), or bump versions.env." >&2
  exit 1
fi

echo "version-consistency OK: OPENSSL_VERSION=$expected"
echo "  single source: docker/base/versions.env (Dockerfile carries no default)"
echo "  stray /opt/openssl-<ver> literals outside bench/: ${paths:-none}"
echo "  bench/ exempt by design (pinned to the OpenSSL its numbers were measured against)"
