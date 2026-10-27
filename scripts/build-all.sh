#!/bin/bash
# Builds all images in dependency order

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

# The base binary artifacts (PQ OpenSSL tarball, nginx, njs modules) are NOT
# committed to git. Build them from source on first run if they are missing.
# Versions for every build below (compose passes them as build args; the images
# assert them). One source: docker/base/versions.env.
set -a; . docker/base/versions.env; set +a

# A :local base image left from an earlier version is not reused: its tag is
# dropped so the published image (if base.lock names this version) or a source
# build replaces it.
if docker image inspect pqc-mtls-openssl-base:local >/dev/null 2>&1 \
	&& ! docker run --rm --entrypoint /opt/openssl/bin/openssl pqc-mtls-openssl-base:local version 2>/dev/null | grep -qF "OpenSSL ${OPENSSL_VERSION} "; then
    echo "0. pqc-mtls-openssl-base:local is not OpenSSL ${OPENSSL_VERSION}; replacing it"
    docker image rm pqc-mtls-openssl-base:local >/dev/null
fi
if docker image inspect pqc-mtls-openresty-base:local >/dev/null 2>&1 \
	&& ! docker run --rm --entrypoint grep pqc-mtls-openresty-base:local -aqF "openresty/${OPENRESTY_VERSION}" /usr/sbin/nginx; then
    # (the base image cannot run nginx: its runtime libraries come in the gateway
    # image, so the version is read from the binary)
    echo "0. pqc-mtls-openresty-base:local is not OpenResty ${OPENRESTY_VERSION}; replacing it"
    docker image rm pqc-mtls-openresty-base:local >/dev/null
fi

if ! docker image inspect pqc-mtls-openssl-base:local >/dev/null 2>&1; then
    # First try the published, signed base: base.lock pins its digest, and the
    # OpenSSL install tree inside it is exactly what the long compile produces.
    # Soft-fails to from-source when offline/unauthenticated, so an air-gapped
    # build is unaffected. PQC_SKIP_BASE_PULL=1 forces from-source.
    echo "0. Base artifacts missing, trying the published base image first..."
    if ./scripts/fetch-base-image.sh; then
        echo "0a. Using the published PQ-OpenSSL base."
    else
        echo "0a. WARN: published base unavailable, falling back to from-source." >&2
    fi

fi

# Fail fast if any hardcoded /opt/openssl-<ver> path has drifted from the single
# source (docker/base/versions.env), otherwise an image could ship with an
# ldconfig/LD_LIBRARY_PATH pointing at a directory that isn't there.
echo "0b. Checking OpenSSL version consistency..."
./scripts/check-version-consistency.sh

# Build the slim PQ-OpenSSL base locally and tag it `pqc-mtls-openssl-base:local`,
# the default value of every consumer's BASE_OPENSSL_IMAGE build-arg. The compose
# builds below (ocsp/crl FROM it, custodian/management-api COPY --from it) resolve
# it from the local image store. In CI this tag is instead the pinned GHCR digest.
# fetch-base-image.sh already tags the pulled image `pqc-mtls-openssl-base:local`.
# Only build it locally when that did not happen (offline, or from-source path).
if docker image inspect pqc-mtls-openssl-base:local >/dev/null 2>&1; then
    echo "1. pqc-mtls-openssl-base:local already present (published base, or a previous build)"
else
    echo "1. Building pqc-mtls-openssl-base:local..."
    # Same reason as fetch-base-image.sh: versions.env is the source of truth, so
    # it must reach the build rather than letting the Dockerfile's ARG default win.
    # shellcheck disable=SC1091
    source docker/base/versions.env
    docker build -t pqc-mtls-openssl-base:local \
        --build-arg "OPENSSL_VERSION=$OPENSSL_VERSION" \
        docker/base/openssl/
fi

# The OpenResty build-tier base. Same pull-or-build shape as the
# OpenSSL base: pull the published image when base.lock names one, otherwise
# build it here. Without this a PR that introduces or changes the image cannot be
# gated at all, bring-up pulls whatever is ALREADY published, so a base-image
# change is never tested against the base image it would produce.
if docker image inspect pqc-mtls-openresty-base:local >/dev/null 2>&1; then
    echo "1b. pqc-mtls-openresty-base:local already present"
else
    # base.lock lives on the orphan deploy-locks branch. A tarball, a zip, or a
    # clone that never fetched it will not have it, and that is normal: fall
    # through to building from source. Without the fallbacks below, set -e turns
    # a missing branch into a silent exit before anything is built.
    if [ -f base.lock ]; then
        OR_LOCK=$(cat base.lock)
    else
        OR_LOCK=$(git show origin/deploy-locks:base.lock 2>/dev/null \
            || git show deploy-locks:base.lock 2>/dev/null || true)
    fi
    OR_REF=$(printf '%s' "$OR_LOCK" | sed -n 's/.*"openresty_image"[^"]*"\([^"]*\)".*/\1/p')
    OR_DIG=$(printf '%s' "$OR_LOCK" | sed -n 's/.*"openresty_digest"[^"]*"\([^"]*\)".*/\1/p')
    OR_VER=$(printf '%s' "$OR_LOCK" | sed -n 's/.*"openresty_version"[^"]*"\([^"]*\)".*/\1/p')
    if [ -n "$OR_REF" ] && [ "$OR_VER" != "$OPENRESTY_VERSION" ]; then
        echo "1b. base.lock names OpenResty ${OR_VER:-?}, versions.env ${OPENRESTY_VERSION}: not pulling it"
        OR_REF=""; OR_DIG=""
    fi
    # PQC_SKIP_OPENRESTY_PULL is the openresty counterpart of PQC_SKIP_BASE_PULL.
    # Without it this block pulled the published image even when the caller had
    # explicitly asked to test the openresty base a change produces.
    if [ "${PQC_SKIP_OPENRESTY_PULL:-0}" = "1" ]; then
        OR_REF=""; OR_DIG=""
        echo "1b. PQC_SKIP_OPENRESTY_PULL=1, building pqc-mtls-openresty-base from source"
    fi
    if [ -n "$OR_REF" ] && [ -n "$OR_DIG" ] && docker pull --quiet "${OR_REF}@${OR_DIG}" >/dev/null 2>&1; then
        docker tag "${OR_REF}@${OR_DIG}" pqc-mtls-openresty-base:local
        echo "1b. Pulled the published pqc-mtls-openresty-base"
    else
        echo "1b. Building pqc-mtls-openresty-base:local from source..."
        docker build -t pqc-mtls-openresty-base:local \
            --build-arg "OPENRESTY_VERSION=$OPENRESTY_VERSION" --build-arg "OPENRESTY_SHA256=$OPENRESTY_SHA256" \
            docker/base/openresty/
    fi
fi

# BASES_ONLY=1: stop here (scripts/stand-up.sh builds the services with its own tags).
[ "${BASES_ONLY:-0}" = 1 ] && { echo "Base images ready."; exit 0; }
echo "2. Building Docker Compose services..."
docker compose -f docker-compose.yml build

echo "Build complete."
