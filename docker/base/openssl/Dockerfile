# syntax=docker/dockerfile:1.7
# pqc-mtls-openssl-base, the compiled post-quantum OpenSSL runtime tree
# (/opt/openssl-<ver>, aliased /opt/openssl), published to ghcr.io/pqc-ra/pqc-mtls-openssl-base.
# The version is ARG OPENSSL_VERSION below, sourced from docker/base/versions.env.
#
# This is the SLIM base: it carries ONLY the OpenSSL install tree, NOT nginx or
# the njs modules. Its consumers are the components that use the `openssl` CLI /
# libs but never run nginx:
#   - ocsp-pq       (FROM this image; runs `openssl ocsp`)
#   - crl-renewer   (FROM this image; runs an openssl-based CRL script)
#   - management-api / pqc-ca-custodian / gateway (COPY --from of the whole /opt)
# The gateway's OpenResty/nginx build is a SEPARATE base (docker/base/openresty):
# nginx and njs deliberately do not live here.
#
# ── The compile happens HERE now ─────────────────────────────────────────────
# The compile happens here, in the image, rather than on a host or CI runner
# with the result shipped in as a tarball. Three reasons.
#
#   * Provenance. The published image's contents depended on whatever the runner
#     happened to compile. It now derives from a checksummed upstream URL, so the
#     image is reproducible from this Dockerfile alone.
#   * Caching. base-images.yml already exports a buildx registry cache with
#     mode=max, which is precisely the mode that caches intermediate stages, but
#     the compile was not a build stage, so it could never participate. That
#     forced a SECOND mechanism (actions/cache over the tarball) to avoid
#     recompiling. One cache now does the job the two were splitting.
#   * The tarball, which existed only to carry the compile's output into this
#     image, and which then had to be produced, version-checked, reused, arch-
#     matched and shipped around by ~160 lines of shell.
#
# `# syntax=docker/dockerfile:1.7` is required for `ADD --checksum`. The version
# and hash live in docker/base/versions.env and are passed as build-args by
# base-images.yml; the defaults below must match that file, which
# scripts/check-version-consistency.sh enforces.
# NO DEFAULT, deliberately. docker/base/versions.env is the single source of
# the version; a default here would be a second copy that only agrees because
# check-version-consistency.sh forces it to.
#
# Docker does NOT error on an unset ARG, it expands to the empty string, so
# dropping the default is only safe with the guard in the build stage below,
# which turns a bare `docker build` into a loud failure instead of an image
# that silently fetched "openssl-.tar.gz".
ARG OPENSSL_VERSION
ARG OPENSSL_SHA256=aaf51a1fe064384f811daeaeb4ec4dce7340ec8bd893027eee676af31e83a04f

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS build

ARG OPENSSL_VERSION
ARG OPENSSL_SHA256

# Fail here, in a second, rather than fetching a nonsense URL or staging a tree
# at /opt/openssl- . Both build paths (scripts/build-all.sh,
# scripts/fetch-base-image.sh) and CI (base-images.yml) pass this from
# versions.env; only a hand-run `docker build` can reach this error.
RUN test -n "${OPENSSL_VERSION}" || { \
      echo "ERROR: OPENSSL_VERSION is unset." >&2; \
      echo "  Build via ./scripts/build-all.sh, or pass it explicitly:" >&2; \
      echo "  docker build --build-arg OPENSSL_VERSION=\$(sed -n 's/^OPENSSL_VERSION=//p' docker/base/versions.env) docker/base/openssl" >&2; \
      exit 1; }
RUN test -n "${OPENSSL_SHA256}" || { echo "ERROR: OPENSSL_SHA256 is unset (see docker/base/versions.env)." >&2; exit 1; }
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    perl \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ADD of a REMOTE url does not auto-extract (unlike a local tarball), so the
# untar below is explicit. --checksum makes a substituted or corrupted download
# fail the build instead of silently producing a different OpenSSL.
ADD --checksum=sha256:${OPENSSL_SHA256} \
    https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    /tmp/openssl.tar.gz

RUN tar -xzf /tmp/openssl.tar.gz -C /tmp

# WORKDIR rather than `cd` inside the RUN (hadolint DL3003); it expands build args.
WORKDIR /tmp/openssl-${OPENSSL_VERSION}
RUN set -eux; \
    ./Configure "--prefix=/opt/openssl-${OPENSSL_VERSION}" --libdir=lib64 \
        enable-ktls enable-ec_nistp_64_gcc_128; \
    make -j"$(nproc)"; \
    make DESTDIR=/stage install_sw

# Fail here, not at first use, if the compile produced an OpenSSL without the PQ
# algorithms, the entire reason this image exists. Otherwise a missing provider
# surfaces as a handshake failure in some consumer, weeks later.
RUN set -eux; \
    P="/stage/opt/openssl-${OPENSSL_VERSION}"; \
    export LD_LIBRARY_PATH="$P/lib64"; \
    "$P/bin/openssl" version; \
    "$P/bin/openssl" list -kem-algorithms       > /tmp/kem.txt; \
    "$P/bin/openssl" list -signature-algorithms > /tmp/sig.txt; \
    grep -qi 'ml-kem' /tmp/kem.txt; \
    grep -qi 'ml-dsa' /tmp/sig.txt; \
    rm -f /tmp/kem.txt /tmp/sig.txt

# Publish the alias and fix permissions INSIDE the staging tree, in the one
# stage that unavoidably knows the version, because it downloads and configures
# with it. The runtime stage then copies the whole of /stage/opt and never names
# a version at all.
#
# The link target is the FINAL absolute path (/opt/openssl-<ver>), NOT the
# staging path, so it dangles here and resolves correctly once copied to /opt.
# `ln -s` does not check its target, which is what makes that possible.
#
# lib -> lib64: OpenSSL installs libs to lib64 here, but plenty of tooling
# assumes <prefix>/lib. One symlink makes both spellings work.
RUN set -eux; \
    ln -s "/opt/openssl-${OPENSSL_VERSION}" /stage/opt/openssl; \
    ln -s lib64 "/stage/opt/openssl-${OPENSSL_VERSION}/lib"; \
    chmod -R 755 "/stage/opt/openssl-${OPENSSL_VERSION}"


FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

# NO `ARG OPENSSL_VERSION` here, deliberately: this stage never names a version.
# It copies the whole of /stage/opt, which already carries both the versioned
# tree and the /opt/openssl alias the build stage put there.
ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps for the OpenSSL libs/CLI only (zlib for compression, ca-certs for
# TLS trust). libpcre3 / the nginx toolchain are intentionally NOT installed,
# this base does not carry nginx.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /stage/opt /opt

# ── /opt/openssl is the path consumers use; the versioned dir is internal ────
# OpenSSL's prefix is compiled into the binary, so the tree MUST physically live
# at /opt/openssl-<ver>. The symlink publishes a stable alias over it.
#
# Why it matters: a bump touches versions.env alone rather than every hardcoded
# path in the tree. This file reads OPENSSL_VERSION through the
# ARG, and every consumer takes the whole /opt from this image and so never
# names a version at all. Two versions can still coexist during a migration
# because the physical directories stay distinct, rollback is repointing one
# symlink.
#
# lib -> lib64 too: OpenSSL installs libs to lib64 here, but plenty of tooling
# assumes <prefix>/lib. One symlink makes both spellings work.
#
# The 00- prefix below is load-bearing, not cosmetic. ldconfig reads
# /etc/ld.so.conf.d/ in alphabetical order and the FIRST directory providing a
# soname wins (verified empirically: 00- passes, zz- fails). Ubuntu's own
# <arch>-linux-gnu.conf carries libssl.so.3 from OpenSSL 3.0, which has no
# ML-KEM or ML-DSA.
#
# Unprefixed, this worked on x86_64 purely because "pqc-openssl" sorts before
# "x86_64-linux-gnu", and failed on aarch64, where "aarch64-linux-gnu" sorts
# first. "0" sorts before every letter, so this is deterministic on any arch.
#
# This comment sits OUTSIDE the RUN below deliberately. A `#` line within a
# backslash continuation is parser-version-dependent: it may happen to work,
# which is worse than failing.
RUN groupadd -g 1001 pqc && \
    useradd -r -u 1001 -g pqc -s /usr/sbin/nologin pqc && \
    echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/00-pqc-openssl.conf && \
    ldconfig

ENV LD_LIBRARY_PATH=/opt/openssl/lib64

# Ubuntu's `openssl` package installs /usr/bin/openssl (3.0.13) and cannot be
# removed: ca-certificates Depends on it, and this image installs
# ca-certificates deliberately for TLS trust.
#
# Left alone, a bare `openssl` therefore resolved to that 3.0.13 CLI, which
# then dynamically bound OUR 3.6.2 libraries, because the 00- ldconfig drop-in
# sorts first. It reported `OpenSSL 3.0.13 (Library: OpenSSL 3.6.2)` and really
# did perform ML-DSA operations. It worked, by coincidence, and the version
# string it printed was actively misleading to anyone debugging.
#
# Putting the PQ bin dir first makes that intent rather than luck.
ENV PATH=/opt/openssl/bin:$PATH

# Assert both halves, because each fails silently on its own:
#   1. bare `openssl` is the PQ CLI:      a later ENV PATH could undo this
#   2. Ubuntu's CLI still binds PQ libs: the deeper dependency; if the
#      ldconfig ordering is ever lost, anything still calling /usr/bin/openssl
#      reverts to OpenSSL 3.0 and ML-KEM/ML-DSA silently disappear. That is not
#      hypothetical: unprefixed, this conf FAILED on arm64 because
#      "aarch64-linux-gnu" sorts before "pqc-openssl".
# Via files, not pipes: hadolint DL4006 wants `SHELL -o pipefail` before any
# piped RUN, and this file already established the file-based pattern for the
# PQ assertion in the build stage. Same reason, same shape.
RUN set -eux; \
    test "$(command -v openssl)" = /opt/openssl/bin/openssl; \
    openssl version                   > /tmp/v.txt; \
    openssl list -signature-algorithms > /tmp/s.txt; \
    ldd /usr/bin/openssl               > /tmp/l.txt; \
    grep -q 'OpenSSL 3\.6\.2'          /tmp/v.txt; \
    grep -qi 'ml-dsa'                  /tmp/s.txt; \
    grep -q '/opt/openssl/lib64/libcrypto.so.3' /tmp/l.txt; \
    rm -f /tmp/v.txt /tmp/s.txt /tmp/l.txt

# Liveness: the PQ OpenSSL binary runs.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD /opt/openssl/bin/openssl version || exit 1

# No default CMD, descendants set their own.
