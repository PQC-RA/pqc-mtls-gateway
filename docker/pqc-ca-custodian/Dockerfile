# pqc-ca-custodian, the only component with any access to the intermediate CA
# private key. Runtime shape mirrors docker/management-api/Dockerfile (Node 22
# + the PQ OpenSSL build), but with no framework, no npm dependencies, and no
# build stage: custodian.js is a single dependency-free script.

# The PQ-OpenSSL runtime comes from the shared base image, aliased as a named
# stage so the COPY below references a stage name (lint-clean) rather than a
# build-arg in --from. CI passes the pinned GHCR digest via --build-arg
# BASE_OPENSSL_IMAGE=ghcr.io/pqc-ra/pqc-mtls-openssl-base@sha256:...; local builds
# default to the tag scripts/build-all.sh produces.
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
FROM ${BASE_OPENSSL_IMAGE} AS opensslbase

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

WORKDIR /usr/src/app

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Node 22 from NodeSource, installed the hardened way: fetch the repo signing
# key over HTTPS into a dedicated keyring, register the apt repo as signed-by
# that keyring, and install an exact pinned nodejs version, no piping a remote
# script into a root shell. curl/gnupg exist only to build the keyring, so they
# (and their pulled-in deps) are purged afterwards; ca-certificates stays for
# runtime TLS trust. (tar is gone, the OpenSSL runtime is COPY --from'd from the
# base image below, not extracted from a tarball, so nothing here unpacks one.)
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	gnupg \
	&& curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
		| gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
		> /etc/apt/sources.list.d/nodesource.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends nodejs=22.23.1-1nodesource1 \
	&& node -v | grep -qE '^v22\.' \
	&& apt-get purge -y --auto-remove curl gnupg \
	&& rm -rf /var/lib/apt/lists/*

# PQ OpenSSL runtime from the shared base image (pqc-mtls-openssl-base). No local
# tarball in the build context anymore, one canonical, digest-pinned source.
# The whole of /opt, so the version appears nowhere in this file. The base image
# publishes both the versioned tree (OpenSSL compiles its prefix in, so it cannot
# move) and the /opt/openssl alias beside it, and COPY --from preserves symlinks.
# Verified, not assumed. Naming the versioned directory here instead would put
# the version in every consumer and force a matching `ln -sfn` to recreate an
# alias the base already ships.
COPY --from=opensslbase /opt /opt

# ENV propagates through FROM but NOT through COPY --from, so this stage does not
# inherit the base image's PATH. Without this line bare `openssl` resolves to
# Ubuntu's /usr/bin/openssl (3.0.13), which then loads OUR 3.6.2 libraries via
# the 00- ldconfig drop-in and works anyway, while reporting "OpenSSL 3.0.13".
# Correct-by-accident, and dependent on ldconfig sort order that already failed
# once on arm64. The base image's own assertion could not catch this: it runs
# where the ENV IS set. bring-up.yml asserts the built images instead.
ENV PATH=/opt/openssl/bin:$PATH

ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib
# The 00- prefix is load-bearing, not cosmetic. ldconfig reads
# /etc/ld.so.conf.d/ in alphabetical order and the FIRST directory providing a
# soname wins (verified empirically: 00- passes, zz- fails). Ubuntu's own
# <arch>-linux-gnu.conf carries libssl.so.3 from OpenSSL 3.0, which has no
# ML-KEM or ML-DSA.
#
# Unprefixed, this worked on x86_64 purely because "pqc-openssl" sorts before
# "x86_64-linux-gnu" -- and failed on aarch64, where "aarch64-linux-gnu" sorts
# first. "0" sorts before every letter, so this is deterministic on any arch.
RUN echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/00-pqc-openssl.conf && \
	echo "/opt/openssl/lib" >> /etc/ld.so.conf.d/00-pqc-openssl.conf && \
	ldconfig

# Same fixed uid/gid as management-api (docker/management-api/Dockerfile) and
# the host CA ownership applied by scripts/setup-pki.sh: intermediate/private
# is root:1001 mode 640 (group-readable), intermediate/db and intermediate/issued
# are owned outright by 1001:1001. That is exactly the access this process
# needs, no reason to run the most sensitive process in the stack as root.
RUN groupadd --system --gid 1001 appuser \
	&& useradd --system --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin appuser

COPY --chown=root:root docker/pqc-ca-custodian/custodian.js ./custodian.js

ENV HOME=/tmp
USER 1001:1001

EXPOSE 8091

CMD ["node", "custodian.js"]
