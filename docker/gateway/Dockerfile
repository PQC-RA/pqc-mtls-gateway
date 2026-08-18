# syntax=docker/dockerfile:1.7
# The gateway now COMPILES NOTHING. Both heavy builds are published images:
#
#   pqc-mtls-openssl-base    PQ OpenSSL, compiled from a checksummed source
#   pqc-mtls-openresty-base  OpenResty 1.27.1.2, linked against that OpenSSL
#
# "genuine build-once". Everything before this
# only amortised the compile via a warm buildx cache.
#
# Both are aliased as named stages so the COPYs reference a stage name
# (lint-clean vs a build-arg in --from). CI passes pinned GHCR digests via
# --build-arg; local builds default to the tags scripts/build-all.sh produces.
#
# nginx links DYNAMICALLY against /opt/openssl (rpath), so the OpenSSL tree
# below is not a duplicate of anything inside the binary, there is exactly one
# OpenSSL in this image. The runtime ldd assertion further down proves the loader
# actually binds it rather than Ubuntu's own libssl.
ARG OPENRESTY_SHA256=74f076f7e364b2a99a6c5f9bb531c27610c78985abe956b442b192a2295f7548
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
ARG BASE_OPENRESTY_IMAGE=pqc-mtls-openresty-base:local
FROM ${BASE_OPENSSL_IMAGE} AS opensslbase
FROM ${BASE_OPENRESTY_IMAGE} AS openrestybase

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	libpcre3 \
	zlib1g \
	libxml2 \
	libxslt1.1 \
	libgd3 \
	libgeoip1 \
	python3 \
	tzdata \
	&& rm -rf /var/lib/apt/lists/*

# The whole of /opt, so the version appears nowhere in this file. The base image
# publishes both the versioned tree (OpenSSL compiles its prefix in, so it cannot
# move) and the /opt/openssl alias beside it, and COPY --from preserves symlinks.
# Verified, not assumed. Naming the versioned directory here instead would put
# the version in every consumer and force a matching `ln -sfn` to recreate an
# alias the base already ships.
COPY --from=opensslbase /opt /opt

COPY --from=openrestybase /usr/sbin/nginx           /usr/sbin/nginx
COPY --from=openrestybase /usr/local/openresty      /usr/local/openresty
COPY --from=openrestybase /etc/nginx                /etc/nginx

COPY gateway/gen_jwks.py /usr/local/bin/gen_jwks.py

RUN set -eux; \
	mkdir -p /etc/nginx /var/log/nginx /var/cache/pqc-gw/routes /run /etc/nginx/lua; \
	echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/00-pqc-openssl.conf; \
	echo "/opt/openssl/lib" >> /etc/ld.so.conf.d/00-pqc-openssl.conf; \
	echo "/usr/local/openresty/luajit/lib" > /etc/ld.so.conf.d/openresty-luajit.conf; \
	ldconfig; \
	/usr/sbin/nginx -V; \
	chmod +x /usr/local/bin/gen_jwks.py; \
	echo "Runtime image ready, signing key and JWKS are injected at container startup"

ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib:/usr/local/openresty/luajit/lib

# ENV propagates through FROM but NOT through COPY --from, so this stage does not
# inherit the base image's PATH. Without this line bare `openssl` resolves to
# Ubuntu's /usr/bin/openssl (3.0.13), which then loads OUR 3.6.2 libraries via
# the 00- ldconfig drop-in and works anyway, while reporting "OpenSSL 3.0.13".
# Correct-by-accident, and dependent on ldconfig sort order that already failed
# once on arm64. The base image's own assertion could not catch this: it runs
# where the ENV IS set. bring-up.yml asserts the built images instead.
ENV PATH=/opt/openssl/bin:$PATH

# nginx now links against the PQ OpenSSL dynamically instead of carrying a static
# copy, so it matters which libssl the loader actually binds at RUNTIME, in this
# stage, not just in the builder. Ubuntu ships its own libssl.so.3 (OpenSSL 3.0,
# no ML-KEM/ML-DSA), and a wrong bind would start cleanly and fail only at the
# first post-quantum handshake.
#
# LD_LIBRARY_PATH above and the -rpath baked into the binary both point at the PQ
# tree; this asserts the result rather than trusting either. Cheap, and it fails
# the build instead of the deployment.
RUN set -eux; \
	ldd /usr/sbin/nginx > /tmp/ldd.txt; \
	grep -q '/opt/openssl/lib64/libssl.so.3'    /tmp/ldd.txt; \
	grep -q '/opt/openssl/lib64/libcrypto.so.3' /tmp/ldd.txt; \
	rm -f /tmp/ldd.txt

COPY gateway/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 443 8081

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
	CMD /usr/sbin/nginx -t && /opt/openssl/bin/openssl version || exit 1

CMD ["/usr/local/bin/entrypoint.sh"]
