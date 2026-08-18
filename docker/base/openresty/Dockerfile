# syntax=docker/dockerfile:1.7
# pqc-mtls-openresty-base, OpenResty 1.27.1.2 built once against the PQ OpenSSL base,
# published to ghcr.io/pqc-ra/pqc-mtls-openresty-base.
#
# This is the same move already made for OpenSSL:
# the expensive compile becomes a published image, and the consumer assembles
# rather than builds. After this the gateway compiles nothing at all.
#
# ── Why this links dynamically rather than using --with-openssl ─────────────────
# `--with-openssl=<dir>` does not mean "link against", it makes nginx BUILD
# OpenSSL from source and bake it in, so the image would carry a second, private
# OpenSSL invisible to any scanner looking at /opt, and a CVE fix in the base
# would not reach it. This links DYNAMICALLY against the base's tree, exactly as
# the gateway does. The configure flags below are lifted verbatim from
# docker/gateway/Dockerfile so they cannot drift.
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
ARG OPENRESTY_VERSION=1.27.1.2
ARG OPENRESTY_SHA256=74f076f7e364b2a99a6c5f9bb531c27610c78985abe956b442b192a2295f7548

FROM ${BASE_OPENSSL_IMAGE} AS opensslbase

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS build

ENV DEBIAN_FRONTEND=noninteractive
ARG OPENRESTY_VERSION
ARG OPENRESTY_SHA256

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	curl \
	wget \
	tar \
	xz-utils \
	perl \
	make \
	git \
	libpcre3 \
	libpcre3-dev \
	zlib1g \
	zlib1g-dev \
	libxml2 \
	libxml2-dev \
	libxslt1.1 \
	libxslt1-dev \
	libgd3 \
	libgd-dev \
	libgeoip-dev \
	libreadline-dev \
	libncurses-dev \
	&& rm -rf /var/lib/apt/lists/*
# The PQ OpenSSL to compile and link against. Present only in this stage, the
# final stage carries OpenResty alone; consumers get OpenSSL from the base image
# directly, so it is never duplicated.
# The whole of /opt, so the version appears nowhere in this file. The base image
# publishes both the versioned tree (OpenSSL compiles its prefix in, so it cannot
# move) and the /opt/openssl alias beside it, and COPY --from preserves symlinks.
# Verified, not assumed. Naming the versioned directory here instead would put
# the version in every consumer and force a matching `ln -sfn` to recreate an
# alias the base already ships.
COPY --from=opensslbase /opt /opt

ADD --checksum=sha256:${OPENRESTY_SHA256} \
    https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz \
    /tmp/openresty.tar.gz
RUN tar -xzf /tmp/openresty.tar.gz -C /tmp && rm -f /tmp/openresty.tar.gz

WORKDIR /tmp/openresty-${OPENRESTY_VERSION}
RUN set -eux; \
	./configure \
	--prefix=/usr/local/openresty \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--pid-path=/run/nginx.pid \
	--lock-path=/run/nginx.lock \
	--modules-path=/etc/nginx/modules \
	--http-log-path=/var/log/nginx/access.log \
	--error-log-path=/var/log/nginx/error.log \
	--with-pcre-jit \
	--with-http_ssl_module \
	--with-http_v2_module \
	--with-http_realip_module \
	--with-http_stub_status_module \
	--with-http_auth_request_module \
	--with-http_slice_module \
	--with-threads \
	--with-file-aio \
	--with-stream \
	--with-stream_ssl_module \
	--with-stream_ssl_preread_module \
	--with-cc-opt='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -I/opt/openssl/include' \
	--with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,-rpath,/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib -L/opt/openssl/lib64 -L/opt/openssl/lib' \
	  > /tmp/configure.log 2>&1 || { cat /tmp/configure.log; exit 1; }; \
	cat /tmp/configure.log; \
	grep -q 'using system OpenSSL library' /tmp/configure.log; \
	make -j"$(nproc)"; \
	make install; \
	ldd /usr/sbin/nginx > /tmp/ldd.txt; \
	grep -q '/opt/openssl/lib64/libssl.so.3' /tmp/ldd.txt; \
	rm -f /tmp/configure.log

# Carrier stage: OpenResty only. No OpenSSL, no build toolchain, consumers
# COPY --from this and take OpenSSL from pqc-mtls-openssl-base separately.
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

COPY --from=build /usr/sbin/nginx      /usr/sbin/nginx
COPY --from=build /usr/local/openresty /usr/local/openresty
COPY --from=build /etc/nginx           /etc/nginx

# No CMD, this is a build-tier image, consumed only via COPY --from.
