#!/usr/bin/env bash
# install-host-openssl.sh: put the PQ OpenSSL (the version in
# docker/base/versions.env) on this host at /opt/openssl-<ver>, aliased
# /opt/openssl, the path every host-side script resolves. Taken from the
# pqc-mtls-openssl-base image (scripts/fetch-base-image.sh: the published image
# by its base.lock digest, else built from source). Idempotent; needs root.
#
# Used by scripts/deploy.sh and, on a host without an OpenSSL 3.5+, by
# scripts/stand-up.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OPENSSL_VER=$(sed -n 's/^OPENSSL_VERSION=//p' docker/base/versions.env)
[ -n "$OPENSSL_VER" ] || { echo "no OPENSSL_VERSION in docker/base/versions.env" >&2; exit 1; }
OSSL=/opt/openssl/bin/openssl

# Probe through the alias: a host from an older deploy has /opt/openssl-<ver>
# without the symlink, falls into the install branch, and is healed by ln -sfn.
if [[ -x "$OSSL" ]] && OPENSSL_CONF=/dev/null "$OSSL" version 2>/dev/null | grep -qF "OpenSSL ${OPENSSL_VER} " \
	&& OPENSSL_CONF=/dev/null "$OSSL" list -signature-algorithms 2>/dev/null | grep -qi "ml-dsa"; then
	echo "PQ OpenSSL ${OPENSSL_VER} already at $OSSL"
	exit 0
fi
docker image inspect pqc-mtls-openssl-base:local >/dev/null 2>&1 || ./scripts/fetch-base-image.sh
docker run --rm --entrypoint sh pqc-mtls-openssl-base:local -c "test -d /opt/openssl-${OPENSSL_VER}" \
	|| { echo "pqc-mtls-openssl-base:local does not carry /opt/openssl-${OPENSSL_VER} (base.lock older than versions.env?)" >&2; exit 1; }
# Copied straight out of the image. `docker cp` of the versioned directory does
# not carry its sibling symlink, so the alias is made here.
_cid=$(docker create pqc-mtls-openssl-base:local /bin/true)
docker cp "$_cid:/opt/openssl-${OPENSSL_VER}" /opt/
docker rm -f "$_cid" >/dev/null
ln -sfn "/opt/openssl-${OPENSSL_VER}" /opt/openssl
echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/00-pqc-openssl.conf
echo "/opt/openssl/lib"  >> /etc/ld.so.conf.d/00-pqc-openssl.conf
ldconfig
echo "$(OPENSSL_CONF=/dev/null $OSSL version)  (/opt/openssl -> openssl-${OPENSSL_VER})"
