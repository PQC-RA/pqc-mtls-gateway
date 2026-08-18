# Consumes the PQ-OpenSSL runtime from the shared base image (only openssl is
# needed, the CRL script uses openssl and signals the gateway to reload; it
# never runs nginx itself). CI passes the pinned GHCR digest via --build-arg
# BASE_OPENSSL_IMAGE=ghcr.io/pqc-ra/pqc-mtls-openssl-base@sha256:...; local builds
# default to the tag produced by scripts/build-all.sh.
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
FROM ${BASE_OPENSSL_IMAGE}

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
