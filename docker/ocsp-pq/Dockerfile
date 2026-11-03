# Consumes the PQ-OpenSSL runtime from the shared base image (only openssl is
# needed, this runs `openssl ocsp`, no nginx). CI passes the pinned GHCR digest
# via --build-arg BASE_OPENSSL_IMAGE=ghcr.io/pqc-ra/pqc-mtls-openssl-base@sha256:...;
# local builds default to the tag produced by scripts/build-all.sh.
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
FROM ${BASE_OPENSSL_IMAGE}

# OCSP Responder for ML-DSA-65 chain
EXPOSE 9080

# The OpenSSL OCSP responder runs in the foreground by default.
# NOTE: -rother (which embedded the intermediate CA in every response) was
# removed deliberately. Clients already trust intermediate+root via the CA
# chain, so bundling the intermediate only bloated the stapled response by
# ~6 KB. Embedding only the responder (signer) leaf shrinks the stapled OCSP
# response from ~15.5 KB to ~9.5 KB and still verifies client-side.
# The OpenSSL this image must carry, passed from docker/base/versions.env by every
# build path (no default here: one source); a stale base image fails the build.
ARG OPENSSL_VERSION
RUN test -n "${OPENSSL_VERSION}" || { echo "OPENSSL_VERSION unset: build via scripts/build-all.sh (it passes docker/base/versions.env)" >&2; exit 1; }; \
	/opt/openssl/bin/openssl version > /tmp/o.txt && grep -qF "OpenSSL ${OPENSSL_VERSION} " /tmp/o.txt && rm -f /tmp/o.txt

# ADR-024: the index is the custodian's snapshot (with index.txt.attr beside
# it), the key and certificate come from the responder's own directory. Each is
# a read-only mount of its own. -CA is the intermediate's certificate ALONE (the
# DER the custodian publishes for AIA): the index is the intermediate's, so a
# request about a certificate the root issued must get "unknown", never an
# answer from this index (with the whole chain here it got one).
CMD ["/opt/openssl/bin/openssl", "ocsp", "-port", "9080", \
     "-index", "/var/lib/pqc-ca-status/index.txt", \
     "-CA", "/var/lib/pqc-ca-public/intermediate-ca.crt", \
     "-rsigner", "/var/lib/pqc-ocsp/ocsp-pq.crt", \
     "-rkey", "/var/lib/pqc-ocsp/ocsp-pq.key", \
     "-ndays", "7", "-nmin", "60", "-ignore_err"]
