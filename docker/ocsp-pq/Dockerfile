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
CMD ["/opt/openssl/bin/openssl", "ocsp", "-port", "9080", \
     "-index", "/etc/pki/pqc-ca/intermediate/db/index.txt", \
     "-CA", "/etc/pki/pqc-ca/intermediate/certs/intermediate-ca.crt", \
     "-rsigner", "/etc/pki/pqc-ca/ocsp/ocsp-pq.crt", \
     "-rkey", "/etc/pki/pqc-ca/ocsp/ocsp-pq.key", \
     "-ndays", "7", "-nmin", "60", "-ignore_err"]
