FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

# PKI distribution serves the CA custodian's public directory (ADR-024): CA
# certificates, chains and CRLs, mounted read-only at /var/www/pki. Its own
# nginx.conf runs it unprivileged on :8090 with everything writable in /tmp.
COPY nginx.conf /etc/nginx/nginx.conf

USER 101:101
EXPOSE 8090
# nginx itself, not the image's entrypoint scripts (they edit files under
# /etc/nginx, which is read-only here).
ENTRYPOINT ["nginx", "-g", "daemon off;"]
