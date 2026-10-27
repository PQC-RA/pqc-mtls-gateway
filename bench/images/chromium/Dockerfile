# pqc-test-chromium:local: headless Chromium from Alpine, with NSS tools to
# trust a test CA, for bench/migration/real-clients.sh (cases 15a/15b).
FROM alpine:3
RUN apk add --no-cache chromium nss-tools
ENTRYPOINT ["chromium-browser"]
