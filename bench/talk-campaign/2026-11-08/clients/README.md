# 2026-11-08: client re-check against the live gateway (Linux curl, Java 21)

Same method as the 4 Nov matrix (`../../tools/matrix_server.sh`): containers with `--network host` on the gateway
host, against the live gateway (203.0.113.99), with the 4 Nov client folder mounted read-only (client certificate
CN=talk-probe-01). Nothing on the gateway changed; no image was pulled.

| client | :8443, verifies the gateway | :443, mutual TLS |
|---|---|---|
| `curlimages/curl` 8.21.0, OpenSSL 3.5.7 (runs as `curl_user`) | 404, verified | 404, verified; the gateway logged CN=talk-probe-01, X25519MLKEM768, client signature ML-DSA-65 |
| JVM 21.0.11 on the host | `handshake_failure` | `handshake_failure` |
| `eclipse-temurin:21-jdk`, 21.0.12.1 | `handshake_failure` | `handshake_failure` |

For all four Java connections the gateway logged `reason=no_pq_group` with the groups offered: Java 21 offers no
hybrid group (`gateway-log-2026-11-08.txt`). 404 means authenticated: the test path has no route.

## The 4 Nov curl row

`../../2026-11-04/clients-matrix-server-side.tsv` shows `000` for the curl container on :443. That run did fail
once and then succeed (`recheck-2026-11-04.txt`, from the gateway's log and the client folder's file times):

- 08:19:18 UTC: the connection closed before the handshake. The image runs as an unprivileged user, which could
  not read the key file in the mounted folder.
- 08:19:36.585 UTC: the key and certificate files' permissions were changed (their contents were not).
- 08:19:36 UTC: the retry authenticated (SNI `pqc-gw.local`, which only the curl command sent; HTTP 404). Its
  `404` is the last line of that file.

The empty "refusal reasons" section of that file has a separate cause: the script read the container's
`docker logs`, but the gateway writes those lines to its log volume. The 4 Nov gateway log does have them: Java 21
at 08:19:17-19 UTC, `reason=no_pq_group` on both ports.
