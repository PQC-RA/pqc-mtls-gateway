# 2026-11-07, revocation backstop: `ssl_crl` alone refuses a revoked certificate after the reload

The gateway has two revocation layers: a per-request check that re-reads the CRL every second and closes the
connection (nginx 444), and nginx's own `ssl_crl`, which is read only when nginx starts or reloads (the
gateway's watcher reloads it when the CRL file changes). This check asks whether the second layer works by
itself.

Same kind of throwaway stack as `../README.md`, brought up fresh (new PKI, new secrets), `main` at `83a4f60`,
OpenResty 1.31.8.1, OpenSSL 3.6.5 (`versions.txt`). Client on the stand, loopback, no added delay.

```
bash tools/bringup.sh
PFX=rs1107-bs OUT=backstop/enroll PACE=13 bash tools/enroll30.sh 3
python3 -I backstop/backstop.py backstop/enroll/enroll.tsv backstop/out
bash tools/teardown.sh
```

Each of 3 runs (`backstop.py`): a pre-check request (404, authenticated; the test path has no route); a
keep-alive connection sending a request every 200 ms; T0 just before the admin revoke call; then a new
connection every 250 ms for 15 s. Every request has its own query string, so each is matched to its access-log
line (`$status`, `$ssl_client_verify`); the reload time is the watcher's line in the gateway's log.

**Result:** in all 3 runs, after the reload every new connection with the revoked certificate got HTTP 400
"The SSL certificate error" (`$ssl_client_verify` = `FAILED:certificate revoked`); no request after the reload
got a 404. 165 of 165 such 400s came from the new (post-reload) nginx worker; every 444 from the old one.
