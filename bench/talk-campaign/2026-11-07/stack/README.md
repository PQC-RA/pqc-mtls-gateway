# 2026-11-07, throwaway stack on the test stand: enrollment and revocation timing

A complete, separate deployment of this repository's `main` at `83a4f60` (compose project `rs1107`, loopback
ports 39443 for :443, 38443 for :8443 and 33000 for :3000), brought up for this run with a new PKI and new
secrets, and torn down afterwards. Nothing live was contacted. Versions: OpenResty 1.31.8.1 with OpenSSL 3.6.5 in
the gateway and the custodian; the management API image pinned in `docker-compose.yml`. Client on the stand,
loopback, no added delay: OpenSSL 3.6.5, curl 8.5.0 on OpenSSL 3.6.5, Python 3.12.3 on OpenSSL 3.6.5.

## How it was brought up (`tools/bringup.sh`)

The steps of `scripts/deploy.sh`, one by one, with every host path under the run's own directory, its own
compose project, ports and image tags, and a compose wrapper that refuses any other project, host path or port.
`tools/teardown.sh` removes the stack again. `results/layout.txt` checks the result against the repository's
CA layout (one writer of the CA state, the custodian the only holder of the intermediate key).

## What ran

- **Enrollment** (`tools/enroll30.sh`, `results/enroll/`): 30 devices, ML-DSA-65, profile `client-30d`, each with
  a one-time token. Per device: key, CSR (one `openssl` process each) and `POST /enroll` with curl
  (`time_total`).
- **Revocation** (`tools/revoke30.py`, `results/revocation/`): the 30 certificates revoked one by one at
  random gaps of 6.2 to 24.7 s. Timed from just before the admin revoke call to the first refused request, with
  a new connection per request (every 250 ms) and with one connection kept open (every 200 ms).
- **Backstop** (`backstop/`): whether `ssl_crl` refuses a revoked certificate by itself once nginx has
  reloaded, without the per-request check. See `backstop/README.md`.

## Results (medians)

- Enrollment: key 2.9 ms, CSR 4.2 ms, request 43.4 ms end to end (TLS 3.0 ms; from the API's receipt to the
  custodian's signature 29.0 ms). Every request 201, every certificate 5,617 B.
- Revocation: 0.41 s to the first refusal, for new connections and for the connection already open alike;
  slowest of 30: 1.07 s. Every refusal came from the per-request check, which closes the connection without an
  answer (nginx 444).
- The enrollment rate limit (5 per minute per address) answered 429 at 1 s spacing; devices 05 to 30 were
  therefore sent 13 s apart.

Private keys, tokens and HMAC secrets of the stack are not here; logs show their file paths only.
