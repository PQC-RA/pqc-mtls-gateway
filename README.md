# PQC TLS Gateway

Post-quantum mutual-TLS API gateway: an OpenResty/nginx edge that terminates
**TLS 1.3 with hybrid post-quantum key exchange (X25519MLKEM768)** and
**ML-DSA-65 certificate authentication**, enforces mTLS + CRL revocation, and
does per-client dynamic routing with a cryptographically-attested identity
hand-off (RS256 JWT) to backends. Ships with a full PKI (ML-DSA root →
intermediate), OCSP responders, a CRL renewer, and a NestJS
management API.

This repository is the **infrastructure** side (Docker, nginx/Lua config,
PKI tooling). The management API lives in its own repository and is consumed as
a published container image. A plain `git clone` of this repo is enough to
deploy, with no `--recursive` and no submodule.

| Component | Repo | How it is consumed here |
|-----------|------|-------------------------|
| Infra (this repo) | https://github.com/PQC-RA/pqc-mtls-gateway | you are here |
| Management API | https://github.com/PQC-RA/pqc-mtls-management-api | `ghcr.io/pqc-ra/pqc-mtls-management-api`, pinned by digest in `docker-compose.yml` |

> ⚠️ **No secrets or private keys are committed.** The CA, server cert, JWT
> signing key and control-plane HMAC are generated locally by the bootstrap
> scripts.

## Services

| Service | Role |
|---|---|
| `gateway` | OpenResty edge, PQC TLS termination, mTLS, routing, JWT minting |
| `management-api` | NestJS control plane, cert lifecycle, policy/routes, CRL, audit |
| `pqc-ca-custodian` | Intermediate-CA signing sidecar, the **only** component with access to the intermediate private key; `management-api` reaches it over an HMAC-authenticated internal API (see [Security notes](#security-notes)) |
| `redis` | Durable routing-policy + enrollment-token store for `management-api`. If absent, the API falls back to in-process memory (lost on restart) and refuses to start under `NODE_ENV=production` |
| `ocsp-pq` | OCSP responder (ML-DSA-65 chain) |
| `crl-renewer` | Periodic CRL regeneration |
| `pki-dist` | Serves CA certs / CRLs over HTTP |
| `shadow-mock` | Test backend (returns `{"status":"pqc-shadow-success"}`), **dev only**, removed by `./scripts/teardown.sh --test-only` |

## Deployment

### Prerequisites

- Linux host (Ubuntu 22.04 / 24.04 recommended)
- Everything else (Docker, Docker Compose v2, build toolchain) is installed automatically by `deploy.sh` if missing

### One-command deploy

```bash
git clone https://github.com/PQC-RA/pqc-mtls-gateway.git
cd pqc-mtls-gateway
sudo ./scripts/deploy.sh
```

`deploy.sh` handles everything end-to-end (auto-installs any missing build packages):

1. **Build base artifacts**, compiles PQ OpenSSL 3.6.2 + OpenResty 1.27.1.2 from source (~30 min, one-time). Skipped on re-runs if artifacts are current.
2. **Install PQ OpenSSL** to `/opt/openssl-<ver>` on the host, aliased as `/opt/openssl`, the path everything else uses.
3. **Bootstrap PKI**, ML-DSA-65 root CA → intermediate CA → gateway server cert + OCSP cert + CRLs. Server IP is auto-detected and embedded in the server cert SAN. Skipped if PKI already exists.
4. **Issue bootstrap admin certificate**, saved to `./admin-cert/`. Writes its SHA-256 fingerprint into `ADMIN_CERT_FINGERPRINTS` in `.env` automatically (gitignored, per-deployment, see [Configuration & `.env`](#configuration-reference) below). No manual fingerprint step.
5. **Generate gateway secrets**, RSA-2048 JWT signing key + control-plane HMAC.
6. **Build Docker images** and start all services.
7. Prints `scp` commands to copy the admin cert to a remote machine.

Pass `--server-ip IP` to override the auto-detected IP (used in the server cert SAN):
```bash
sudo ./scripts/deploy.sh --server-ip 10.0.0.5
```

Pass `--rebuild-artifacts` to ignore the published PQ-OpenSSL base image and build it from source:
```bash
sudo ./scripts/deploy.sh --rebuild-artifacts
```

## Issuing client certificates

`issue-cert.sh` supports two modes. In both cases the operator generates their own ML-DSA-65 key pair locally, the private key never leaves the machine.

### Self-enrollment (operator, no admin credentials needed)

An admin pre-issues a CN-constrained enrollment token and hands it to the operator out-of-band. The operator enrolls autonomously via the dedicated enrollment endpoint on **port 8443** (no mTLS client certificate required):

```bash
ENROLLMENT_TOKEN=enroll_xxx \
PQC_GATEWAY=https://<server-ip> \
PQC_CA_CHAIN=./ca-chain.crt \
PQC_ENROLL_CA=./enroll-ca.crt \
./issue-cert.sh <cn>
```

> `PQC_ENROLL_CA` is the CA that signed the **:8443 enrollment listener's**
> server cert, a **classical ECDSA** cert, distinct from the ML-DSA chain in
> `PQC_CA_CHAIN`. Copy it from the server at
> `/etc/pki/pqc-ca/enroll-classical-ca.crt`. **On the server itself it is
> auto-detected**, so `PQC_ENROLL_CA` is only needed when enrolling from a
> remote machine.

The token carries an `allowedCn` constraint set by the admin at creation time. The CSR subject CN must match exactly, a mismatched CN returns 403 without consuming the token.

To issue the token (admin only):
```bash
curl -sk --cacert $CA_CHAIN --cert $ADMIN_CERT --key $ADMIN_KEY \
  -H "X-PQC-CSRF: 1" \
  -X POST "https://<server>/admin/certs/enrollment-tokens?cn=<cn>&ttl=86400"
# → { "token": "enroll_...", "expiresAt": ..., "allowedCn": "<cn>" }
```

> The `X-PQC-CSRF` header is required on **every mutating admin call** (`POST`/`PUT`/`DELETE`).
> It's the management-api CSRF guard's defense: a cross-site browser can't set it (its CORS
> preflight is blocked), so a CLI that sets it explicitly is authorized without needing a
> browser-console `Origin`. `issue-cert.sh` sends it for you; only hand-rolled `curl` needs it.

### Admin-direct (token created automatically)

If you have admin credentials, `issue-cert.sh` creates a short-lived token automatically and then enrolls via port 8443 in a single command.

#### From the server:

```bash
PQC_GATEWAY=https://127.0.0.1 \
PQC_CA_CHAIN=/etc/pki/pqc-ca/ca-chain.crt \
PQC_ADMIN_CERT=./admin-cert/gateway-admin.crt \
PQC_ADMIN_KEY=./admin-cert/gateway-admin.key \
./scripts/issue-cert.sh <cn> <backend-url>
```

#### From a remote machine (macOS / Linux):

Copy the credentials printed by `deploy.sh`:
```bash
scp root@<server>:<repo>/admin-cert/gateway-admin.crt ./admin.crt
scp root@<server>:<repo>/admin-cert/gateway-admin.key ./admin.key
chmod 600 admin.key
scp root@<server>:/etc/pki/pqc-ca/ca-chain.crt ./ca-chain.crt
# The :8443 enrollment listener presents a separate (classical) CA, copy it
# too so the enrollment step can be verified from this machine:
scp root@<server>:/etc/pki/pqc-ca/enroll-classical-ca.crt ./enroll-ca.crt
scp root@<server>:<repo>/scripts/issue-cert.sh .
```

Then run (`PQC_ENROLL_CA` points at the enrollment CA you copied; unnecessary on the server, where it is auto-detected):
```bash
PQC_GATEWAY=https://<server-ip> PQC_ENROLL_CA=./enroll-ca.crt \
  ./issue-cert.sh <cn> <backend-url>
```

**How `issue-cert.sh` finds a PQ-capable OpenSSL** (in order):

1. **Native PQ OpenSSL**, if a binary with ML-DSA-65 support is on `PATH` (or at `/opt/openssl/bin/openssl`, or `PQC_OPENSSL=<path>`), it runs natively. On **macOS** this means Homebrew's OpenSSL 3.5+:
   ```bash
   brew install openssl@3            # provides /opt/homebrew/bin/openssl (ML-DSA-65 capable)
   PQC_GATEWAY=https://<server-ip> PQC_OPENSSL=/opt/homebrew/bin/openssl \
     ./issue-cert.sh <cn> <backend-url>
   ```
   The script uses `openssl s_client` directly for the admin/enrollment calls, because the system `curl` (macOS LibreSSL, or older Linux) cannot negotiate X25519MLKEM768 or load ML-DSA-65 client certs.
2. **Docker fallback**, only if no PQ OpenSSL is found. The script re-execs inside the published PQ-OpenSSL base image, pinned by digest. It is multi-arch, so Apple Silicon runs it natively (no `--platform` pin, no Rosetta 2). The package is currently private: run `docker login ghcr.io` with a `read:packages` token first.

## Routing policies

A client certificate alone does not get traffic to a backend, the gateway routes
each request by the client's CN, so every CN needs a **routing policy** (CN →
backend + rate limit + allowed paths). Without a policy for the presented CN, the
gateway has nowhere to send the request and returns `404`/`502`.

The simplest way to create one is the **backend-URL argument to `issue-cert.sh`**,
it issues the cert and PUTs the policy in one step:

```bash
# CN 'demo-service' → the bundled shadow-mock test backend (works out of the box)
./scripts/issue-cert.sh demo-service http://shadow-mock:80
```

> The backend must **resolve on a gateway network**. `shadow-mock` is the bundled
> test service; `http://my-backend:8080` in the examples above is a **placeholder**,
> replace it with a real `host:port` or you'll get a `502` (the backend won't resolve).

Or manage policies directly via the admin API (mTLS on port 443):

```bash
CURL_ADMIN="curl -sk --cacert ca-chain.crt --cert admin.crt --key admin.key -H X-PQC-CSRF:1"   # PQ-capable curl; header satisfies the CSRF guard

# Create / update
$CURL_ADMIN -X PUT https://<server>/admin/policy/routes/demo-service \
  -H 'Content-Type: application/json' \
  -d '{"org":"ACME","backend":"http://shadow-mock:80","rate_limit":{"rps":100,"burst":200},"allowed_paths":["/api/","/status/"]}'

# Inspect / remove
$CURL_ADMIN https://<server>/admin/policy/routes/demo-service
$CURL_ADMIN -X DELETE https://<server>/admin/policy/routes/demo-service
```

Policies are persisted (gateway volume + management-api store) and survive restarts.

## Verifying the deployment

```bash
# PQC handshake, expect "Negotiated TLS1.3 group: X25519MLKEM768" + "mldsa65"
OSSL=/opt/openssl/bin/openssl
CA=/etc/pki/pqc-ca/ca-chain.crt
CERT=./admin-cert/gateway-admin.crt
KEY=./admin-cert/gateway-admin.key

echo | OPENSSL_CONF=/etc/ssl/openssl.cnf $OSSL s_client \
  -connect 127.0.0.1:443 -CAfile $CA -cert $CERT -key $KEY -tls1_3 2>&1 \
  | grep -E 'Negotiated|Peer signature'

# Admin API health
curl -sk --cacert $CA --cert $CERT --key $KEY https://127.0.0.1/admin/health

# Full end-to-end: issue cert → route to shadow-mock → request through gateway
PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=$CA PQC_ADMIN_CERT=$CERT PQC_ADMIN_KEY=$KEY \
  ./scripts/issue-cert.sh test-service http://shadow-mock:80

curl -s --cacert $CA \
  --cert ./certs/test-service/test-service.crt \
  --key  ./certs/test-service/test-service.key \
  https://127.0.0.1/api/v1/status
# → {"status":"pqc-shadow-success","pqc":"ML-DSA-65"}

# Smoke tests
./scripts/test-stack-smoke.sh
```

## Reproducing the paper's figures

`bench/` carries the measurement harness, the raw per-sample data, and the commands that recompute
each published figure. `bench/EXPECTED-RESULTS.md` records what every script returned on the
reference testbed, so a re-run can be **checked rather than trusted**.

The reference testbed is an 8-core i9-11950H LXC guest with 8 GiB, Ubuntu 24.04, OpenSSL 3.6.2.
Absolute latency and throughput scale with the host; certificate sizes, wire bytes and the
enforcement behaviour do not, and those are the figures to compare first.

```bash
# 1. Issue the identity the live-gateway arms use. Run every step from the
#    repository root; the harness runs in place, in ./bench.

#    The CA holds one active certificate per CN, so a second issuance for
#    bench-client is refused with 409 cn_already_active. Re-running is
#    therefore a no-op; to force a fresh one revoke it first, as
#    scripts/test-issuance-e2e.sh does via POST /admin/certs/revoke.
if [ ! -f certs/bench-client/bench-client.crt ]; then
    PQC_GATEWAY=https://127.0.0.1 PQC_CA_CHAIN=/etc/pki/pqc-ca/ca-chain.crt \
    PQC_ADMIN_CERT=./admin-cert/gateway-admin.crt \
    PQC_ADMIN_KEY=./admin-cert/gateway-admin.key \
    ./scripts/issue-cert.sh bench-client http://pqc-shadow-mock:80
fi

#    The live-gateway arms read the identity from $EXPORT, which defaults to
#    /root/measure-export. Set it to anywhere writable.
export EXPORT=$PWD/bench-identity
mkdir -p "$EXPORT"
cp certs/bench-client/bench-client.crt "$EXPORT/client.crt"
cp certs/bench-client/bench-client.key "$EXPORT/client.key"
cp /etc/pki/pqc-ca/ca-chain.crt        "$EXPORT/ca-chain.crt"

# 2. Check the testbed. The harness reads and writes beside its own scripts,
#    so it runs from the tree; set WORKDIR to put its output elsewhere.
cd bench
./preflight.sh          # must end "PREFLIGHT OK". If it does not, stop.

# 3. Build the hermetic comparison arms. throughput3.sh and wirebytes.sh
#    measure THESE, not the live gateway, so skipping this step makes both
#    report FAILED / ERR for every row.
./setup-classical-arm.sh           # hybrid :4433 + classical :4434
./add-pure-arm.sh                  # pure ML-KEM-768 :4435

# 4. Measure.
./verify-suite.sh                  # cert sizes, OCSP staple, PQC-only enforcement
./throughput3.sh 10 3              # three arms, CPU-normalised
./wirebytes.sh                     # handshake byte budget
./stats.py gw-pqc-main.dat         # recomputes the published latency table

# 5. Fresh latency, all four arms. Needs a PQC-capable curl, which the deploy
#    provides; confirm with `curl -V` (expect OpenSSL/3.6).
./measure-latency.sh gw-pqc-sni https://pqc-gw.local/api/v1/status \
    "$EXPORT" X25519MLKEM768 220 pqc-gw.local:443:127.0.0.1
./measure-latency.sh herm-pqc       https://127.0.0.1:4433/ hermetic/pqc       X25519MLKEM768
./measure-latency.sh herm-pure      https://127.0.0.1:4435/ hermetic/pqc       MLKEM768
./measure-latency.sh herm-classical https://127.0.0.1:4434/ hermetic/classical X25519
./stats.py *.dat
```

`bench/README.md` carries the full quick start, including `netem-sweep.sh` for the WAN sweep and
`fullchain-test.sh` for the congestion-window question. Run `gen-provenance.sh` first if you intend
to report the numbers: it records CPU, RAM, OpenSSL version and repo HEAD into `PROVENANCE.md`.

`preflight.sh` installs any missing measurement tools and refuses to proceed on a testbed that
would produce invalid numbers: a stopped container, a missing route, swap in use, or a load average
above 1.0. **Read its output rather than skipping past it.**

## Admin authorization

Admin API access is authorized by **client-certificate SHA-256 fingerprint**, not by cert subject fields. `deploy.sh` issues a bootstrap admin cert and writes its fingerprint into `ADMIN_CERT_FINGERPRINTS` in `.env` automatically.

To add more admins: issue a cert, get its fingerprint, append it (comma-separated) to `ADMIN_CERT_FINGERPRINTS` in `.env`, then `docker compose up -d management-api`.

```bash
/opt/openssl/bin/openssl x509 -in admin.crt -noout -fingerprint -sha256 \
  | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
```

## Configuration reference

Deploy-specific values are kept in a **`.env`** file at the repo root, which Docker
Compose reads automatically and substitutes into `docker-compose.yml`
(`${VAR}` references). `.env` holds real per-deployment values and is **gitignored,
never commit it**. The committed, value-less template is **`.env.example`**; copy it
to `.env` (deploy.sh does this for you) and fill in the per-environment values.

| Where | Key | Purpose |
|---|---|---|
| `.env` | `ADMIN_CERT_FINGERPRINTS` | Admin authz allowlist (SHA-256 fingerprints, comma-separated). Auto-written by `deploy.sh` from the bootstrap admin cert; fails closed if empty. |
| `.env` | `CORS_ALLOWED_ORIGINS` | Comma-separated web origins allowed to call the management API (CORS). Per-environment; set manually. Empty = no cross-origin access. |
| compose (`management-api`) | `JWT_EXPECTED_ISSUER` / `JWT_EXPECTED_AUDIENCE` | JWT validation pinning |
| compose (`management-api`) | `OPENSSL_CONF` | Points PQ OpenSSL to system config (avoids missing-file errors) |
| secrets/ | `gateway-signing.key` | RSA-2048 JWT signing key (generated, gitignored) |
| secrets/ | `control-plane-hmac.key` | `/update-routes` HMAC secret (generated, gitignored) |

## Scripts

| Script | Purpose |
|---|---|
| `scripts/deploy.sh` | **One-shot deployment**, full stack from bare Linux host |
| `scripts/teardown.sh` | Tear down, `--test-only` (remove shadow-mock + test certs) or `--all` (full: services, volumes, host PKI/OpenSSL) |
| `scripts/issue-cert.sh` | Issue ML-DSA-65 client cert, self-enrollment (ENROLLMENT_TOKEN) or admin-direct; runs on native PQ OpenSSL (incl. macOS Homebrew), Docker fallback if absent |
| `scripts/setup-pki.sh` | Bootstrap the ML-DSA PKI (called by deploy.sh) |
| `scripts/generate-gateway-secrets.sh` | JWT signing key + control-plane HMAC (called by deploy.sh) |
| `scripts/pqc-crl-renew.sh` | Regenerate CRLs (mounted into containers) |
| `scripts/init-volumes.sh` | Seed Docker named volumes |
| `scripts/build-all.sh` | Build base image + all compose services |
| `scripts/request-client-cert.sh` | Enroll a client cert via local management API (server-side) |
| `scripts/test-stack-smoke.sh` | Smoke test: all containers running and healthy |
| `scripts/test-issuance-e2e.sh` | End-to-end issuance regression test against a live gateway (issue → route → mTLS request → 200; then revoke). Run post-deploy. |

## Security notes

- Private keys (CA, server, JWT signing), the HMAC secret, client artifacts and build binaries are **gitignored**, never committed.
- Each deployment generates its **own** CA and secrets; do not share key material between environments.
- The control plane (`/update-routes`, port 8081) is HMAC-authenticated and restricted to internal networks.
- All keys and signatures on the data/admin plane use ML-DSA-65 (NIST PQC standard). TLS key exchange uses X25519MLKEM768 (hybrid classical + ML-KEM-768). Four classical elements remain and are deliberate: the ECDSA P-256 server certificate on the :8443 enrollment bootstrap channel and its self-signed enrollment CA, the classical fallback group offered there, and the internal RS256/RSA-2048 JWT used for backend identity hand-off.
- `management-api` runs as a dedicated non-root service account (`user: 1001:1001`) with **zero filesystem access to the CA tree**, no mount at all. Signing, revocation, and reads of the CA index/issued certs/CRL all go through the `pqc-ca-custodian` sidecar, the only component with any access to the intermediate private key, over an HMAC-authenticated internal API. The gateway edge also mounts the CA tree with the private-key-bearing subdirs masked, so it never sees a CA private key either.

## Licence

AGPL-3.0-only. The full text is in [LICENSE](LICENSE).

    pqc-mtls-gateway: a mutual-TLS API gateway with post-quantum client authentication
    Copyright (C) 2026 Alexander Shestakov
    Copyright (C) 2026 Rumen Doynov

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License, version 3,
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
