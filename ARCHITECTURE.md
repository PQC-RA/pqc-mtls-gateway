# PQC TLS Gateway, Architecture

## Overview

A post-quantum mutual-TLS API gateway running as a Docker Compose stack. It terminates client connections with TLS 1.3 using a hybrid post-quantum key exchange (X25519MLKEM768) and ML-DSA-65 certificate authentication, enforces per-client routing and rate-limit policy, and hands off a cryptographically-attested client identity (RS256 JWT) to backend services. A full PKI, OCSP responders, a CRL renewer, and a NestJS management API are co-deployed in the same stack.

---

## Services

| Service | Role |
|---|---|
| **gateway** | OpenResty edge, PQC TLS termination, mTLS enforcement, per-client policy routing, JWT minting |
| **management-api** | NestJS control plane, certificate lifecycle, enrollment tokens, routing policy, CRL, audit |
| **ocsp-pq** | OCSP responder for the ML-DSA-65 chain |
| **crl-renewer** | Periodically regenerates and publishes CRLs |
| **pki-dist** | Serves CA certificates and CRLs over HTTP |
| **pqc-ca-custodian** | Sole holder of the intermediate CA private key; exposes a narrow signing and revocation interface |
| **redis** | Backing store for routing policy state |
| **shadow-mock** | Test backend |

---

## Network topology

Four Docker bridge networks partition trust boundaries:

| Network | Members | Purpose |
|---|---|---|
| `pqc-edge` | gateway | External-facing TLS termination |
| `pqc-internal` | gateway, shadow-mock | Proxy to registered backends |
| `pqc-pki` | gateway, ocsp-pq, pki-dist, crl-renewer, pqc-ca-custodian, management-api | PKI services; CA files and CRLs |
| `pqc-mgmt` | gateway, management-api, redis | Control-plane communication |

The management API binds only to `127.0.0.1:3000` and is never directly reachable from outside the host.

---

## Port layout

| Port | Protocol | Purpose |
|---|---|---|
| 443 | TLS 1.3 + mTLS | Main data/admin plane, `ssl_verify_client on`, ML-DSA-65 server cert, ML-DSA-65 client cert required |
| 8443 | TLS 1.3 | Enrollment bootstrap, MLKEM key exchange + **classical (ECDSA P-256)** server cert, no client cert; proxies only the CSR-signing route |
| 8081 | TLS (internal) | Gateway control plane, HMAC-authenticated, restricted to loopback and 172.16.0.0/12 (the default Docker bridge range), never published to host |

---

## PKI hierarchy

```
ML-DSA-65 Root CA                          (data/admin plane, port 443)
└── ML-DSA-65 Intermediate CA
    ├── Gateway TLS server certificate  (SAN: server IP + domain names)
    ├── OCSP signing certificate
    └── Client certificates  (issued to service operators)

ECDSA P-256 enroll-classical-ca            (bootstrap plane, port 8443 only)
└── enroll-classical leaf  (same SANs as the ML-DSA server cert)
```

The data/admin plane (443) uses ML-DSA-65 for all keys and signatures (NIST PQC standard, lattice-based). TLS key exchange everywhere uses X25519MLKEM768 (hybrid classical + ML-KEM-768 post-quantum). The only classical *certificate* is the `enroll-classical` leaf presented on the pre-enrollment bootstrap channel (port 8443), see [TLS and mTLS](#tls-and-mtls) for why classical server auth is acceptable there. The only other classical element is the internal RS256/RSA-2048 JWT used for backend identity hand-off. The enrollment CA is a separate self-signed ECDSA root generated per-deployment by `scripts/gen-enroll-classical-cert.sh`; operators import `enroll-classical-ca.crt` to trust the bootstrap page.

The intermediate CA private key is held solely by the `pqc-ca-custodian` container, which runs as non-root and exposes a narrow signing and revocation interface on the PKI network. The management-api has no mount of the CA tree and never reads the key; it requests every signature and revocation over that interface. The CA files are mounted read-only into the gateway and OCSP containers, with the private-key-bearing directories masked.

---

## TLS and mTLS

The design principle is: **post-quantum key exchange and authentication on the authenticated plane (:443), where a classical group is rejected outright.** Four classical dependencies remain, all of them on the pre-enrollment listener or on internal hops: the ECDSA P-256 server certificate on :8443, the X25519 key-exchange fallback on :8443 (`Groups X25519MLKEM768:X25519`), the three RSA-2048 keys signing the RS256 identity tokens handed to backends, to the admin API and to cert-lookup, and the RSA-2048 internal-TLS chain that carries the JWKS fetch. Symmetric HMAC-SHA256, on the control-plane and custodian channels, is not affected by quantum search in the way asymmetric primitives are.

**Data/admin plane, port 443 (fully ML-DSA mutual TLS):**

- **Key exchange:** X25519MLKEM768 (hybrid classical + ML-KEM-768 post-quantum)
- **Authentication:** ML-DSA-65 certificates on both sides, server cert presented by the gateway, client cert presented by service operators (`ssl_verify_client on`; `ssl_conf_command ClientSignatureAlgorithms ML-DSA-65` restricts client auth to ML-DSA-65)
- **Protocol:** TLS 1.3 only, older versions are not negotiated
- **CRL enforcement:** The gateway loads the combined CRL at startup and a background worker polls for updates. Revoked certificates are rejected at the TLS handshake.

**Enrollment bootstrap plane, port 8443 (MLKEM KE + classical server auth, no mTLS):**

- **Key exchange:** X25519MLKEM768, **still post-quantum.** Confidentiality of the channel is unchanged; only the server certificate's signature is classical.
- **Server authentication:** a **classical ECDSA P-256** certificate (`enroll-classical`), *not* ML-DSA-65. Browsers and standard TLS clients cannot validate an ML-DSA-65 server certificate (they fail with `SSL_ERROR_NO_CYPHER_OVERLAP`), so an operator who does not yet have a client certificate could not even load the enrollment page over the ML-DSA leaf.
- **No client certificate:** operators enroll *before* they have a cert; the single-use, CN-constrained enrollment token is the sole authorization.
- **Why classical server auth is acceptable here (and nowhere else):** no long-term secret transits this channel, the operator's private key never crosses the wire (only the CSR does), the enrollment token is single-use and short-TTL, and the CSR and issued certificate are public. Forging the classical server certificate in real time would require a cryptographically-relevant quantum computer (CRQC) operating as a live MITM, which does not exist. The exposure is therefore a non-issue today, while the benefit (a browser-reachable enrollment page) is immediate. The key exchange remaining post-quantum means the channel is not even retrospectively decryptable. Port 443 is untouched by this and stays fully ML-DSA mutual TLS.

---

## Admin authorization

Admin API access is authorized by **client-certificate SHA-256 fingerprint**, not by any subject field in the certificate. An operator cannot self-authorize by requesting `OU=admin` in a CSR. The allowlist (`ADMIN_CERT_FINGERPRINTS`) is set in the compose environment; it fails closed when empty.

The gateway validates the admin's mTLS certificate, mints a short-lived RS256 JWT carrying the certificate's SHA-256 fingerprint, and injects it as a Bearer token on the proxied request. The management API verifies the JWT signature against the gateway's JWKS endpoint, checks the issuer and audience claims, then checks the fingerprint against the allowlist.

---

## Certificate issuance and enrollment

### Two-party self-enrollment model

The design separates authorization (admin) from key generation (operator) so the operator's private key never leaves their machine.

1. **Admin** creates a single-use, CN-constrained enrollment token via the admin API on port 443 (mTLS required). The token records the exact CN the operator is allowed to enroll.
2. **Admin** hands the token to the operator out-of-band (secure channel).
3. **Operator** generates their own ML-DSA-65 key pair locally and creates a CSR with the authorized CN.
4. **Operator** submits the CSR and token to the enrollment endpoint on port 8443. No client certificate is required here, the token is the sole authorization. The POST body must use the field name `enrollmentToken` (not `token`) for the enrollment credential.
5. The management API verifies the CSR self-signature, **rejects the CSR with HTTP 400 if its public-key algorithm is not ML-DSA-65 (enforced before token consumption or signing, fail-closed)**, extracts the CN, checks it against the token's CN constraint atomically (Redis Lua script; in-memory fallback for single-instance), and signs the CSR with the intermediate CA.
6. A CN mismatch returns 403 **without consuming the token**, so the legitimate operator can still use it. A stolen token cannot be used for a different CN.

### CN constraint security property

Because the gateway uses the client certificate CN as the routing key, a forged CN could redirect traffic to the wrong backend. The CN constraint on enrollment tokens prevents this: the admin explicitly authorizes exactly one CN per token, and the constraint is enforced atomically before signing.

---

## Request routing (data plane)

For every inbound request on port 443:

1. Gateway terminates TLS; nginx verifies the client certificate against the CA chain and CRL.
2. A Lua policy router reads the client's CN from the verified certificate subject.
3. The router looks up the CN in a shared-memory route table (populated by the control plane).
4. It enforces: path allowlist, per-client rate limit (per-second fixed-window counter in shared memory), CRL status.
5. On success, it sets the upstream backend address and proxies the request.
6. The gateway mints a short-lived RS256 JWT carrying the client CN and the SHA-256 fingerprint of its certificate, and injects it as an identity header so backends can trust the caller's identity without re-verifying the certificate.

---

## Control plane (zero-reload routing)

Route updates do not require an nginx reload:

- The management API POSTs the full route document to the gateway's internal control plane endpoint (`gateway:8081/update-routes`), authenticated with an HMAC-SHA256 body signature.
- The control plane Lua handler validates the payload, writes it to shared memory immediately (visible to all worker processes), and atomically persists it to disk for restart recovery.
- On gateway restart, the `init_by_lua_block` reloads the persisted route document from disk so routing is available before the management API re-pushes.
- The data plane reads only from shared memory on each request, no disk I/O per request.

---

## Security posture

**In place:**
- `no-new-privileges` and `cap_drop ALL` on every service, with a minimal `cap_add` only where a process must bind a privileged port or drop its workers to an unprivileged uid; read-only root filesystem with tmpfs for writable paths on the gateway, OCSP responder, management-api and CA custodian
- Admin authorization by certificate fingerprint (not subject fields), self-authorization via CSR is structurally impossible
- Enrollment tokens: single-use, TTL-bounded, CN-constrained, atomic consumption
- Control plane: HMAC-authenticated, restricted to 127.0.0.1 and 172.16.0.0/12 — the Docker bridge range this stack uses, not all of RFC 1918. A deployment on a different Docker pool must widen `allow` in `nginx.conf`. Not published to the host
- All secrets (CA keys, JWT signing key, HMAC secret) are gitignored and generated locally per deployment; no secret sharing between environments
- CA private keys are held only by `pqc-ca-custodian`, which exposes a narrow signing interface on the PKI network. The management-api never reads them; its only PKI mount is the public `internal-tls-ca.crt`
- **Post-quantum-only client authentication is enforced at two independent points, and both are required:**
  - *Handshake:* `ssl_conf_command ClientSignatureAlgorithms ML-DSA-65` restricts the CertificateRequest to ML-DSA-65. Without it the gateway advertises the full classical signature-algorithm list, and a classical-keyed certificate signed by the post-quantum intermediate authenticates successfully. Chain validation alone does not enforce a post-quantum client key. The file-form command name is `ClientSignatureAlgorithms` and the value token is `ML-DSA-65`; the form `ClientSigAlgs id-ml-dsa-65` is invalid and makes nginx fail to start under OpenSSL 3.6.2
  - *Issuance:* `assertCsrKeyAlgorithmAllowed` refuses to sign any CSR whose public key is not ML-DSA-65, fail-closed and before token consumption, so a classical-keyed client certificate cannot be issued in the first place
- OCSP stapling is enabled and verified for the ML-DSA-65 chain (`ssl_stapling on; ssl_stapling_verify on`). nginx/OpenResty 1.27.1.2 with OpenSSL 3.6.2 fetches from the responder, verifies the ML-DSA-65 signature on the response and staples it inline
