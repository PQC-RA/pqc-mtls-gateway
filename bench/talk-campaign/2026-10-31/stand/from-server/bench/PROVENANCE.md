# Benchmark Provenance, QS-GW-LXC5

**Generated:** 2026-10-31T14:46:32Z

> Every figure produced on this host MUST be cited with this host and date. Do not
> merge it into a table carrying numbers from different hardware without attribution.

## Testbed

| Field | Value |
|---|---|
| Host | QS-GW-LXC5 |
| CPU | 11th Gen Intel(R) Core(TM) i9-11950H @ 2.60GHz |
| Cores visible | 8 |
| RAM | 16192 MiB |
| Swap | 0 MiB total, 0 MiB in use |
| AVX-512 | present |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.17.13-2-pve |
| Virtualization | lxc |

## Software

| Field | Value |
|---|---|
| PQ OpenSSL | OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026) |
| curl | curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 |
| Repo HEAD | `` |
| Branch |  |
| Working tree | clean |
| Containers | a23-ca-custodian a23-crl-renewer a23-gateway a23-management-api a23-ocsp-pq a23-pki-dist a23-redis a23-shadow-mock pqc-ca-custodian pqc-crl-renewer pqc-gateway pqc-mtls-management-api pqc-ocsp-pq pqc-pki-dist pqc-redis pqcfix-ca-custodian pqcfix-crl-renewer pqcfix-gateway pqcfix-management-api pqcfix-ocsp-pq pqcfix-pki-dist pqcfix-redis upg1-ca-custodian upg1-crl-renewer upg1-gateway upg1-management-api upg1-ocsp-pq upg1-pki-dist upg1-redis upg1-shadow-mock  |

## Cryptographic configuration

| Arm | Group | Server auth | Client auth |
|---|---|---|---|
| PQC, live gateway :443 | X25519MLKEM768 | ML-DSA-65 | ML-DSA-65 |
| PQC, hermetic :4433 | X25519MLKEM768 | ML-DSA-65 | ML-DSA-65 |
| Classical, hermetic :4434 | X25519 | ECDSA P-256 | RSA-2048 |

Resumption is DISABLED on every arm: servers run `-no_ticket -no_cache`; the latency probe
spawns a fresh curl per handshake. Verified, `s_client -reconnect` reports 0 Reused.

## PKI

| Field | Value |
|---|---|
| Intermediate CA SHA-256 | `68:A1:2C:D6:F7:60:D1:74:88:14:DF:55:55:AB:63:F8:1D:72:14:04:94:5E:2C:74:24:C9:7C:3C:05:3B:0A:C8` |
| Bench client | CN=bench-client, serial 1007 |
| CA index | 120 revoked, 21 valid |

> This CA is unique to this deployment. Certificates from .22/.23/.24 carry an identical
> subject DN (`CN=PQC-GW PQC Intermediate CA G1`) but a different key, they will NOT
> validate here. Mint client identities against this CA only.

## Metric definitions

- **Handshake latency** = `time_appconnect - time_connect`, ms (TLS only, TCP excluded).
  N=220, first 20 discarded -> N=200. 95% CI = mean +/- 1.96*(sd/sqrt(N)).
- **Throughput** = `openssl s_time -new`. conn/USER-sec is single-core CPU-normalised;
  conn/REAL-sec is wall-clock wrapped with `date +%s.%N` (s_time's own real-seconds is
  integer-rounded and too coarse for short windows).

## Known caveats for this host

- Routing policy is **durable** (`pqc-redis` running) - it survives a management-api restart.
- `pqc-shadow-mock` has `restart: no` by design (test-only backend) - it does **not** come
  back after a reboot, and every request then 502s.
- Both are checked by `./preflight.sh`. Run it before every campaign.
