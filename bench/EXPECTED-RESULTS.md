# Expected results

Reference values measured 2026-07-30 on a clean tree.
Testbed: i9-11950H, 8 cores, 8192 MiB, AVX-512, LXC guest, OpenSSL 3.6.2, curl 8.5.0.

Use this to check a re-run rather than trusting it. **Expect timings within ~10% on this
hardware, and only ratios to transfer to different hardware.**

**Byte counts match exactly on the post-quantum arms and vary by a few bytes on the
classical one.** ML-DSA-65 signatures are fixed-length, so a PQ arm reproduces to the byte.
An ECDSA P-256 signature is DER-encoded as two INTEGERs, each of which loses a leading byte
when its high bit is clear, so the classical arm's totals move over a ~5-byte span between
otherwise identical runs. Three runs of the hermetic classical leaf arm gave totals of
3,378 / 3,381 / 3,383 B while the hybrid arm gave 20,782 B every time. Treat a few bytes of
movement on a classical arm as expected, and any movement on a PQ arm as a real change.

## Which numbers came from which rig — read this before comparing anything

Three rigs produce numbers in this directory, and a figure from one is **not**
comparable with a figure from another. Every ratio below is correct for its own
rig; none of them contradict each other.

| rig | what it is | where its numbers live |
|---|---|---|
| **Hermetic** | `s_server` arms on loopback with their own self-contained PKI, built by `setup-classical-arm.sh` and `add-pure-arm.sh`. No gateway involved | this file |
| **Deployed** | the running gateway with the deployment's own PKI and an issued client identity | this file, rows labelled *live gateway* |
| **Matched-PKI** | two three-tier PKIs identical except for algorithm, built by `mk-matched-pki.sh` | `2026-08/results/cert-sizes.csv` |

The figures reported in the paper come from `2026-08/results/`, which is a
**separate campaign** with its own README. Where a number here differs from the
paper, check the rig and the campaign before treating it as a discrepancy.

Two concrete cases that look like contradictions and are not:

- **Handshake bytes.** The hermetic classical arm totals ~3,381 B against the
  hybrid's 20,782 B, a ratio near 6.1x. The paper's Section V-C quotes 2,285 B
  against 21,277 B, near 9.3x. Different rigs, different client certificates,
  both correct. A wire-byte ratio is meaningless without its chain configuration.
- **VPN ratio.** `2026-08/` reports 1.30x at a measured 11.4 ms RTT. The post-quantum
  cost is compute and the network term is shared by both arms, so the ratio **falls as
  the path lengthens** — a ratio measured over a shorter tunnel is legitimately higher.
  Quote it with the RTT it was measured at, never on its own.

---

## Deterministic, these must match exactly

Certificate size is fully determined by algorithm, subject DN, issuer DN, serial, validity
encoding and extension set. A mismatch means the construction differed, not that the system
changed.

### Certificate sizes (DER bytes), `verify-suite.sh`, `certsize.sh`

| Role | Bytes |
|---|---:|
| Root CA (ML-DSA-65) | **5,822** |
| Intermediate CA | **6,016** |
| Server TLS leaf | **6,107** |
| Client leaf `CN=gateway-admin, OU=Admin` | **6,134** |
| OCSP signing | **5,882** |
| `enroll-classical` leaf (ECDSA P-256) | 624-626 |
| `internal-tls` leaf (RSA-2048) | 1,002 |

> The client row is **identity-dependent**. `CN=bench-client, O=ACME` on the same deployment is
> 5,614 B. Always record which identity a client-leaf figure came from.

> The ECDSA row is a **range, and re-issuing moves it**: an ECDSA signature's DER length depends
> on the random `r` and `s`, so a leading zero byte makes the certificate one byte shorter.
> Observed at both 624 and 626 on the same tree. The ML-DSA and RSA rows are fixed-length and
> must match exactly.

### Handshake wire bytes, `wirebytes.sh`

MTU forced to 1500. Live gateway, connected by hostname so **SNI is sent**:

| Client sends | read | written | total |
|---|---:|---:|---:|
| leaf only | **11,071** | 10,611 | **21,682** |
| full chain | **11,071** | 22,481 | **33,552** |

Hermetic arms, leaf-only client:

| Arm | read | written | total |
|---|---:|---:|---:|
| PQC hybrid | 10,303 | 10,479 | 20,782 |
| PQC pure | 10,271 | 10,391 | 20,662 |
| Classical | 864 | 2,517 | 3,381 |

> Connecting by **IP literal** gives 11,067 B instead of 11,071 B. The 4 bytes are the server's
> zero-length `server_name` echo in EncryptedExtensions. Not a regression.

> The Classical row carries the same ECDSA variance and reproduces within ~2 B. The PQC rows are
> fixed-length and reproduce exactly.

### OCSP, `verify-suite.sh`, `check-ocsp-and-policy-values.sh`

| | Bytes | Share of the ~33.5 KB handshake |
|---|---:|---:|
| Staple, responder leaf only (current config) | **9,498** | **+28.3%** |
| Staple with `-rother` (full signer chain) | **15,514** | **+46.2%** |
| Difference | 6,016 | = one ML-DSA-65 intermediate |
| Signed status alone (total - signer cert) | 3,616 | |

`Cert Status: good`, response `Signature Algorithm: ML-DSA-65`.

> **The first connection after a deploy may not carry the staple.** In one of two back-to-back
> runs here, section 2 printed the flight sizes but no decoded OCSP response. The gateway
> fetches and caches the response on the first request that asks for it, so that first
> handshake goes out without one, while the size measurements later in the same run already
> show it at 20,540 B. Run it again to see the response. An empty first run is warm-up, **not**
> evidence that stapling fails for post-quantum chains.

---

## Timing, expect within ~10% on identical hardware

### Handshake latency, N=200, `measure-latency.sh` + `stats.py`

| Arm | min | median | mean | 95% CI | P95 | P99 | sd | CV |
|---|---:|---:|---:|---|---:|---:|---:|---:|
| Live gateway, SNI | 3.379 | 4.262 | **4.503** | ±0.116 | 6.271 | 7.083 | 0.834 | 18.5% |
| Live gateway, IP literal | 3.470 | 4.404 | 4.550 | ±0.115 | 6.141 | 7.198 | 0.827 | 18.2% |
| From a second host | 3.342 | 4.484 | **4.629** | ±0.113 | 6.234 | 6.926 | 0.815 | 17.6% |
| Hermetic hybrid | 3.171 | 4.146 | 4.286 | ±0.103 | 5.870 | 6.342 | 0.744 | 17.4% |
| Hermetic pure | 3.110 | 3.997 | 4.138 | ±0.103 | 5.587 | 6.674 | 0.744 | 18.0% |
| Hermetic classical | 2.431 | 2.599 | **2.616** | ±0.014 | 2.822 | 2.935 | 0.100 | **3.8%** |

**The classical CV of 3.8% against PQC's 17–20% is a real property**, not noise, PQC latency is
markedly more variable, and its standard deviation is 7–8× wider.

### Throughput, 3×10 s windows, `throughput3.sh`

| Arm | conn/USER-s | ms CPU/HS | conn/REAL-s | ms wall/HS |
|---|---:|---:|---:|---:|
| classical | **1229.4** | 0.813 | 872.6 | 1.146 |
| hybrid | **562.4** | 1.778 | 347.7 | 2.876 |
| pure | **629.4** | 1.589 | 374.2 | 2.673 |

`classical/hybrid = 2.19×` CPU, `2.51×` wall · `pure/hybrid = 1.12×`

> `conn/USER-s` is CPU-normalised, `conn/REAL-s` is wall-clock. **Never compare one against the
> other.**

### WAN sweep, `netem-sweep.sh`, `check-published-values.sh`

Median handshake, ms:

| One-way delay | Effective RTT | classical | hybrid | pure |
|---:|---:|---:|---:|---:|
| 0 ms | 0.0 | 2.518 | 3.978 | 4.037 |
| 5 ms | 10.1 | 12.784 | 14.396 | 14.201 |
| 25 ms | 50.2 | **53.270** | **54.624** | **54.361** |

**Unstapled, no arm pays an extra round trip:** the gateway's 11,071 B server flight is under
TCP's initial congestion window (14,480 B = 10 x 1448).

**Stapled, it does.** The shipped `nginx.conf` sets `ssl_stapling on`, and a stapled flight is
20,540 B — over the window by one certificate, because the staple carries the responder's own
certificate. Any client sending `status_request` pays one extra round trip, about +50 ms at a
50 ms RTT. The rows above were measured without a staple; state which case a figure describes.

### Full-chain client flight, `fullchain-test.sh`

Measured 2026-08-13 on a 4-core LXC guest, **not** the 8-core reference testbed. The verdict is a
round-trip count, which survives the change of host; the absolute times do not.

| Client cert file | c2s | s2c |
|---|---:|---:|
| leaf only (1 cert) | 16,839 | 23,264 |
| full chain (3 certs) | 22,688 | 23,248 |

At a measured 50.2 ms RTT the chain arm costs **0.10 ms** more than the leaf arm, so **no extra
round trip is attributable to the client chain** even though the chain flight is well over IW10.
The initial congestion window constrains the **server's** first burst, before any ACK returns; the
client sends its certificate a full round trip later, by which point cwnd has already grown. This
is why the server flight is the one that decides whether the handshake pays a round trip.

> The c2s/s2c figures above are the script's own byte counters and are **not** the server flight
> that `wirebytes.sh` measures at 11,071 B. What they span has not been pinned down, so do not
> compare them against the 14,480 B window and do not quote them as flight sizes. The `IW10
> reference: ~14600 B per direction` line the script prints invites exactly that comparison.

### The round-trip mechanism, `rtt-proof.sh`, `rtt-cwnd2.sh`

Deliberately reintroducing the artifact, at 25 ms one-way (RTT 50.1 ms):

| `initcwnd` | 1 cert (10,303 B) | 2 certs (15,857 B) |
|---:|---:|---:|
| 10 (default) | 54.289 | **104.059** |
| 20 | 54.309 | **54.785** |
| 30 | 54.468 | 54.797 |

A second certificate costs **+49.77 ms against a 50.1 ms RTT**, one full round trip, and
widening `initcwnd` removes it with the same two certificates. `tcpdump` shows the server push
13,893 B, wait ~50 ms, then send the remaining 1,965 B.

> `rtt-cwnd2.sh` sets `initcwnd` on the **host route** `local 127.0.0.1 dev lo`. Setting it on
> `local 127.0.0.0/8` silently affects nothing, because `ip route get 127.0.0.1` resolves to the
> host route.

### Concurrency, `concurrency-from-client.sh`

200 requests per level, driven from a second host:

| Concurrency | Success | mean HS ms | P95 HS ms |
|---:|---:|---:|---:|
| 1 | **100%** | 4.698 | 6.444 |
| 10 | **100%** | 26.727 | 67.913 |
| 20 | **100%** | 42.476 | 87.041 |
| 30 | **100%** | 59.931 | 97.761 |
| 50 | **100%** | 65.534 | 112.752 |

**Success is the result. The latency column is not a gateway measurement** if the load generator
shares a hypervisor with the gateway, the gateway's load average was 0.35 on 8 cores at 50
concurrent.

If success drops below 100%, check for **HTTP 429** before concluding anything: `issue-cert.sh`
creates routes with a default `rate_limit: rps 100, burst 200`.

### Memory, `memcheck.sh`, `allmem.sh`

Working set (`anon`), at genuine idle:

| Container | `memory.current` | **anon** |
|---|---:|---:|
| `pqc-mtls-management-api` | 76.9 MiB | **67.6 MiB** |
| `pqc-ca-custodian` | 73.5 MiB | 13.5 MiB |
| `pqc-gateway` | 55.9 MiB | **48.8 MiB** |
| **Whole stack (9 containers)** | 279.0 MiB | **157.0 MiB** |

Idle CPU: median 0.07%, mean 0.133% over 10 samples.

> `docker stats` shows `memory.current`, which includes reclaimable page cache. The custodian
> looks second-heaviest by that metric and is sixth by working set.

---

## Pass / fail, these are binary

| Check | Expected | Script |
|---|---|---|
| ML-DSA-65 client reaches the backend | HTTP **200**, `pqc-shadow-success` | `verify-suite.sh` |
| No client certificate | HTTP **400** | `verify-suite.sh` |
| CN with no route | HTTP **403** | `check-negative-controls.sh` |
| Revoked certificate, offline | `error 23 at 0 depth lookup: certificate revoked` | `check-negative-controls-detail.sh` |
| Revoked certificate, data plane | refused within ~10 s of CRL publication | `check-negative-controls-detail.sh` |
| Server requests only `id-ml-dsa-65` | exactly that, nothing else | `verify-suite.sh` |
| RSA / EC / ML-DSA-44 CSRs | **400 ×3**, CA index hash **unchanged** | `verify-suite.sh` |
| **Classical-keyed cert signed by the real intermediate** | `openssl verify` **OK**, handshake **400 "No required SSL certificate was sent"**, control **200** | `check-negative-controls.sh` |
| Policy change | **0** nginx reloads | `check-ocsp-and-policy-values.sh` |
| Server certificate count on every arm | **1** | `setup-classical-arm.sh` |

---
