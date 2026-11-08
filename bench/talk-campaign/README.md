# Talk campaign data and scripts (October and November 2026)

Raw measurements, scripts and results behind the slides of "Making ML-DSA Work for Machine-to-Machine mTLS"
(PKI Consortium PQC Conference, Amsterdam, 3 December 2026). Everything here was produced against this
repository's gateway (an LXC container on an Intel i9-11950H host, Ubuntu 24.04, OpenSSL 3.6.5, OpenResty 1.31.8.1) and a
MacBook device (Homebrew OpenSSL 3.6.2, curl 8.21) over a VPN.

| Folder | What | Gateway commit |
|---|---|---|
| `2026-10-31/` | First campaign: live enrollment, hostile CSRs, sizes, issuance, bytes, CPU, latency, staple, header buffer, ECDSA leaf under a PQ CA, renewal (7 min), revocation (20 devices), client matrix. Its own `README.md` maps slides to files. | 086e235 |
| `2026-11-03/` | Additions after an audit: classical client on the live gateway, issuance (two runs of 50), client leaf versus full chain, loopback arms, revocation after the custodian changes. | 086e235 / branch builds |
| `2026-11-04/` | Full re-measurement after the ADR-024 cut-over, plus renewal semantics, expiry on an open connection, the 2x2 enforcement matrix and the issuance test with the key-type check removed. `RESULTS.md` compares every figure with the slide; server-side files added later are in `server/`. | 83a4f60 |
| `2026-11-05/` | Three checks: CPU per handshake with matched arms, a Mac client's full chain against the test stand, Java 25 and 27 against the live gateway. | 83a4f60 |
| `2026-11-07/` | Re-measurement on the test stand with the live certificate profile (`stand/`); enrollment and revocation on a throwaway stack, with the `ssl_crl` backstop check (`stack/`); where the CPU goes and the header size (`cpu-split/`). | 83a4f60 (stack); stand image from 11a5422 |
| `2026-11-08/` | Client re-check against the live gateway: Linux curl over mutual TLS and Java 21 (`clients/`), and why the 4 Nov curl row says `000`. | 83a4f60 |
| `tools/` | Enrollment, revocation timing, renewal probe, matrix and issuance drivers (4 Nov versions). `tools/2026-10-31-original/` holds the first versions. `build-test8b-openssl.sh` builds the test-only patched OpenSSL client. | |

## Conditions to know before quoting a number

- The real VPN round trip was about 34 ms on 31 Oct and about 6 ms on 4 Nov. On 4 Nov, 34 ms and 70 ms were
  emulated with `tc netem` on the gateway's egress towards the test device only (removed afterwards, no bandwidth
  limit). Files and `RESULTS.md` say which is which.
- The gateway host runs several other stacks; some 4 Nov runs are noisy (issuance especially). Medians of repeated
  runs are in `2026-11-04/stand/`.
- The 4 Nov matrix and the issuance test run on isolated, throwaway stacks (own CA, own secrets, loopback ports).
  The live CA only issued and revoked clearly named test certificates (`talk-*`, `adr024-*`).
- `2026-11-04/server-scripts/a24/patch.diff` shows the single change used to switch off the key-type check in a
  copy of the management API bundle for the "issuance check removed" cells. It is a test aid, never a deployment.

## Addresses

The files keep the lab's own private addresses (RFC 1918): `192.168.1.99` is the gateway host, `192.168.1.27`
the test stand, and `192.168.1.10` the virtualisation host, which forwards the test device's VPN connections, so
they arrive from that address. Packet captures are published as recorded.

## Deliberately not included

Private keys, `identity.pem`, `pending.*`, certificate requests, `.pem` files, enrollment tokens, HMAC secrets,
the patched OpenSSL binary (build it with `tools/build-test8b-openssl.sh`; the patch is in `bench/test8b/`), and a
few first attempts that failed for harness reasons (a path with spaces, bash 3.2 on macOS). Public certificates are
kept as `.crt`.

## Reproducing

Start with `tools/enroll.sh` (admin side over SSH, device side local) and `tools/rev_series.sh`; they expect the
gateway host, the admin certificate and the CA chain path of a deployment like the one in this repository. Server
side drivers are in `2026-11-04/server-scripts/` and the repository's own `bench/` scripts.
