# Measurement campaign, 31 October 2026

Every number in `deck/PQC-mTLS-Amsterdam-2026.pptx` comes from this folder (via `deck/data.js`).

- **Gateway:** the gateway host (203.0.113.99 in these files), i9-11950H, LXC, Ubuntu 24.04, OpenSSL 3.6.5, OpenResty 1.31.8.1, public commit 086e235.
- **Device:** MacBook, Homebrew OpenSSL 3.6.2, curl 8.21, over the VPN (RTT ≈ 34 ms median, MSS 1,380 B).

| Slide | What | Files |
|---|---|---|
| 2 | Live handshake and gateway log line | `live/proof-s_client-mac*.txt`, `live/access-log-line-talk-probe-01.json` |
| 6 | Enrollment over the network; hostile CSRs on the live CA | `device/talk-*/enroll.tsv`, `live/negative-issuance/` |
| 7 | Certificate sizes (matched PKIs), issuance N=50 | `stand/from-server/bench/pki/cert-sizes.csv`, `stand/from-server/issuance/issuance.csv` |
| 8 | Bytes, CPU, real-link latency, primitive speed | `stand/from-server/matched-bytes.tsv`, `stand/from-server/throughput3.log`, `stand/vpn-matched-latency.tsv`, `stand/openssl-speed.txt` |
| 9 | Staple vs initial window (server-side capture, N=60/arm) | `live/staple-vpn.tcpdump.txt`, `live/staple-vpn-handshakes.tsv`, `live/handshake-bytes-mac.tsv` |
| 10 | Header buffer, stock nginx | `stand/header-buffer/result.tsv` |
| 11–12 | Classical leaf under a PQ CA, with and without the guard | `stand/from-server/trap/` |
| 14 | Autonomous renewal, 7 min | `device/talk-renew-02/renew-loop.log`, `device/talk-renew-02/probe.tsv` |
| 15 | Revocation, 20 devices (series C) | `live/revocation/revocation-vpn.tsv`, `live/revocation/revocation-vpn-codes.tsv` |
| 17 | Client matrix | `clients/matrix-server-side.tsv`, `clients/matrix-mac-side.tsv` |

**Discarded, kept for honesty:**

- `live/revocation/_aborted-series-network-outage/` was cut by a client-side network outage.
- `live/revocation/_series-b-flawed-probe-criterion/` counted nginx's HTTP 400 as "accepted". It also hit the 5/min enrollment limit.
- `device/_failed-attempt-bash32-*` failed because macOS bash 3.2 cannot run the renewal client unchanged.

**Test identities on the live CA:**

- Every certificate issued here is revoked or expired, except `talk-probe-01`, which is valid until 30 Nov 2026.
- `talk-probe-01` was kept for re-shooting. Revoke it when it is no longer needed.

**Additions on 3 Nov 2026** (in `campaign/2026-11-03/`). They were made after an independent audit of this deck against Alexander's rev9.

| What | File | Result |
|---|---|---|
| Classical client on the live gateway | `live/classical-client-live.txt` | HTTP 400, "No required SSL certificate was sent" |
| Issuance, two runs N=50 (replaces the noisy 31 Oct run) | `stand/issuance-r1.csv`, `stand/issuance-r2.csv` | 14.2 / 12.1 / 52.4 ms pooled |
| Client leaf vs full chain, time to first byte, N=60 each | `live/client-chain-vpn.tsv` | +4.8 ms at 5.5 ms RTT, one round trip |
| The VPN's matched arms on loopback on the gateway host, same method, N=200 each (replaces the hermetic reference values, whose classical arm had an RSA client) | `stand/loopback-matched/` | 4.06 / 2.25 ms, +1.8 ms: the computation alone; the VPN run adds the link (+8.2 ms) |

Corrections in the deck:
- The intermediate key is in the custodian **and** the CRL renewer.
- ML-DSA in TLS 1.3 is still draft-ietf-tls-mldsa-06.
- The default for `copy_extensions` is none.
- The CPU figure is client-side `s_time`.
- The live gateway answers HTTP 400 to a classical client.
- Admin tokens are already ML-DSA-65.

Tools: `campaign/tools/`. The stand ran from `/root/talk-campaign-20261031` on the gateway host and never attached to the live Docker networks.
