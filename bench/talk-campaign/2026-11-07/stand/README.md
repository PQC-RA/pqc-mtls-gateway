# 2026-11-07, test stand: handshake bytes and time, staple and the initial window, CPU, issuance, tickets

Measured on the test stand (Proxmox LXC, Intel i9-11950H, 6 cores; kernel 6.17.13-2-pve). Nothing live was
contacted. Server: the gateway image built from this repository (OpenResty 1.31.8.1, OpenSSL 3.6.5) with the
live gateway's TLS settings for :443 (`nginx.conf`). Client: `openssl s_client` 3.6.5 on the same host, server
verified, SNI sent, one HTTP request after the handshake.

## Setup

- **Certificates** (`mkpki.sh`, `pki/`): two PKIs with the live certificate profile (names, lifetimes and
  extensions as in the live certificates). Post-quantum, DER: root 5,822, intermediate 6,016, server 6,107,
  OCSP responder 5,882, device 5,617 B. Classical twin (ECDSA P-256): 696 / 891 / 981 / 757 / 492 B. An RSA-2048
  twin is in `pki/rs/` for issuance.
- **Arms** (`run.sh`), alternating sample by sample, 60 each (58 to 60 matched to the capture): leaf only; leaf
  with a staple requested; chain in the client's trust store (`-CAfile`, so `s_client` sends leaf,
  intermediate and root); full chain (`-cert_chain`).
- **Delay:** `tc netem` on loopback for the test ports only, 0 ms and 25 ms each way; measured round trip 50.1 ms.
- **Stopwatch:** the server-side capture (`cap-delay0.pcap`, `cap-delay25.pcap`), from the ClientHello's arrival
  to the arrival of the last packet of the client's flight. `rerun_analyse.py` turns the captures into
  `per-connection.tsv`; byte counts are `s_client`'s own totals (`samples.tsv`).
- **CPU:** `openssl s_time`, client side, 3 windows of 10 s per arm, alternating (`cpu.txt`).
- **Second pass** (`extra.sh`, `extra/`): issuance timing for ML-DSA-65, ECDSA P-256 and RSA-2048, 100 each,
  alternating, every step a new `openssl` process (`issuance.py`, `issuance.csv`); session tickets with client
  authentication on and off (`nginx-tickets.conf`, `tickets-exact.tsv`, the ticket length read from the DER of
  the saved session; `tickets.tsv` is an earlier count from a hex dump that came out about 6 % high and is kept
  only for the record); an ECDSA client certificate under the post-quantum CA against servers with and without
  `ClientSignatureAlgorithms ML-DSA-65` (`trap/`).

## Results (medians)

| | post-quantum | classical |
|---|---:|---:|
| bytes, leaf only: server to client / client to server / total | 11,071 / 10,614 / 21,685 | 1,619 / 2,251 / 3,870 |
| bytes, stapled | 20,540 / 10,623 / 31,163 | 2,723 / 2,260 / 4,983 |
| bytes, client sends its full chain | 11,071 / 22,484 / 33,555 | 1,619 / 3,848 / 5,467 |
| handshake, leaf only, no delay | 2.66 ms | 1.03 ms |
| handshake, leaf only, RTT 50.1 ms | 52.71 ms | 51.24 ms |
| stapled, RTT 50.1 ms | 103.17 ms (the server pauses 50.1 ms after 14,232 B) | 51.82 ms |
| client sends its full chain, RTT 50.1 ms | 101.91 ms (the client pauses 50.1 ms after 14,232 B) | 51.17 ms |
| CPU per handshake, client side | 2.084 ms | 0.683 ms |
| issuance, key + CSR + CA signature | 14.6 ms (5,617 B) | 12.2 ms ECDSA (492 B); RSA-2048 49.8 ms (888 B) |
| session tickets per connection, with client authentication | 2 x 5,856 B | 2 x 736 B |

The capture's timestamps are taken on loopback after the delay, so only client-to-server packets are used for
timing. Private keys were deleted on the stand after the run; none is here.
