# Re-measurement, 4 Nov 2026 (07:50–08:35 UTC)

Gateway QS-GW-LXC5 (192.168.1.99), live repo HEAD 83a4f60 (after the ADR-024 CA-layout cut-over), OpenSSL 3.6.5, OpenResty 1.31.8.1.
Device: MacBook, Homebrew OpenSSL 3.6.2 / curl 8.21. The real VPN RTT today is ~6 ms (31 Oct: ~34 ms), so RTT-dependent tests were run
at ~6 ms (real) and at ~34 ms and ~70 ms (tc netem on the gateway's eth0, egress to the Mac's IP only, removed afterwards).

| # | Deck claim | Re-measured | Verdict |
|---|---|---|---|
| 1 | Client cert 5,659 / 930 / 533 B | 5,659 / 930 / 534 B | OK |
| 2 | Issue 14.2 / 12.1 / 52.4 ms (ML-DSA / ECDSA / RSA) | quiet run 14.9 / 12.6 / 46.4; noisy runs 16.5 / 18.4 / 48.4; 4 runs pooled 15.2 / 15.7 / 47.7 | OK in kind; "2 ms slower" is within noise |
| 3 | Device: key 30, CSR 30, enrol 0.2 s | 34 / 31 / 0.19 s (3 devices) | OK |
| 4 | 21,080 B vs 2,086 B | 21,080 vs 2,085-2,089 | OK |
| 5 | CPU 1.72 vs 0.80 ms (2.2x) | same arms 1.71 vs 0.79 (2.16x); matched ECDSA/ECDSA arms 2.03 vs 0.67 (3.0x) | OK, but the arms differ from slide 23 |
| 5b | X25519 hedge +8.7 % | +6.4 % | varies 6-9 % |
| 6 | Loopback 4.06 vs 2.25 (+1.8 ms) | 4 runs: 4.1-4.9 vs 2.2-2.4 (+1.9 to +2.5) | OK ("about +2 ms") |
| 7 | Real link 34 ms: +8 ms (39.8 vs 31.5) | real VPN 6 ms: 10.98 vs 7.63 (+3.4); emulated 34 ms: 42.1 vs 37.8, 41.9 vs 37.8 (+4.2, +4.1) | NOT reproduced; link-specific |
| 8 | Staple 38.8 -> 69.2 ms (+30), stall 28 ms | 37.6 -> 73.7 ms (+36), stall 33 ms, 11,071 vs 20,540 B (N=60, 1 of 60 got no staple) | OK |
| 9 | Full client chain costs one more round trip (+4.8 ms at 5.5 ms RTT) | +5.6 ms at 6, +5.2 at 34, +4.3 at 70 ms RTT | NOT a round trip: constant ~5 ms for this client |
| 10 | Header 8,286 B -> 400; 64 B -> 200 | same; 8,000/8,150 -> 200, 8,200 -> 400 | OK |
| 11 | ECDSA leaf under PQ CA: 200 without guard | same; with guard: alert 116 (stand) / HTTP 400 (live) | OK |
| 12 | Hostile CSRs: 400 / 201 minimal / 403, tokens survive | identical | OK |
| 13 | Renewal: 132/132 requests, 5 renewals in 7 min | 150/150 requests, 6 renewals in 7.8 min | OK |
| 14 | Revocation median 1.03 s / 1.00 s, max 2.27 s (n=20) | median 0.38 s / 0.34 s, max 1.27 s / 1.19 s (n=20, RTT 34 ms) | CHANGED (faster after cut-over) |
| 15 | Client matrix | identical (OpenSSL 3.5+, Node OK; Java 21/26, LibreSSL fail) | OK |
| 16 | Slide 4: intermediate key in two containers (custodian + CRL renewer) | verify-suite section 6: only pqc-ca-custodian holds a CA key; pqc-crl-renewer is stopped | WRONG now |
| 17 | verify-suite / negative controls | ALL GUARDS PASSED | OK |

Files: stand/, live/, device/ in this folder. The revocation series is live/rev2/ (a first attempt with a path error is not included).
