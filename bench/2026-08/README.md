# `bench/2026-08`, the camera-ready campaign

Every figure in the CSCN 2026 camera-ready comes from this run. It was made
**against the deployed current `main`**, which is the point: the paper describes
the shipped system, so its numbers had to be measured on the shipped system.

| | |
|---|---|
| Host | LXC guest, i9-11950H, 8 GiB |
| Measured | 2026-08-04 |
| Images | the pinned digests were rebuilt 2026-08-18 for publication. The
  OpenSSL version and its source checksum are unchanged, and those fix the
  measured behaviour; the digests do not date from the campaign |
| OpenSSL / OpenResty | 3.6.2 / 1.27.1.2, linked dynamically from `/opt/openssl` |
| Date | 2026-08-04 |
| Quiet-host gates | swap 0 MiB, load 0.15 at start |

> **What backs these numbers.** `results/` holds the raw per-sample data behind every figure,
> and the run order below regenerates it. Certificate sizes and handshake byte counts are
> determined by the algorithm, the DN and the extension set, so they reproduce to the byte on
> any host; timings scale with the machine, which is why `../EXPECTED-RESULTS.md` says to
> compare ratios rather than absolute values across hardware.

Run order: `mk-matched-pki.sh` → `mk-arms.sh` → `measure-arms.sh` → `policy.sh`,
then the live-gateway probes. Those four scripts are in `bench/`; `results/` here is the data.

## What each file backs

| File | Paper |
|---|---|
| `cert-sizes.csv` | Table II, five roles, three PKIs differing only in algorithm |
| `handshake_bytes.csv` | Table IV size row, Table V byte row |
| `netem.csv` | Table IV latency rows, unstapled |
| `latency.csv` | the three-arm latency cross-check |
| `throughput.csv` | Table V throughput |
| `policy.csv` | §V-E zero-reload policy push |

> `policy.csv` holds curl's time_* values, which are **seconds**. The columns were named
> `_ms` until 2026-08-19, so any reading taken from them before that is out by 1000x. The
> median full round trip, including a fresh TLS handshake, is **2.48 ms** over 250
> pushes. The paper's ~4.7 ms for Section V-E is an upper bound on that path, not a
> contradiction.

## The result worth stating first

**The handshake byte counts are stable across runs**:
2,285 / 21,277 / 21,213 B for classical / hybrid / pure. Between the two
campaigns OpenSSL moved from statically linked into nginx to dynamically linked
from `/opt/openssl`. Byte counts are protocol facts, so this is the expected
result, and it is what licenses describing the current build while citing
measurements.

**At a measured 50.1 ms RTT the post-quantum arms cost +1.9 ms**, not a further
round trip — measured **without OCSP stapling**.

The shipped `docker-compose.yml` runs with `ssl_stapling on`. A stapled server
flight is 20,540 B, over TCP's 14,480 B initial window by one certificate, and
any client sending `status_request` does pay one extra round trip. These rows
describe the unstapled case; see `../EXPECTED-RESULTS.md` for both.

## Two figures that are NOT from this campaign

Both are flagged rather than silently carried:

- **The VPN cross-check** needs a client off the hypervisor, so it is measured
  separately from the rest of this campaign; `results/vpn/` carries its samples.
- **The `initcwnd` control experiment** (15,857 B two-certificate flight; the
  penalty vanishing at `initcwnd 20`) is the diagnostic that
  explains *why* the original number appeared. It is cited as history, not as a
  current measurement.

## Reading these without being misled

**Do not quote a ratio from `results/latency.csv`.** Its classical arm's three
repeats came in at 2.264 / 2.95 / 3.086 ms — a 36.3% spread from host SMT
contention, not from anything in the software. `latency-stats.py` refuses to
reject an outlier below five repeats, because at three it cannot tell one bad
repeat from a bad majority, and it prints that refusal. A ratio taken from this
file inherits the inflated baseline: it computes to 1.82x, which is wrong.

**The loopback ratio is in `results/netem.csv`**, whose 0 ms row gives
classical 2.256 ms against hybrid 4.409 ms, a ratio of **1.95x**. That is the
figure the paper's loopback comparison rests on.

**The CPU ratio is run-dependent.** This campaign gives 2.90×. Seven
measurements across three hosts span 2.14×–3.03×. Report it as indicative.

**Say whether SNI was sent.** The live gateway's server flight is 11,071 B with
SNI and 11,067 B by IP literal. The 4 bytes are the empty `server_name` echo.
