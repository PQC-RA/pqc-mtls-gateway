# `bench/`, the measurement harness

The measurement harness behind the project's published performance figures.
`EXPECTED-RESULTS.md` records the values to expect, so a re-run can be checked rather than
trusted. Read the rig table at the top of it before comparing any number: a figure from one rig
is not comparable with a figure from another.

Run them after any OpenSSL, OpenResty or policy change. Several are **negative controls**, they
test that something is *refused*, and those are the ones that catch a security property quietly
ceasing to hold.

> **Before comparing any number here with the paper**, read the rig table at the top of
> [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md). Hermetic, deployed and matched-PKI arms produce
> different and equally correct ratios for the same system, and the paper's figures come from
> the separate [`2026-08/`](2026-08/) campaign.

## The matched-PKI scripts

`mk-matched-pki.sh`, `mk-arms.sh`, `measure-arms.sh` and `policy.sh` are the chain that produced
the campaign in [`2026-08/`](2026-08/). They live here alongside everything else.

The arms in this directory inherit the deployment's PKI, so a certificate-size comparison drawn
from them depends on that PKI's DNs and extension set. `mk-matched-pki.sh` removes that
dependency: it builds two three-tier PKIs that are byte-identical except for the algorithm, so
the size comparison can be rebuilt from scratch by anyone, on any host. Its output is
[`2026-08/results/cert-sizes.csv`](2026-08/results/cert-sizes.csv).

It also carries the remote-client-over-VPN measurement, the policy-push and policy-durability
tests, and the investigation that identified the run-to-run outliers as **host SMT contention**
rather than anything in the gateway: a slow repeat is host scheduling, not the crypto. Reject the
contaminated repeat with `latency-stats.py` rather than averaging it in, and treat an outlier here
as a property of the host before treating it as a regression.

**`policy.sh` and `re-apply-route.sh` write to a running gateway.** `policy.sh` pushes the
current policy back unchanged, so live routing is unaffected; `re-apply-route.sh` creates a
route. Neither is destructive, but do not run them against a deployment you are measuring.

## Quick start

Two steps: place the client identity, then run the driver.

```bash
# 1. The live-gateway arms need an issued client identity. $EXPORT points at it
#    and defaults to /root/measure-export; issue-cert.sh writes to ./certs/<cn>/
#    under the repo, so place it first:
export EXPORT=$PWD/bench-identity
mkdir -p "$EXPORT"
cp certs/bench-client/bench-client.crt "$EXPORT/client.crt"
cp certs/bench-client/bench-client.key "$EXPORT/client.key"
cp /etc/pki/pqc-ca/ca-chain.crt        "$EXPORT/ca-chain.crt"

# 2. Run everything that needs only this host. The harness reads and writes
#    beside its own scripts, so it runs in place; set WORKDIR to send its
#    working files elsewhere.
cd bench
./run-all.sh
```

`run-all.sh` checks the testbed, records it to `PROVENANCE.md`, builds the
hermetic arms, runs the verification suite and the negative controls, then
measures wire bytes, throughput, the live gateway and the three hermetic latency
arms, and summarises with `stats.py`. It stops at the first failure rather than
carrying on with a broken arm, and will not proceed past a failed `preflight.sh`.

It deliberately leaves out what needs root `netem`, a second machine, or a VPN:
`netem-sweep.sh`, `rtt-proof.sh`, `rtt-cwnd2.sh` and `concurrency-from-client.sh`.
Its own header lists them with the reason. The matched-PKI chain
(`mk-matched-pki.sh` → `mk-arms.sh` → `measure-arms.sh` → `policy.sh`) is a
separate rig and is also run by hand.

Compare what you get against [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md), and
read the rig table at the top of it first: a figure from one rig is not
comparable with a figure from another.

### Running the steps by hand

What `run-all.sh` does, one command at a time, plus the extras it leaves out.
Step 1 above still applies; run these from `bench/`.

```bash
./preflight.sh              # refuses to measure a broken testbed, read its output
./gen-provenance.sh         # captures CPU/RAM/OpenSSL/repo HEAD -> PROVENANCE.md
./setup-classical-arm.sh    # hermetic hybrid :4433 + classical :4434
./add-pure-arm.sh           # hermetic pure ML-KEM-768 :4435

./measure-latency.sh gw-pqc-sni https://pqc-gw.local/api/v1/status \
    "$EXPORT" X25519MLKEM768 220 pqc-gw.local:443:127.0.0.1
./measure-latency.sh herm-pqc       https://127.0.0.1:4433/ hermetic/pqc       X25519MLKEM768
./measure-latency.sh herm-pure      https://127.0.0.1:4435/ hermetic/pqc       MLKEM768
./measure-latency.sh herm-classical https://127.0.0.1:4434/ hermetic/classical X25519
./stats.py *.dat

./throughput3.sh 10 3       # CPU-normalised, 3x10 s windows per arm
./wirebytes.sh              # both chain configurations, lo MTU forced to 1500
./netem-sweep.sh 60         # 0 / 5 / 25 ms one-way
./fullchain-test.sh         # does a full-chain client flight cross IW10?
./verify-suite.sh           # cert sizes, OCSP, PQC-only enforcement -> evidence/
```

Concurrency runs **from a second machine**, see the caveat at the bottom.

## Prerequisites

| | Requirement | Why |
|---|---|---|
| OS | Linux with `tc`, `tcpdump`, `ss`, `docker`, `bc` | netem, wire capture, arithmetic |
| Crypto | **OpenSSL ≥ 3.5** with native ML-KEM/ML-DSA at `/opt/openssl` | no OQS provider is used |
| Client | `curl` **linked against that OpenSSL** | the deploy installs `/etc/ld.so.conf.d/00-pqc-openssl.conf`, so the distro curl resolves libssl/libcrypto from `/opt/openssl` and becomes PQC-capable with no extra work. Confirm with `curl -V` (expect `OpenSSL/3.6`); `measure-latency.sh` exits if it is not |
| Deployment | the stack up, with an issued client identity in `/root/measure-export` | live-gateway arms |
| Privilege | root | `tc qdisc`, `ip link set mtu`, `tcpdump`, cgroup reads |
| Quiet | swap **0 MiB used**, load average < 1.0 | tail latency is destroyed by either |

Paths are hardcoded to this deployment's layout. `env.sh.example` lists every one that needs
changing elsewhere.

## What each script does

### Setup and gating

| Script | Purpose |
|---|---|
| `preflight.sh` | **Run first.** Refuses to continue unless containers, route, mTLS, PQC handshake, swap and load are all sane. Two conditions fail *silently* into invalid numbers, see below. |
| `gen-provenance.sh` | Captures testbed state into `PROVENANCE.md`. Run at the start of every campaign; a figure without provenance is not citable. |
| `re-apply-route.sh` | Restores the bench client's route after a management-api restart. |

### Comparison arms

This is a **PQC-only deployment**, no classical certificate exists, so a classical baseline
cannot be measured against the live gateway and has to be constructed.

| Script | Purpose |
|---|---|
| `setup-classical-arm.sh` | Throwaway hermetic PKIs; hybrid `:4433` and classical `:4434`. **Asserts the server sends exactly one certificate.** |
| `add-pure-arm.sh` | Third arm, pure `MLKEM768` on `:4435`, reusing the hybrid PKI so the group is the only variable. |

| Arm | Port | Group | Server auth | Client auth |
|---|---|---|---|---|
| PQC hybrid | 4433 | `X25519MLKEM768` | ML-DSA-65 | ML-DSA-65 |
| Classical | 4434 | `X25519` | ECDSA P-256 | RSA-2048 |
| PQC pure | 4435 | `MLKEM768` | ML-DSA-65 | ML-DSA-65 |

Resumption is off everywhere: servers run `-no_ticket -no_cache` and the latency probe spawns a
**fresh curl process per handshake**. Do not "optimise" that into one curl call, it is what
guarantees every sample is a full handshake.

### Measurement

| Script | Purpose |
|---|---|
| `measure-latency.sh` | N=220 handshakes, first 20 discarded. Metric `time_appconnect - time_connect`. |
| `stats.py` | min / median / mean / 95% CI / P95 / P99 / sd / CV over a `.dat` file. |
| `throughput3.sh` | `s_time` CPU-normalised throughput across all three arms. |
| `wirebytes.sh` | Handshake wire bytes in **both** chain configurations, `lo` MTU forced to 1500. |
| `netem-sweep.sh` | WAN delay sweep, 0 / 5 / 25 ms one-way. |
| `fullchain-test.sh` | Does a full-chain *client* flight cross IW10? Measured with `tcpdump`, not `s_client` counters. |

### Verification and negative controls

**These are the ones to wire into CI.** Each tests that something is refused, and a
negative control that quietly stops testing anything looks exactly like a pass.

| Script | Tests |
|---|---|
| `verify-suite.sh` | Certificate sizes, OCSP stapling, PQC-only enforcement, functional paths → `evidence/` |
| `check-negative-controls.sh` | Out-of-route CN → 403; revocation; **the classical-key bypass handshake** |
| `check-negative-controls-detail.sh` | Revocation via the correct endpoint, plus hardened bypass evidence |
| `check-ocsp-and-policy-values.sh` | OCSP `-rother` comparison; zero-reload latency; `sendRawCert` |
| `check-published-values.sh` | Pure arm under netem and in wire bytes; OCSP signer DER; idle CPU |

The **bypass test** in `check-negative-controls.sh` is the most important thing in this directory. It mints a
classical-keyed certificate signed by the legitimate ML-DSA intermediate and confirms the handshake
refuses it. Chain validation *alone* accepts such a certificate; only the explicit
`ClientSignatureAlgorithms` restriction rejects it, and an `ssl_conf_command` that OpenSSL does not
recognise is accepted at parse time and simply never applied. **Run it after every OpenSSL or
nginx upgrade.**

### Analysis and diagnostics

| Script | Purpose |
|---|---|
| `rtt-proof.sh` | Proves the extra-round-trip mechanism: 1 cert vs 2, plus a `tcpdump` timeline |
| `rtt-cwnd2.sh` | The control, same two certificates at `initcwnd` 10 / 20 / 30 |
| `certsize.sh` | Re-derives every certificate size; shows how construction moves a classical leaf |

## Every script in this directory

Grouped by when you would run it. `run-all.sh` runs the arms, the checks and the
measurements; the rest are run on their own, in
order; the rest are run on their own when you have a specific question.

### Before measuring

| script | what it does |
|---|---|
| `preflight.sh` | Refuses to continue unless containers, route, mTLS, PQC handshake, swap and load are all sane. **Run first.** |
| `gen-provenance.sh` | Captures CPU, RAM, OpenSSL version and repo HEAD into `PROVENANCE.md`. Run before reporting any number |
| `re-apply-route.sh` | Restores the `bench-client` route after a gateway restart |

### Building the arms

| script | what it does |
|---|---|
| `setup-classical-arm.sh` | Builds throwaway hermetic PKIs and starts the hybrid `:4433` and classical `:4434` endpoints |
| `add-pure-arm.sh` | Adds the pure ML-KEM-768 arm on `:4435`, reusing the hermetic PQ PKI so the only difference is the group |
| `mk-matched-pki.sh` | Builds two three-tier PKIs identical except for the algorithm, so a certificate-size difference IS the algorithm difference |
| `mk-arms.sh` | Starts the campaign arms from those PKIs and verifies each one before anything is measured |

### Measuring

| script | what it does |
|---|---|
| `wirebytes.sh` | Handshake wire bytes, leaf and full-chain, with the chain configuration recorded alongside |
| `throughput3.sh` | CPU-normalised throughput across all three arms |
| `measure-latency.sh` | TLS 1.3 mutual-TLS handshake latency, paper methodology, one arm per invocation |
| `vpn-bench.sh` | The same latency measurement driven across a VPN from a remote client. Produces `2026-08/results/vpn/` |
| `vpn-conc.sh` | Concurrency over that same tunnel, so the remote-client result covers more than one connection at a time |
| `measure-arms.sh` | The repeated campaign: sizes, wire bytes, latency and throughput, with per-repeat spread reported |
| `verify-suite.sh` | The non-timing checks: certificate sizes, OCSP staple, post-quantum-only enforcement |
| `certsize.sh` | Re-derives every certificate size and shows how construction moves a classical leaf |

### Analysing

| script | what it does |
|---|---|
| `stats.py` | Summarises handshake-latency `.dat` files, paper methodology |
| `latency-stats.py` | Reports latency arms with **outlier-repeat rejection**, and prints which column it used. Every campaign here has had exactly one contaminated repeat |

### Negative controls, the checks that must FAIL

| script | what it does |
|---|---|
| `check-negative-controls.sh` | Out-of-route CN refused, revoked certificate refused, and a classical-keyed certificate signed by the legitimate PQC intermediate refused |
| `check-negative-controls-detail.sh` | The two above that need more than an exit code: captures the response body and nginx's own verify state |
| `check-published-values.sh` | Four checks against values the paper prints: netem, wire bytes, OCSP signer DER, idle CPU |
| `check-ocsp-and-policy-values.sh` | Three more: zero-reload policy latency, OCSP `-rother` comparison, the quantum buffer via `sendRawCert` |

### Specific questions

| script | what it does |
|---|---|
| `netem-sweep.sh` | Does the PQC handshake pay an extra round trip at realistic RTTs? |
| `2026-08/envoy-pqc-probe.sh` | Can an Envoy data plane authenticate with ML-DSA-65? Backs the service-mesh finding: three Envoy versions refuse such a certificate |
| `rtt-proof.sh` | Proves the +1 RTT explanation by controlled A/B/C |
| `rtt-cwnd2.sh` | The control for the above: same two certificates at `initcwnd` 10 / 20 / 30 |
| `fullchain-test.sh` | Does a client sending its full chain exceed IW10? |
| `concurrency-from-client.sh` | Concurrency sweep driven from a separate machine, so the load generator's CPU does not compete with the gateway's. Backs the 10/20/30/50-client result |
| `memcheck.sh` | One container's memory: working set versus page cache. Backs the edge-footprint figures |
| `allmem.sh` | The same across every running container |


## Seven traps that produce wrong numbers silently

Each of these is asserted against, because each one fails by producing **plausible numbers
rather than an error**.

1. **`s_server -CAfile` makes the server send its CA too.** Two certificates instead of one, about
   **+5.5 KB** on a PQC arm, enough to push the flight over TCP's initial congestion window and
   manufacture an extra round trip. Use `-verifyCAfile`. `setup-classical-arm.sh` counts
   certificates with `-showcerts` and aborts if it is not 1.
2. **`s_client -CAfile` makes the *client* send its full chain**, about +11 KB on "written".
   `wirebytes.sh` measures both configurations and labels them.
3. **A server certificate with no `subjectAltName IP:127.0.0.1`.** `s_client` does not verify
   hostnames; **curl does**. The handshake completes server-side, curl aborts, and
   `time_appconnect` reads 0, which looks like "0 ms handshakes", not a failure.
4. **`conn/USER-sec` is not `conn/REAL-sec`.** CPU-normalised versus wall-clock. Mixing them across
   hosts manufactures a discrepancy that is not there. Always say which.
5. **Default `lo` MTU is 65536**, which hides segmentation and makes congestion-window effects
   invisible. The relevant scripts force 1500 and restore on exit.
6. **`docker stats` MemUsage includes page cache.** On cgroup v2 it reports `memory.current`, which
   overstates the working set by 20+ MiB on a busy container. Read `anon` from `memory.stat`.
7. **The first connection after a deploy may not carry the OCSP staple.** `verify-suite.sh`
   section 2 then prints the flight sizes with no decoded response. The staple is fetched and
   cached on the first request that asks for it, so run it again. This is warm-up, not a
   post-quantum stapling limitation.

And one definition rather than a trap: **connect by hostname, not IP literal**. An IP literal
suppresses SNI, and the server's 4-byte empty `server_name` echo disappears with it, 11,067 B
instead of 11,071 B.

## Two more things that will waste an afternoon

- **Revocation is `POST /admin/certs/revoke` with `{"serial","reason"}`**, not
  `POST /admin/certs/<serial>/revoke`, which 404s. A 404 there reads as *"the revoked certificate
  was still accepted"*, which is a far more alarming and completely false conclusion.
- **HTTP 400 is ambiguous.** nginx returns 400 both when a client certificate is rejected *and*
  when none was sent. Always run the valid-identity control alongside and read the body: *"No
  required SSL certificate was sent"* is the one that means the signature-algorithm guard fired.

## What this harness cannot measure

**The gateway's saturation point.** The concurrency sweep is driven from a second host to get the
load generator off the box, but if that host is another guest on the same hypervisor, it isolates
the process tree and **not the physical CPU**. Under 50 concurrent clients the gateway's load
average was 0.35 on 8 cores; the rising latency is client-side contention, not the server bending.

A real saturation number needs a load generator on **separate hardware**. Until then, treat the
concurrency latencies as a lower bound on capacity and nothing more.

## Not included

The hermetic PKIs' private keys, throwaway, 30-day, and regenerated by `setup-classical-arm.sh`
on every run.
