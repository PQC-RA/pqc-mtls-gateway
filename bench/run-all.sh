#!/usr/bin/env bash
# run-all.sh: build the hermetic arms and run the measurements that need only
# this host, in an order that cannot produce empty output.
#
# It does NOT run everything in bench/. It runs: preflight, gen-provenance,
# the hermetic arms, the verification suite, the negative controls, wire bytes,
# throughput, the live-gateway latency arm and the three hermetic ones, then
# stats.py over the result. The matched-PKI chain (mk-matched-pki.sh ->
# mk-arms.sh -> measure-arms.sh -> policy.sh) is a separate rig and is run by
# hand; see README.md.
#
# The individual scripts are independent on purpose, but the order between them
# is not optional: throughput3.sh and wirebytes.sh measure the hermetic arms, so
# running them before setup-classical-arm.sh reports ERR on every row rather
# than failing. This runs them in an order that cannot produce that.
#
# What it does NOT run, deliberately:
#   netem-sweep.sh, rtt-proof.sh, rtt-cwnd2.sh   need root netem and change the
#                                                host's queueing discipline
# Run those by hand when you want them.
#
# Usage:  ./run-all.sh [--skip-preflight]
#   WORKDIR  where output lands          (default: this directory)
#   EXPORT   issued client identity      (default: /root/measure-export)
set -uo pipefail
BENCH_HOME="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="${WORKDIR:-$BENCH_HOME}"
EXPORT_DIR="${EXPORT:-/root/measure-export}"
cd "$BENCH_HOME"

SKIP_PRE=0
[ "${1:-}" = "--skip-preflight" ] && SKIP_PRE=1

step() { printf '\n=== [%s] %s ===\n' "$1" "$2"; }
fail() { echo "FAILED at: $1" >&2; echo "Nothing after this point ran." >&2; exit 1; }

# 1. Refuse to measure a testbed that is not sane. Skipping this is what turns a
#    broken route or a busy host into numbers that look plausible and are wrong.
if [ "$SKIP_PRE" = 0 ]; then
    step 1/6 "preflight"
    ./preflight.sh || fail "preflight.sh (use --skip-preflight only if you know why it failed)"
else
    echo "WARNING: preflight skipped, results are not trustworthy without it" >&2
fi

# 2. Record the testbed before measuring it. A number without its host and
#    date is not citable, and every other document here says to run this first.
step 2/6 "record the testbed"
./gen-provenance.sh || fail gen-provenance.sh


# 3. The hermetic arms. The measurements below read them.
step 3/6 "build the hermetic arms"
./setup-classical-arm.sh || fail setup-classical-arm.sh
./add-pure-arm.sh        || fail add-pure-arm.sh

# 3. Non-timing checks first: they are fast and they fail closed, so a broken
#    enforcement property is reported before spending minutes on timings.
step 4/6 "verification suite and negative controls"
./verify-suite.sh   || fail verify-suite.sh
./check-negative-controls.sh   || echo "NOTE: check-negative-controls.sh reported a failure, read its output" >&2

# 4. The figures.
step 5/6 "measurements"
./wirebytes.sh    || fail wirebytes.sh
./throughput3.sh 10 3 || fail throughput3.sh
# The live gateway first: it is what the paper measures. --resolve keeps SNI
# on, which is worth four bytes of server flight and makes two otherwise
# identical runs disagree if one of them omits it.
./measure-latency.sh gw-pqc-sni https://pqc-gw.local/api/v1/status \
    "$EXPORT_DIR" X25519MLKEM768 220 pqc-gw.local:443:127.0.0.1 || fail "measure-latency.sh (live gateway)"
./measure-latency.sh herm-pqc       https://127.0.0.1:4433/ hermetic/pqc       X25519MLKEM768 || fail "measure-latency.sh (hybrid)"
./measure-latency.sh herm-pure      https://127.0.0.1:4435/ hermetic/pqc       MLKEM768       || fail "measure-latency.sh (pure)"
./measure-latency.sh herm-classical https://127.0.0.1:4434/ hermetic/classical X25519         || fail "measure-latency.sh (classical)"

# 5. Summarise. stats.py reads every .dat produced above; latency-stats.py is the
#    one that rejects a contaminated repeat rather than averaging it in.
step 6/6 "analysis"
./stats.py "$WORKDIR"/*.dat 2>/dev/null || ./stats.py ./*.dat

cat <<EOF

Done. Output is in $WORKDIR:
  wirebytes_raw.txt     handshake wire bytes, both chain configurations
  *.dat                 per-sample handshake latencies, one file per arm

Compare against EXPECTED-RESULTS.md. Read the rig table at the top of it first:
a figure from one rig is not comparable with a figure from another.

Tear down the arms with:  pkill -f 's_server -accept 44[3-9]'
EOF
