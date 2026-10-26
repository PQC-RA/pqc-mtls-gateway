#!/usr/bin/env bash
# test-crl-renewer.sh: hermetic tests for docker/crl-renewer/entrypoint.sh and
# for the filesystem property pqc-crl-renew.sh relies on. Touches no running
# stack and no CA: each case runs the renewer image against a fake renew script
# and throwaway directories.
#
#   1  a revocation that lands WHILE a renewal is running triggers another run
#   2  a failing renewal is retried with backoff; the marker advances only on success
#   3  a burst of revocations coalesces (bounded number of regenerations)
#   4  rename within the destination directory is never observed half-written,
#      while the old pattern (mktemp in /tmp + mv across filesystems) is
#
# Usage: IMAGE=<renewer image> bench/test-crl-renewer.sh
# Cases 1-3 exercise the entrypoint BAKED INTO $IMAGE (what deploys), so build
# the image from this tree first, e.g.
#   docker build -t pqc-crl-renewer:test docker/crl-renewer
#   IMAGE=pqc-crl-renewer:test bench/test-crl-renewer.sh
set -uo pipefail
IMAGE=${IMAGE:?set IMAGE to a crl-renewer image built from this tree}
W=$(mktemp -d); trap 'docker rm -f crlr-test >/dev/null 2>&1; rm -rf "$W"' EXIT
FAILS=0
pass(){ echo "  PASS: $*"; }
fail(){ echo "  FAIL: $*"; FAILS=$((FAILS+1)); }

start(){ # start <fake-renew-script-body>
  docker rm -f crlr-test >/dev/null 2>&1
  rm -rf "$W/sig" "$W/runs"; mkdir -p "$W/sig" "$W/runs"
  printf '#!/bin/bash\n%s\n' "$1" > "$W/renew.sh"; chmod +x "$W/renew.sh"
  docker run -d --name crlr-test -e CRL_POLL_INTERVAL=1 \
    -v "$W/renew.sh:/usr/local/bin/pqc-crl-renew.sh:ro" -v "$W/sig:/signals" -v "$W/runs:/runs" \
    "$IMAGE" >/dev/null
}
runs(){ ls "$W/runs" | wc -l; }
sig(){ docker exec crlr-test sh -c 'echo x > /signals/renew-crl'; }

echo "== 1: revocation during a running renewal"
# Each run records itself, then takes 2 s. Startup run is #1.
start 'touch /runs/$(date +%s%N); sleep 2'
sleep 1.5; sig                       # lands while the startup run is still sleeping
sleep 6
n=$(runs)
[ "$n" -ge 2 ] && pass "a signal during run #1 caused run #2 ($n runs)" \
               || fail "signal during a running renewal was lost ($n run(s))"

echo "== 2: failure is retried with backoff, marker only on success"
# Fails on the first two invocations, succeeds from the third.
start 'n=$(ls /runs | wc -l); touch /runs/$(date +%s%N); [ "$n" -ge 2 ]'
sleep 6
n=$(runs)
log=$(docker logs crlr-test 2>&1)
echo "$log" | grep -q 'will retry in 1s' && echo "$log" | grep -q 'will retry in 2s' \
  && pass "backoff 1s then 2s observed" || fail "expected retry backoff 1s,2s; log: $(echo "$log" | tr '\n' '|')"
[ "$n" -eq 3 ] && pass "exactly 3 runs: fail, fail, succeed" || fail "expected 3 runs, got $n"
docker exec crlr-test test -f /tmp/.crl-last-run && pass "marker present after success" || fail "marker missing after success"
# Now an ordinary revocation must still be picked up after recovery.
sleep 1; sig; sleep 3
[ "$(runs)" -eq 4 ] && pass "revocation after recovery triggered a run" || fail "no run after recovery ($(runs))"

echo "== 3: a burst of 20 revocations coalesces"
start 'touch /runs/$(date +%s%N); sleep 0.05'
sleep 2; base=$(runs)
for _ in $(seq 1 20); do sig; done
sleep 4
extra=$(( $(runs) - base ))
[ "$extra" -ge 1 ] && [ "$extra" -le 3 ] && pass "20 signals -> $extra regeneration(s)" \
  || fail "20 signals -> $extra regenerations (expected 1-3)"
docker rm -f crlr-test >/dev/null 2>&1

echo "== 4: atomic publication (filesystem property)"
# A ~12 KB payload stands in for the combined CRL. A reader in the same
# container polls the destination; any read that is not exactly the full
# payload is a torn read. Old pattern: mktemp in /tmp (overlayfs) then mv into a
# bind-mounted directory (different fs). New pattern: mktemp beside the
# destination then mv (rename(2)).
mkdir -p "$W/dest"
head -c 12321 /dev/urandom | base64 -w 64 > "$W/payload"; SZ=$(stat -c %s "$W/payload")
docker run --rm -v "$W/dest:/dest" -v "$W/payload:/payload:ro" --entrypoint bash "$IMAGE" -c '
  SZ='"$SZ"'
  cp /payload /dest/f
  reader(){ bad=0; total=0; end=$((SECONDS+'"${ATOMIC_SECS:-8}"'));
    while [ $SECONDS -lt $end ]; do
      s=$(stat -c %s /dest/f 2>/dev/null || echo missing); total=$((total+1))
      [ "$s" = "$SZ" ] || bad=$((bad+1))
    done; echo "$bad $total"; }
  writer_old(){ while :; do t=$(mktemp); cat /payload > "$t"; mv "$t" /dest/f; done; }
  writer_new(){ while :; do t=$(mktemp /dest/.f.XXXXXX); cat /payload > "$t"; chmod 644 "$t"; mv -f "$t" /dest/f; done; }
  echo "tmp fs: $(stat -f -c %T /tmp)   dest fs: $(stat -f -c %T /dest)"
  writer_old & W1=$!; r=$(reader); kill $W1; wait $W1 2>/dev/null; echo "OLD $r"
  cp /payload /dest/f
  writer_new & W2=$!; r=$(reader); kill $W2; wait $W2 2>/dev/null; echo "NEW $r"
' > "$W/atomic.txt" 2>&1
cat "$W/atomic.txt" | sed 's/^/  /'
read -r _ ob ot < <(grep '^OLD' "$W/atomic.txt"); read -r _ nb nt < <(grep '^NEW' "$W/atomic.txt")
[ "${nb:-1}" -eq 0 ] && pass "new pattern: 0 torn reads in ${nt} reads" || fail "new pattern: ${nb} torn reads in ${nt}"
[ "${ob:-0}" -gt 0 ] && echo "  (old pattern: ${ob} torn reads in ${ot}, the defect being fixed)" \
                     || echo "  (old pattern: no torn read observed in ${ot} reads, not reproduced this run)"

echo
[ "$FAILS" -eq 0 ] && echo "ALL CRL RENEWER TESTS PASSED" || echo "*** $FAILS CRL RENEWER TEST(S) FAILED ***"
exit "$FAILS"
