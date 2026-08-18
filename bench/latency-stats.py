#!/usr/bin/env python3
"""latency-stats.py - report latency arms with outlier-repeat rejection.

Why this exists
---------------
Every campaign on this testbed so far has had exactly ONE contaminated repeat,
in a different arm each time (2026-07-31 pure, 2026-08-04 classical, 2026-08-04
re-run hybrid). It is host scheduling, not the crypto: an arm-specific cost
would stay with its arm.

A pooled median swallows that repeat, so the same system reports 1.83x one week
and 2.05x the next. Reporting per-repeat medians alongside the pooled figure
makes the contamination visible instead of silently shifting the answer.

The rejection rule is stated BEFORE it is applied, so it is a criterion rather
than a post-hoc convenience: a repeat whose median deviates more than THRESH
from the median of repeat medians is reported separately and excluded from the
headline ratio.

Usage:  latency-stats.py [latency.csv] [--thresh 0.15] [--baseline classical]
"""
import csv, sys, math, statistics as s
from collections import defaultdict

path = next((a for a in sys.argv[1:] if not a.startswith("-")), "latency.csv")

def opt(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

THRESH = float(opt("--thresh", 0.15))
# The rule below assumes AT MOST ONE contaminated repeat. Under that many it does
# not merely weaken, it INVERTS -- see the guard where it is applied.
MIN_REPEATS = int(opt("--min-repeats", 5))
BASELINE = opt("--baseline", "classical")

# Which column holds the measurement.
#
# Select the column by exact name. Matching on a substring takes the FIRST
# matching column in CSV order. bench/2026-08/results/vpn/vpn-latency.csv is
# `seq,arm,repeat,connect_ms,handshake_ms`, so it silently measured TCP connect
# time instead of the TLS handshake -- and connect time is pure RTT, identical
# across arms by construction, so every ratio came out 1.00x. That reads as a
# real finding ("PQC is free over a WAN") rather than as a bug. It only ever
# fired on the one CSV with two candidates, which is also the one dataset where
# nobody has an intuition for the right answer.
#
# So: prefer a known name, and REFUSE when the choice is genuinely ambiguous.
_used_col = [None]
PREFERRED = ("handshake_ms", "sample_ms", "latency_ms", "sample", "ms")
COLUMN = opt("--column", None)

def pick_column(row):
    cols = list(row)
    if COLUMN:
        if COLUMN not in cols:
            sys.exit("--column %r not in %s" % (COLUMN, cols))
        return COLUMN
    for name in PREFERRED:
        for c in cols:
            if c.lower() == name:
                return c
    cands = [c for c in cols if "ms" in c.lower() or "sample" in c.lower()]
    if len(cands) == 1:
        return cands[0]
    if not cands:
        sys.exit("no measurement column in %s -- pass --column" % cols)
    sys.exit("ambiguous measurement column: %s\n"
             "Refusing to guess -- the first match is not reliably the right one.\n"
             "Pass --column <name> explicitly." % cands)

d = defaultdict(lambda: defaultdict(list))
with open(path) as fh:
    for r in csv.DictReader(fh):
        col = pick_column(r)
        _used_col[0] = col
        d[r["arm"]][r.get("repeat", "1")].append(float(r[col]))
if not d:
    sys.exit("no rows in " + path)
MEASURED_COL = _used_col[0]

def stats(v):
    v = sorted(v)
    n = len(v)
    m = s.mean(v)
    sd = s.stdev(v) if n > 1 else 0.0
    ci = 1.96 * sd / math.sqrt(n) if n else 0.0
    return (n, v[0], s.median(v), m, ci, v[int(n * .95)], v[int(n * .99)], v[-1], sd,
            (sd / m * 100 if m else 0.0))

def row(lbl, t):
    n, mn, med, mean, ci, p95, p99, mx, sd, cv = t
    lo, hi = mean - ci, mean + ci
    print("  %-22s%6d%8.3f%9.3f%8.3f  [%.3f,%.3f]%8.3f%8.3f%8.3f%7.3f%6.1f%%"
          % (lbl, n, mn, med, mean, lo, hi, p95, p99, mx, sd, cv))

print("# %s   column: %s   outlier rule: |repeat median - median(repeat medians)| > %.0f%%\n"
      % (path, MEASURED_COL, THRESH * 100))
print("  arm / basis                n     min   median    mean         95% CI"
      "      P95     P99     max     sd     CV")

headline = {}
undersized = []
for arm in sorted(d):
    reps = d[arm]
    med = dict((k, s.median(v)) for k, v in reps.items())
    mm = s.median(list(med.values()))
    keep = set(k for k, x in med.items() if abs(x - mm) / mm <= THRESH)
    drop = sorted(set(reps) - keep)
    # Refuse to reject when there are too few repeats to tell healthy from
    # contaminated. With 3 repeats and TWO bad, the median of repeat medians
    # lands inside the contaminated cluster, deviation is measured from there,
    # and the rule throws away the one GOOD repeat. Not hypothetical: 2026-08-04
    # classical was [2.264, 2.95, 3.086]; the rule dropped 2.264 and reported
    # clean=1.46x -- further from the truth than doing nothing at all.
    # Reporting the pooled figure with a visible warning beats a confident lie.
    if len(reps) < MIN_REPEATS:
        undersized.append((arm, len(reps)))
        keep, drop = set(reps), []
    pooled = [x for v in reps.values() for x in v]
    clean = [x for k in keep for x in reps[k]]
    row(arm + " pooled", stats(pooled))
    if drop:
        row(arm + " clean", stats(clean))
        print("      dropped repeat(s) %s - median(s) %s vs %.3f"
              % (drop, [round(med[k], 3) for k in drop], mm))
    spread = (max(med.values()) - min(med.values())) / min(med.values()) * 100
    print("      per-repeat medians: %s   spread %.1f%%"
          % ([round(med[k], 3) for k in sorted(med)], spread))
    headline[arm] = (s.median(pooled), s.median(clean))

if BASELINE in headline:
    bp, bc = headline[BASELINE]
    print("\n  ratios vs %s:" % BASELINE)
    for arm in sorted(headline):
        if arm == BASELINE:
            continue
        p, c = headline[arm]
        print("    %-12s pooled=%.2fx   clean=%.2fx" % (arm, p / bp, c / bc))
    print("\n  Quote the CLEAN ratio; report the pooled figure and the per-repeat")
    print("  spread alongside it so the exclusion is visible.")

if undersized:
    print("\n  !! OUTLIER REJECTION DISABLED -- fewer than %d repeats: %s"
          % (MIN_REPEATS, ", ".join("%s(%d)" % (a, n) for a, n in undersized)))
    print("     The rule cannot distinguish one bad repeat from a bad majority at")
    print("     this size, and inverts when most repeats are contaminated. Figures")
    print("     above are POOLED and uncorrected. Re-run with >=%d repeats before" % MIN_REPEATS)
    print("     quoting any ratio from them.")
