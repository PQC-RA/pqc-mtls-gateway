#!/usr/bin/env python3
"""stats.py, analyse handshake-latency .dat files (paper methodology).

Input rows: "<time_connect> <time_appconnect>" in SECONDS.
Reported metric: (time_appconnect - time_connect) * 1000  -> ms  (pure TLS).

Discards the first DISCARD samples as warm-up, then reports
min / median / mean / 95% CI / P95 / P99 / max / stddev / CV.
95% CI = mean +/- 1.96 * (sigma / sqrt(N)), normal approximation.
Percentiles by linear interpolation.
"""
import sys, json, math, statistics as st

DISCARD = 20

def pct(xs, p):
    if not xs: return float("nan")
    k = (len(xs) - 1) * p
    f, c = math.floor(k), math.ceil(k)
    return xs[int(k)] if f == c else xs[f] + (xs[c] - xs[f]) * (k - f)

def analyse(path):
    tls = []
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) != 2: continue
            try: c, a = float(parts[0]), float(parts[1])
            except ValueError: continue
            if a <= 0: continue          # failed handshake
            tls.append((a - c) * 1000.0)
    raw_n = len(tls)
    tls = tls[DISCARD:]
    n = len(tls)
    if n < 2: return {"label": path, "raw_n": raw_n, "n": n, "error": "insufficient samples"}
    s = sorted(tls)
    mean, sd = st.fmean(s), st.stdev(s)
    half = 1.96 * sd / math.sqrt(n)
    return {
        "label": path, "raw_n": raw_n, "discarded": DISCARD, "n": n,
        "min": round(s[0], 3), "median": round(st.median(s), 3), "mean": round(mean, 3),
        "ci95_lo": round(mean - half, 3), "ci95_hi": round(mean + half, 3),
        "ci95_half": round(half, 3),
        "p95": round(pct(s, 0.95), 3), "p99": round(pct(s, 0.99), 3),
        "max": round(s[-1], 3), "std": round(sd, 3), "cv_pct": round(sd / mean * 100, 2),
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: stats.py <file.dat> [file2.dat ...]")
    res = [analyse(p) for p in sys.argv[1:]]
    print(json.dumps(res, indent=2))
    print("\n| file | N | min | median | mean | 95% CI | P95 | P99 | max | sd | CV |")
    print("|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|")
    for r in res:
        if "error" in r:
            print(f"| {r['label']} | {r['n']} |, |, |, | {r['error']} | | | | | |"); continue
        print(f"| {r['label']} | {r['n']} | {r['min']} | {r['median']} | **{r['mean']}** | "
              f"[{r['ci95_lo']}, {r['ci95_hi']}] | {r['p95']} | {r['p99']} | {r['max']} | "
              f"{r['std']} | {r['cv_pct']}% |")
    print("\nAll values in ms, TLS handshake only (time_appconnect - time_connect).")
