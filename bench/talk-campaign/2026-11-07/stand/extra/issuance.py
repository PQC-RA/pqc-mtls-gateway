"""Issuance with the live device profile, 2026-11-07, test stand .27. Same method as the campaign's
issuance-bench.py (one openssl process per step: key, CSR, CA signature), plus the start-up floor.
Algorithms alternate sample by sample."""
import csv
import os
import statistics as st
import subprocess
import sys
import time

O = "/opt/openssl-3.6.5/bin/openssl"
ENV = dict(os.environ, OPENSSL_CONF="/etc/ssl/openssl.cnf")
P = "/root/rerun-20261107/pki"
OUT = "/root/rerun-20261107/extra"
N = int(sys.argv[1])
W = os.path.join(OUT, "work")
os.makedirs(W, exist_ok=True)
KEY = {"ML-DSA-65": ("pq", ["-algorithm", "ML-DSA-65"]),
       "ECDSA-P256": ("cl", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
       "RSA-2048": ("rs", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])}


def run(a):
    t = time.perf_counter()
    r = subprocess.run([O] + a, env=ENV, capture_output=True)
    dt = (time.perf_counter() - t) * 1e3
    if r.returncode:
        raise SystemExit(r.stderr.decode()[:300])
    return dt


floor = [run(["version"]) for _ in range(N)]
rows = []
for i in range(N):
    for alg, (d, ko) in KEY.items():
        k, c, x = (os.path.join(W, f"{d}-{i}.{e}") for e in ("key", "csr", "crt"))
        tk = run(["genpkey"] + ko + ["-out", k])
        tc = run(["req", "-new", "-key", k, "-subj", "/CN=rerun-device1", "-out", c])
        ts = run(["x509", "-req", "-in", c, "-CA", f"{P}/{d}/int.crt", "-CAkey", f"{P}/{d}/int.key", "-days", "30",
                  "-set_serial", str(0x108D), "-extfile", f"{P}/ext.cnf", "-extensions", "device", "-out", x])
        der = len(subprocess.run([O, "x509", "-in", x, "-outform", "DER"], env=ENV, capture_output=True).stdout)
        rows.append(dict(alg=alg, i=i + 1, keygen_ms=round(tk, 3), csr_ms=round(tc, 3), sign_ms=round(ts, 3),
                         total_ms=round(tk + tc + ts, 3), der=der))
        for f in (k, c, x):
            os.remove(f)
with open(os.path.join(OUT, "issuance.csv"), "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(f"floor (openssl version) median {st.median(floor):.2f} ms, N={N}")
for alg in KEY:
    v = [r for r in rows if r["alg"] == alg]

    def q(f):
        return sorted(r[f] for r in v)
    t = q("total_ms")
    print(f"{alg:11} total median {st.median(t):6.2f} ms  min {t[0]:6.2f}  p10 {t[len(t) // 10]:6.2f}  "
          f"p90 {t[9 * len(t) // 10]:6.2f}  max {t[-1]:6.2f} | key {st.median(q('keygen_ms')):.2f} "
          f"csr {st.median(q('csr_ms')):.2f} sign {st.median(q('sign_ms')):.2f} | DER {sorted(set(r['der'] for r in v))}")
