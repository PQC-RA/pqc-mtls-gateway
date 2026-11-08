"""summarize.py RESULTS_DIR: statistics for the enrollment and revocation series of the throwaway
stack rs1107 (2026-11-07). Percentiles: linear interpolation between closest ranks (numpy's
default, Hyndman-Fan type 7). Reads results/enroll/enroll.tsv, results/revocation/*.tsv and the
log extracts in results/logs/. Writes results/summary.txt and the joined per-item tables.
"""
import collections, datetime, json, math, re, sys

RES = sys.argv[1]

def pct(xs, p):
    xs = sorted(xs); n = len(xs)
    if n == 0: return float('nan')
    k = (n - 1) * p / 100.0; f = math.floor(k); c = min(f + 1, n - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

def stat(xs):
    xs = [x for x in xs if not math.isnan(x)]
    return dict(n=len(xs), min=min(xs), p10=pct(xs, 10), median=pct(xs, 50), p90=pct(xs, 90), max=max(xs),
                mean=sum(xs) / len(xs))

def fmt_row(name, xs, unit='ms', nd=1):
    s = stat(xs)
    return (f'{name:<58} {s["n"]:>3}  {s["min"]:>8.{nd}f} {s["p10"]:>8.{nd}f} {s["median"]:>8.{nd}f} '
            f'{s["p90"]:>8.{nd}f} {s["max"]:>8.{nd}f} {s["mean"]:>8.{nd}f}  {unit}')

HDR = f'{"":<58} {"n":>3}  {"min":>8} {"p10":>8} {"median":>8} {"p90":>8} {"max":>8} {"mean":>8}'

def iso(s):  # '2026-11-07T15:59:54.711856565Z' or '...711Z' -> unix seconds
    s = s.rstrip('Z'); frac = 0.0
    if '.' in s: s, f = s.split('.'); frac = float('0.' + f)
    return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp() + frac

def read_tsv(p):
    L = [l.rstrip('\n').split('\t') for l in open(p)]
    return [dict(zip(L[0], r)) for r in L[1:]]

ANSI = re.compile(r'\x1b\[[0-9;]*m')
# custodian lines: <docker ts> <own ISO ts> [custodian] [LEVEL] msg ; own ts is used (ms, same kernel clock)
cust = []
for l in open(f'{RES}/logs/custodian.log'):
    p = l.split(' ', 2)
    if len(p) == 3 and '[custodian]' in p[2]:
        cust.append((iso(p[1]), p[2].strip()))
api = []   # (docker receipt ts, message)
for l in open(f'{RES}/logs/management-api.log'):
    l = ANSI.sub('', l).rstrip('\n'); ts, _, rest = l.partition(' ')
    api.append((iso(ts), rest))
gw = []
for l in open(f'{RES}/logs/gateway-stdout.log'):
    ts, _, rest = l.rstrip('\n').partition(' ')
    gw.append((iso(ts), rest))
acts = [json.loads(l) for l in open(f'{RES}/logs/admin-actions.sanitized.ndjson')]
enroll_acc = [json.loads(l) for l in open(f'{RES}/logs/pqc-enroll-access.log') if '"/enroll"' in l]
mtls_acc = [json.loads(l) for l in open(f'{RES}/logs/pqc-mtls-access.log')]

out = []
w = out.append
w('Throwaway stack rs1107 on the test stand (.27), public main 83a4f60, 2026-11-07. Client on the stand,')
w('loopback, no added delay, no netem. One clock (the stand\'s; containers share its kernel clock).')
w('Percentiles: linear interpolation (type 7). Times in ms unless stated.')
w('')

# ── enrollment ──
E = read_tsv(f'{RES}/enroll/enroll.tsv')
acc201 = [a for a in enroll_acc if a['status'] == 201]
acc201 = acc201[len(acc201) - len(E):]   # in order; the smoke-test enrollment before the series is dropped
rows = []
for e, a in zip(E, acc201):
    cs, ce = float(e['curl_start_unix']), float(e['curl_end_unix'])
    serial = e['serial']
    signed = [t for t, m in cust if f'Signed certificate serial={serial} ' in m]
    recv = [t for t, m in api if 'Received CSR signing request' in m and cs - 0.01 <= t <= ce + 0.01]
    apisig = [t for t, m in api if f'Certificate signed: serial={serial},' in m]
    resv = [iso(a['ts']) for a in acts if a['action'] == 'token.reserve' and a['target'] == f'cn={e["cn"]}' and cs - 0.01 <= iso(a['ts']) <= ce + 0.01]
    done = [iso(a['ts']) for a in acts if a['action'] == 'cert.enroll' and a['target'].startswith(f'cn={e["cn"]} ')]
    assert abs(iso(a['ts'].replace('+00:00', '')) - ce) < 2.0, (e['cn'], a['ts'])
    r = dict(i=e['i'], cn=e['cn'], serial=serial,
             key=float(e['key_ms']), csr=float(e['csr_ms']),
             connect=float(e['connect_s']) * 1e3, tls=(float(e['appconnect_s']) - float(e['connect_s'])) * 1e3,
             appconnect=float(e['appconnect_s']) * 1e3,
             after_tls=(float(e['total_s']) - float(e['appconnect_s'])) * 1e3,
             total=float(e['total_s']) * 1e3, wall=(ce - cs) * 1e3,
             token=float(e['token_total_s']) * 1e3,
             gw_rt=a['rt'] * 1e3,
             api_recv=(recv[0] - cs) * 1e3 if recv else float('nan'),
             api_reserve=(resv[0] - cs) * 1e3 if resv else float('nan'),
             cust_signed=(signed[0] - cs) * 1e3 if signed else float('nan'),
             api_done=(done[0] - cs) * 1e3 if done else float('nan'),
             reply_after_sign=(ce - signed[0]) * 1e3 if signed else float('nan'),
             api_recv_to_signed=(signed[0] - recv[0]) * 1e3 if signed and recv else float('nan'))
    rows.append(r)
cols = list(rows[0].keys())
with open(f'{RES}/enroll/enroll-joined.tsv', 'w') as f:
    f.write('\t'.join(cols) + '\n')
    for r in rows: f.write('\t'.join(f'{r[c]:.3f}' if isinstance(r[c], float) else str(r[c]) for c in cols) + '\n')
w(f'== 1. Enrollment, N = {len(rows)} devices (CN rs1107-dev-01..30, profile client-30d, ML-DSA-65) ==')
w('Device side: openssl 3.6.5 genpkey / req (one process each, start-up included).')
w('Request: curl 8.5.0 (libcurl on OpenSSL 3.6.5), POST /enroll on the enrollment port, timers from curl -w.')
w(HDR)
for name, k in [('key generation (genpkey ML-DSA-65)', 'key'), ('CSR (openssl req)', 'csr'),
                ('request: time_connect (TCP)', 'connect'), ('request: TLS handshake (appconnect - connect)', 'tls'),
                ('request: time_appconnect', 'appconnect'),
                ('request: after TLS (upload, API checks, signature, reply)', 'after_tls'),
                ('request: time_total', 'total'),
                ('admin token call (curl time_total, mTLS :443)', 'token')]:
    w(fmt_row(name, [r[k] for r in rows]))
w('Server side, same clock, from the request start (curl started):')
for name, k in [('gateway $request_time for /enroll (nginx, ms resolution)', 'gw_rt'),
                ('management-api logs "Received CSR signing request"', 'api_recv'),
                ('management-api audit token.reserve', 'api_reserve'),
                ('custodian logs "Signed certificate"', 'cust_signed'),
                ('management-api audit cert.enroll (done)', 'api_done'),
                ('API received -> custodian signed', 'api_recv_to_signed'),
                ('custodian signed -> reply complete at the device', 'reply_after_sign')]:
    w(fmt_row(name, [r[k] for r in rows]))
w('(management-api line times are docker\'s receipt times of its stdout lines; the custodian and the')
w(' audit log carry their own millisecond timestamps.)')
w('')

# ── revocation ──
V = read_tsv(f'{RES}/revocation/revocation.tsv')
reloads = [t for t, m in gw if '[reload-watcher]' in m and 'nginx reloaded' in m]
vr = []
for v in V:
    t0 = float(v['t0_unix']); s = v['serial']
    rev = [t for t, m in cust if f'Revoked certificate serial={s} ' in m]
    pub = [t for t, m in cust if 'Published intermediate CRL number' in m and rev and t >= rev[0]]
    rl = [t for t in reloads if t >= t0]
    acc = [a for a in mtls_acc if a['uri'] == '/admin/certs/revoke' and a['method'] == 'POST'
           and abs(iso(a['ts'].replace('+00:00', '')) - t0) < 1.5]
    vr.append(dict(i=v['i'], cn=v['cn'], serial=s, planned_gap=float(v['planned_gap_s']), actual_gap=float(v['actual_gap_s']),
                   revoke_http=v['revoke_http'], crl_before=v['crl_before'], crl_after=v['crl_after'],
                   A=float(v['A_refused_s']) * 1e3, A_start=float(v['A_refused_req_start_s']) * 1e3, A_kind=v['A_refusal_kind'],
                   A_last_ok=float(v['A_last_ok_s']) * 1e3,
                   B=float(v['B_refused_s']) * 1e3, B_start=float(v['B_refused_req_start_s']) * 1e3, B_kind=v['B_refusal_kind'],
                   B_last_ok=float(v['B_last_ok_s']) * 1e3,
                   revoke_call=float(v['revoke_call_s']) * 1e3,
                   crl_mtime=float(v['crl_file_mtime_minus_t0_s']) * 1e3 if v['crl_file_mtime_minus_t0_s'] != 'unchanged' else float('nan'),
                   cust_revoked=(rev[0] - t0) * 1e3 if rev else float('nan'),
                   cust_published=(pub[0] - t0) * 1e3 if pub else float('nan'),
                   cust_rev_to_pub=(pub[0] - rev[0]) * 1e3 if pub else float('nan'),
                   gw_rt=acc[0]['rt'] * 1e3 if len(acc) == 1 else float('nan'),
                   reload=(rl[0] - t0) * 1e3 if rl else float('nan'),
                   healthy=v['healthy_before_t0']))
for r in vr:
    r['A_after_pub'] = r['A'] - r['crl_mtime']; r['B_after_pub'] = r['B'] - r['crl_mtime']
cols = list(vr[0].keys())
with open(f'{RES}/revocation/revocation-joined.tsv', 'w') as f:
    f.write('\t'.join(cols) + '\n')
    for r in vr: f.write('\t'.join(f'{r[c]:.3f}' if isinstance(r[c], float) else str(r[c]) for c in cols) + '\n')
ok = [r for r in vr if r['healthy'] == 'yes']
w(f'== 2. Revocation, N = {len(vr)} certificates ({len(ok)} with both probes healthy before T0; statistics over those) ==')
seedline = open(f'{RES}/revocation/schedule.txt').readline().strip()
w(f'Schedule: {seedline}')
w(f'Actual gaps between consecutive T0 (s): min {min(r["actual_gap"] for r in vr[1:]):.2f}, '
  f'max {max(r["actual_gap"] for r in vr[1:]):.2f}; largest |actual - planned| '
  f'{max(abs(r["actual_gap"] - r["planned_gap"]) for r in vr[1:]):.3f} s')
w('T0 = immediately before the admin revoke call. Refusal time = end of the first request that started')
w('after T0 and was not answered 404. A = new connection per request (curl, back to back);')
w('B = one keep-alive connection, a GET every 50 ms (Python ssl).')
w(HDR)
for name, k in [('A, new connection per request: T0 -> first refusal', 'A'),
                ('B, open keep-alive connection: T0 -> first refusal', 'B'),
                ('A: T0 -> start of the refused request', 'A_start'),
                ('B: T0 -> start of the refused request', 'B_start'),
                ('A: T0 -> end of the last accepted request', 'A_last_ok'),
                ('B: T0 -> end of the last accepted request', 'B_last_ok'),
                ('revoke call: T0 -> reply at the admin client', 'revoke_call'),
                ('T0 -> custodian logs "Revoked certificate" (index)', 'cust_revoked'),
                ('T0 -> custodian logs "Published intermediate CRL"', 'cust_published'),
                ('custodian: revoked -> CRL published', 'cust_rev_to_pub'),
                ('T0 -> new CRL file on disk (mtime of the published file)', 'crl_mtime'),
                ('gateway $request_time of the revoke call', 'gw_rt'),
                ('CRL on disk -> A refused (gateway pick-up, 1 s poll)', 'A_after_pub'),
                ('CRL on disk -> B refused', 'B_after_pub'),
                ('T0 -> gateway reload-watcher reload (ssl_crl refreshed)', 'reload')]:
    w(fmt_row(name, [r[k] for r in ok]))
w('')
w('Refusal kinds (first refusal per run):')
for p in ('A', 'B'):
    c = collections.Counter(r[f'{p}_kind'] for r in ok)
    for kind, n in c.most_common(): w(f'  {p}  {n:>2} x  {kind}')
w(f'Reload (ssl_crl refreshed) before the first refusal of A: {sum(1 for r in ok if r["reload"] < r["A"])} of {len(ok)} runs; '
  f'B reconnects (a close answered 404 on reconnect): {sum(int(v["B_reconnects"]) for v in V)}')
w(f'HTTP 400 (TLS-layer ssl_crl refusal) anywhere in the mTLS access log: {sum(1 for a in mtls_acc if a["status"] == 400)}; '
  f'HTTP 444 (Lua per-request check, connection closed without a response): {sum(1 for a in mtls_acc if a["status"] == 444)}')
w('Revoke answers: ' + ', '.join(f'{k} x {n}' for k, n in collections.Counter(r['revoke_http'] for r in vr).items()))
w('CRL number before -> after, per run: ' + ' '.join(f'{r["crl_before"]}->{r["crl_after"]}' for r in vr))
open(f'{RES}/summary.txt', 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
