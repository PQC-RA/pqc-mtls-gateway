"""revoke30.py ENROLL_TSV OUTDIR [SEED]: revoke every certificate in ENROLL_TSV, one at a time, at
random gaps, against the throwaway stack rs1107. Client on the stand, no added delay, one clock
(this host's; the containers share its kernel clock, so the custodian's log and the published
CRL's mtime are on the same clock).

Per certificate, two probe loops start 1.5 s before T0 and must both be healthy by then:
  A  a new connection per request, back to back (curl, a new TLS handshake each time)
  B  one keep-alive connection, a GET every 50 ms (Python ssl, OpenSSL 3.6.5)
Accepted = HTTP 404 (authenticated; the CN has no route, '/' has no page). Anything else is a
refusal, recorded with its kind. T0 is taken immediately before the admin revoke call
(curl, admin certificate, POST /admin/certs/revoke on :443, the normal admin path).
Result per loop: the first request that STARTS after T0 and is not accepted; its end - T0 is the
time to refusal (as in the 4 Nov tool), its start - T0 is also kept.
Gaps: T0(i+1) - T0(i) drawn uniform in [5, 25] s from random.Random(SEED); the actual gap is kept.
The next run's probes start only after the reload the previous revocation causes (gateway reload
watcher, 5 s poll) plus 0.5 s, so a planned gap shorter than that is stretched (recorded).
"""
import datetime, json, os, random, socket, ssl, subprocess, sys, threading, time

D = '/root/rerun-stack-20261107'; R = D + '/repo'
CHAIN = D + '/host/var-lib-pqc-ca-public/ca-chain.crt'
CRL = D + '/host/var-lib-pqc-ca-public/hybrid-combined-crl.pem'
ADM_C = R + '/admin-cert/gateway-admin.crt'; ADM_K = R + '/admin-cert/gateway-admin.key'
HOST, PORT = '127.0.0.1', 39443
CURL = '/usr/bin/curl'; O = '/opt/openssl/bin/openssl'
WARM = 1.5; DEADLINE = 15.0; GAP_LO, GAP_HI = 5.0, 25.0

tsv, out = sys.argv[1], sys.argv[2]
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 20261107
os.makedirs(out, exist_ok=True)
rows = [l.rstrip('\n').split('\t') for l in open(tsv)][1:]
devs = [(r[1], r[2]) for r in rows]          # (cn, serial hex)
rng = random.Random(seed)
gaps = [rng.uniform(GAP_LO, GAP_HI) for _ in range(len(devs) - 1)]

def crl_info():
    st = os.stat(CRL)
    n = subprocess.run([O, 'crl', '-in', CRL, '-noout', '-crlnumber'], capture_output=True, text=True,
                       env={**os.environ, 'OPENSSL_CONF': '/dev/null'}).stdout.strip().split('=')[-1]
    return n, st.st_mtime_ns / 1e9, st.st_ino

def wait_reload(t0, limit=12.0):
    # the gateway's reload watcher reloads nginx when the published CRL changes (5 s poll); the next
    # run's probes start only after that reload, so no reload closes their connections mid-run
    end = time.time() + limit
    since = datetime.datetime.fromtimestamp(t0 - 0.5, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    while time.time() < end:
        r = subprocess.run(['docker', 'logs', '-t', '--since', since, 'pqc-gateway'], capture_output=True, text=True)
        for l in (r.stdout + r.stderr).splitlines():
            if '[reload-watcher]' in l and 'nginx reloaded' in l:
                ts = l.split(' ', 1)[0].rstrip('Z'); main, frac = ts.split('.')
                t = datetime.datetime.strptime(main, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp() + float('0.' + frac)
                if t >= t0:
                    time.sleep(0.5)
                    return t
        time.sleep(0.25)
    return None

def run_one(idx, cn, serial):
    d = f'{D}/devices/{cn}'
    stop = threading.Event()
    A, B = [], []                          # (start, end, accepted, kind)

    def probe_a():
        while not stop.is_set():
            s = time.time()
            r = subprocess.run([CURL, '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '3',
                                '--cacert', CHAIN, '--cert', f'{d}/client.crt', '--key', f'{d}/client.key',
                                f'https://{HOST}:{PORT}/'], capture_output=True, text=True)
            e = time.time(); code = r.stdout.strip()
            if code == '404':
                kind = '404'
            elif code not in ('', '000'):
                kind = f'HTTP {code}'
            else:
                kind = f'curl exit {r.returncode}: ' + r.stderr.strip().replace('\t', ' ')[:90]
            A.append((s, e, code == '404', kind))

    def connect_b():
        ctx = ssl.create_default_context(cafile=CHAIN)
        ctx.check_hostname = False
        ctx.load_cert_chain(f'{d}/client.crt', f'{d}/client.key')
        return ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=3), server_hostname='pqc-gw.local')

    def get_b(sk):
        sk.sendall(b'GET / HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: keep-alive\r\n\r\n')
        buf = b''
        while b'\r\n\r\n' not in buf:
            c = sk.recv(65536)
            if not c:
                raise ConnectionError('closed by the gateway (EOF, no response)')
            buf += c
        hdr, _, body = buf.partition(b'\r\n\r\n')
        lines = hdr.split(b'\r\n')
        n = int([l for l in lines if l.lower().startswith(b'content-length')][0].split(b':')[1])
        while len(body) < n:
            c = sk.recv(65536)
            if not c: raise ConnectionError('closed mid-body')
            body += c
        return lines[0].split(b' ')[1].decode()

    def probe_b():
        # One keep-alive connection, a GET every 50 ms. If the connection is closed or a request is
        # not answered 404, ONE immediate reconnect with the same certificate tells a refusal from a
        # close that is not one (an nginx reload closes idle keep-alive connections): a reconnect
        # answered 404 means not refused, and the loop goes on on the new connection (logged as
        # 'reconnected'); otherwise the first failure is the refusal, its kind carries both answers.
        try:
            sk = connect_b()
        except Exception as ex:
            B.append((time.time(), time.time(), False, f'connect failed: {type(ex).__name__}: {ex}'[:120])); return
        while not stop.is_set():
            s = time.time(); ok = False
            try:
                code = get_b(sk); ok = code == '404'; kind = code if ok else f'HTTP {code}'
            except Exception as ex:
                kind = f'{type(ex).__name__}: {ex}'[:100]
            e = time.time()
            if not ok:
                try: sk.close()
                except Exception: pass
                try:
                    sk = connect_b(); code2 = get_b(sk)
                    again = code2 == '404'; k2 = code2 if again else f'HTTP {code2}'
                except Exception as ex:
                    again = False; k2 = f'{type(ex).__name__}: {ex}'[:80]
                if again:
                    B.append((s, e, True, f'reconnected after [{kind}]: 404'))
                    time.sleep(0.05); continue
                B.append((s, e, False, f'{kind}; reconnect: {k2}'))
                try: sk.close()
                except Exception: pass
                return
            B.append((s, e, True, kind))
            time.sleep(0.05)

    crl_n0, crl_m0, crl_i0 = crl_info()
    ta = threading.Thread(target=probe_a); tb = threading.Thread(target=probe_b)
    ta.start(); tb.start()
    return stop, A, B, ta, tb, (crl_n0, crl_m0, crl_i0)

def finish(idx, cn, serial, planned_gap, actual_gap, ctx, t0, rv, rv_end):
    stop, A, B, ta, tb, (crl_n0, crl_m0, crl_i0) = ctx
    deadline = t0 + DEADLINE
    while time.time() < deadline:
        ra = [x for x in A if x[0] > t0 and not x[2]]
        if ra and not tb.is_alive():
            break
        time.sleep(0.02)
    stop.set(); ta.join(); tb.join(timeout=5)
    crl_n1, crl_m1, crl_i1 = crl_info()
    reload_at = wait_reload(t0)
    pre_a = [x for x in A if x[0] <= t0]; pre_b = [x for x in B if x[0] <= t0]
    healthy = bool(pre_a and all(x[2] for x in pre_a) and pre_b and all(x[2] for x in pre_b))
    def first_ref(xs):
        r = [x for x in xs if x[0] > t0 and not x[2]]
        return (f'{r[0][1]-t0:.3f}', f'{r[0][0]-t0:.3f}', r[0][3]) if r else ('nan', 'nan', 'none within 15 s')
    def last_ok(xs):
        r = [x for x in xs if x[2]]
        return f'{r[-1][1]-t0:.3f}' if r else 'nan'
    fa = first_ref(A); fb = first_ref(B)
    try:
        body = json.loads(rv.stdout.rsplit('\n', 1)[0]) if rv.stdout else {}
    except Exception:
        body = {}
    code = rv.stdout.rsplit('\n', 1)[-1] if rv.stdout else '000'
    with open(f'{out}/requests.tsv', 'a') as f:
        for p, xs in (('A', A), ('B', B)):
            for x in xs:
                f.write(f'{idx}\t{p}\t{x[0]-t0:.4f}\t{x[1]-t0:.4f}\t{int(x[2])}\t{x[3]}\n')
    row = [str(idx), cn, serial, f'{planned_gap:.3f}', f'{actual_gap:.3f}', f'{t0:.6f}', code,
           f'{rv_end - t0:.4f}', json.dumps(body, sort_keys=True).replace('\t', ' ')[:160],
           crl_n0, crl_n1, f'{crl_m1 - t0:.4f}' if crl_i1 != crl_i0 else 'unchanged',
           fa[0], fa[1], fa[2], last_ok(A), str(len(A)),
           fb[0], fb[1], fb[2], last_ok(B), str(len(B)), 'yes' if healthy else 'NO',
           str(sum(1 for x in B if x[3].startswith('reconnected'))), f'{reload_at - t0:.4f}' if reload_at else 'nan']
    with open(f'{out}/revocation.tsv', 'a') as f:
        f.write('\t'.join(row) + '\n')
    print('\t'.join(row[:8] + row[9:12] + [row[12], row[14][:40], row[17], row[19][:40], row[22]]), flush=True)

hdr = ['i', 'cn', 'serial', 'planned_gap_s', 'actual_gap_s', 't0_unix', 'revoke_http', 'revoke_call_s',
       'revoke_response', 'crl_before', 'crl_after', 'crl_file_mtime_minus_t0_s',
       'A_refused_s', 'A_refused_req_start_s', 'A_refusal_kind', 'A_last_ok_s', 'A_requests',
       'B_refused_s', 'B_refused_req_start_s', 'B_refusal_kind', 'B_last_ok_s', 'B_requests', 'healthy_before_t0',
       'B_reconnects', 'reload_minus_t0_s']
with open(f'{out}/revocation.tsv', 'w') as f:
    f.write('\t'.join(hdr) + '\n')
with open(f'{out}/requests.tsv', 'w') as f:
    f.write('i\tprobe\tstart_minus_t0_s\tend_minus_t0_s\taccepted\tkind\n')
with open(f'{out}/schedule.txt', 'w') as f:
    f.write(f'seed {seed}; gaps uniform [{GAP_LO}, {GAP_HI}] s between consecutive T0; warm-up {WARM} s; deadline {DEADLINE} s\n')
    f.write('planned gaps: ' + ' '.join(f'{g:.3f}' for g in gaps) + '\n')

prev_t0 = None; target = time.time() + WARM
for k, (cn, serial) in enumerate(devs):
    idx = k + 1
    planned = gaps[k - 1] if k else 0.0
    if prev_t0 is not None:
        target = max(prev_t0 + planned, time.time() + WARM)
    # start the probes WARM s before the target T0 (immediately, if already late)
    time.sleep(max(0.0, target - WARM - time.time()))
    ctx = run_one(idx, cn, serial)
    time.sleep(max(WARM, target - time.time()))
    payload = json.dumps({'serial': serial, 'reason': 'cessationOfOperation'})
    t0 = time.time()
    rv = subprocess.run([CURL, '-sS', '--cacert', CHAIN, '--cert', ADM_C, '--key', ADM_K,
                         '-H', 'X-PQC-CSRF: 1', '-H', 'Content-Type: application/json', '-X', 'POST',
                         f'https://{HOST}:{PORT}/admin/certs/revoke', '-d', payload, '-w', '\n%{http_code}'],
                        capture_output=True, text=True)
    rv_end = time.time()
    actual = (t0 - prev_t0) if prev_t0 is not None else 0.0
    finish(idx, cn, serial, planned, actual, ctx, t0, rv, rv_end)
    prev_t0 = t0
print('done', flush=True)
