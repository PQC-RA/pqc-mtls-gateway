"""backstop.py ENROLL_TSV OUTDIR: does the TLS-layer revocation backstop (ssl_verify_client on +
ssl_crl, refreshed by the gateway's reload watcher) refuse with HTTP 400, besides the per-request
Lua check (444)? Throwaway stack rs1107 on the test stand, client on the stand, loopback, no delay.

Per certificate in ENROLL_TSV, one run:
  pre   one new connection (curl --http1.1) GET /?pre-<run> must answer 404 (authenticated).
  B     one keep-alive connection (Python ssl, HTTP/1.1), GET /?b-<run>-<n> every 200 ms, open
        through the whole run; it stops only when the connection fails or answers non-404.
  T0    immediately before the admin revoke call (curl, admin certificate, POST /admin/certs/revoke).
  A     from T0, a NEW connection every 250 ms for 15 s (slot k at T0 + 0.25 k), curl --http1.1,
        GET /?a-<run>-<k>; it keeps going after the first refusal. Exit code, HTTP code, <title>.
Every request carries its own query string, so each one is found in the gateway's access log
($request_uri) with its $status and $ssl_client_verify. The reload time is the reload watcher's
line in the gateway's stdout (docker logs -t).
"""
import datetime, json, os, re, socket, ssl, subprocess, sys, threading, time

D = '/root/rerun-stack-20261107'; R = D + '/repo'
CHAIN = D + '/host/var-lib-pqc-ca-public/ca-chain.crt'
CRL = D + '/host/var-lib-pqc-ca-public/hybrid-combined-crl.pem'
ADM_C = R + '/admin-cert/gateway-admin.crt'; ADM_K = R + '/admin-cert/gateway-admin.key'
LOGS = '/var/lib/docker/volumes/rs1107_pqc-logs-nginx/_data'
HOST, PORT = '127.0.0.1', 39443
CURL = '/usr/bin/curl'; O = '/opt/openssl/bin/openssl'
WINDOW, STEP, B_EVERY = 15.0, 0.25, 0.2

tsv, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
devs = [l.rstrip('\n').split('\t') for l in open(tsv)][1:]

def crlnum():
    return subprocess.run([O, 'crl', '-in', CRL, '-noout', '-crlnumber'], capture_output=True, text=True,
                          env={**os.environ, 'OPENSSL_CONF': '/dev/null'}).stdout.strip().split('=')[-1]

def curl_get(d, uri):
    s = time.time()
    r = subprocess.run([CURL, '--http1.1', '-sS', '--max-time', '3', '-w', '\n%{http_code}', '--cacert', CHAIN,
                        '--cert', f'{d}/client.crt', '--key', f'{d}/client.key', f'https://{HOST}:{PORT}{uri}'],
                       capture_output=True, text=True)
    e = time.time()
    body, _, code = r.stdout.rpartition('\n')
    m = re.search(r'<title>(.*?)</title>', body)
    return s, e, r.returncode, code or '000', (m.group(1) if m else ''), r.stderr.strip().replace('\t', ' ')[:100]

def docker_ts(ts):
    main, frac = ts.rstrip('Z').split('.')
    return datetime.datetime.strptime(main, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp() + float('0.' + frac)

def reloads_since(t):
    since = datetime.datetime.fromtimestamp(t - 1, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    r = subprocess.run(['docker', 'logs', '-t', '--since', since, 'pqc-gateway'], capture_output=True, text=True)
    return [(docker_ts(l.split(' ', 1)[0]), l) for l in (r.stdout + r.stderr).splitlines() if '[reload-watcher]' in l]

req_f = open(f'{out}/requests.tsv', 'w')
req_f.write('run\tprobe\tk\tstart_minus_t0_s\tend_minus_t0_s\tcurl_exit\thttp\ttitle_or_error\taccess_status\taccess_verify\tafter_reload\n')
sum_f = open(f'{out}/runs.tsv', 'w')
sum_f.write('run\tcn\tserial\tt0_unix\trevoke_http\trevoke_s\tcrl_before\tcrl_after\tpre_http\treload_s\t'
            'A_first_444_s\tA_first_400_s\tA_after_reload_404\tA_after_reload_444\tA_after_reload_400\tA_after_reload_other\t'
            'A_sequence\tB_404_count\tB_end_s\tB_end_kind\tB_404_after_reload\n')
loglines = open(f'{out}/log-lines.txt', 'w')

for run, row in enumerate(devs, 1):
    cn, serial = row[1], row[2]
    d = f'{D}/devices/{cn}'
    crl0 = crlnum()
    pre = curl_get(d, f'/?pre-{run}')
    assert pre[3] == '404', f'run {run}: pre-check answered {pre[3]}'
    B, A = [], []
    stop = threading.Event()

    def probe_b():
        ctx = ssl.create_default_context(cafile=CHAIN); ctx.check_hostname = False
        ctx.load_cert_chain(f'{d}/client.crt', f'{d}/client.key')
        sk = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=3), server_hostname='pqc-gw.local')
        n = 0
        while not stop.is_set():
            s = time.time(); kind = ''
            try:
                sk.sendall(f'GET /?b-{run}-{n} HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: keep-alive\r\n\r\n'.encode())
                buf = b''
                while b'\r\n\r\n' not in buf:
                    c = sk.recv(65536)
                    if not c: raise ConnectionError('EOF: closed by the gateway, no response')
                    buf += c
                hdr, _, body = buf.partition(b'\r\n\r\n'); lines = hdr.split(b'\r\n')
                ln = int([l for l in lines if l.lower().startswith(b'content-length')][0].split(b':')[1])
                while len(body) < ln:
                    c = sk.recv(65536)
                    if not c: raise ConnectionError('EOF mid-body')
                    body += c
                code = lines[0].split(b' ')[1].decode()
            except Exception as ex:
                code = '000'; kind = f'{type(ex).__name__}: {ex}'[:100]
            B.append((n, s, time.time(), code, kind))
            n += 1
            if code != '404':
                return
            time.sleep(B_EVERY)

    tb = threading.Thread(target=probe_b); tb.start()
    time.sleep(1.0)
    assert B and all(x[3] == '404' for x in B), f'run {run}: keep-alive probe not healthy before T0'

    t0 = time.time()
    def probe_a():
        for k in range(int(WINDOW / STEP)):
            time.sleep(max(0.0, t0 + k * STEP - time.time()))
            A.append((k,) + curl_get(d, f'/?a-{run}-{k}'))
    ta = threading.Thread(target=probe_a); ta.start()
    rv = subprocess.run([CURL, '-sS', '--cacert', CHAIN, '--cert', ADM_C, '--key', ADM_K, '-H', 'X-PQC-CSRF: 1',
                         '-H', 'Content-Type: application/json', '-X', 'POST', f'https://{HOST}:{PORT}/admin/certs/revoke',
                         '-d', json.dumps({'serial': serial, 'reason': 'cessationOfOperation'}), '-w', '\n%{http_code}'],
                        capture_output=True, text=True)
    rv_end = time.time()
    ta.join()
    stop.set(); tb.join(timeout=5)
    time.sleep(1.0)                                    # access log flushed (it is written per request)

    rl = [t for t, l in reloads_since(t0) if t >= t0 and 'nginx reloaded' in l]
    reload_at = rl[0] if rl else None
    acc = {}
    for l in open(f'{LOGS}/pqc-mtls-access.log'):
        if f'?a-{run}-' in l or f'?b-{run}-' in l or f'?pre-{run}"' in l:
            j = json.loads(l); acc[j['uri']] = (j['status'], j['verify'])
    def after(s): return reload_at is not None and s >= reload_at
    for (k, s, e, rc, code, title, err) in A:
        st, vf = acc.get(f'/?a-{run}-{k}', ('', ''))
        req_f.write(f'{run}\tA\t{k}\t{s-t0:.4f}\t{e-t0:.4f}\t{rc}\t{code}\t{title or err}\t{st}\t{vf}\t{int(after(s))}\n')
    for (n, s, e, code, kind) in B:
        st, vf = acc.get(f'/?b-{run}-{n}', ('', ''))
        req_f.write(f'{run}\tB\t{n}\t{s-t0:.4f}\t{e-t0:.4f}\t\t{code}\t{kind}\t{st}\t{vf}\t{int(after(s))}\n')
    st, vf = acc.get(f'/?pre-{run}', ('', ''))
    req_f.write(f'{run}\tpre\t0\t{pre[0]-t0:.4f}\t{pre[1]-t0:.4f}\t{pre[2]}\t{pre[3]}\t{pre[4]}\t{st}\t{vf}\t0\n')
    req_f.flush()

    def first(pred):
        r = [x for x in A if pred(x)]
        return f'{r[0][2]-t0:.3f}' if r else 'none'
    # A's answer per request, compressed: e.g. 404x3 444x4 400x53 (access-log status, else curl's)
    seq = []
    for (k, s, e, rc, code, title, err) in A:
        st = acc.get(f'/?a-{run}-{k}', ('',))[0]; v = str(st or code)
        if seq and seq[-1][0] == v: seq[-1][1] += 1
        else: seq.append([v, 1])
    aft = [x for x in A if after(x[1])]
    def acc_status(x): return str(acc.get(f'/?a-{run}-{x[0]}', ('',))[0])
    b404 = [x for x in B if x[3] == '404']
    bend = B[-1] if B else None
    row_out = [str(run), cn, serial, f'{t0:.6f}', rv.stdout.rsplit('\n', 1)[-1], f'{rv_end-t0:.4f}', crl0, crlnum(), pre[3],
               f'{reload_at-t0:.3f}' if reload_at else 'none',
               first(lambda x: acc_status(x) == '444'), first(lambda x: acc_status(x) == '400' or x[4] == '400'),
               str(sum(1 for x in aft if x[4] == '404')), str(sum(1 for x in aft if acc_status(x) == '444')),
               str(sum(1 for x in aft if x[4] == '400')),
               str(sum(1 for x in aft if x[4] not in ('400', '404') and acc_status(x) != '444')),
               ' '.join(f'{v}x{n}' for v, n in seq),
               str(len(b404)), f'{bend[2]-t0:.3f}' if bend else 'none',
               (f'HTTP {bend[3]}' if bend[3] != '000' else bend[4]) if bend else 'none',
               str(sum(1 for x in b404 if after(x[1])))]
    sum_f.write('\t'.join(row_out) + '\n'); sum_f.flush()
    print('\t'.join(row_out), flush=True)

    # log lines of this run: reload watcher, crl_worker polls, the info-level verify errors
    loglines.write(f'=== run {run} {cn} serial {serial}, T0 {datetime.datetime.fromtimestamp(t0, datetime.timezone.utc).isoformat()}\n')
    for t, l in reloads_since(t0): loglines.write(f'gateway stdout: {l}\n')
    lo = datetime.datetime.fromtimestamp(t0 - 1, datetime.timezone.utc).strftime('%Y/%m/%d %H:%M:%S')
    hi = datetime.datetime.fromtimestamp(t0 + WINDOW + 2, datetime.timezone.utc).strftime('%Y/%m/%d %H:%M:%S')
    for f in ('error.log', 'pqc-mtls-error.log', 'pqc-mtls-handshake.log'):
        hits = [l.rstrip('\n') for l in open(f'{LOGS}/{f}') if lo <= l[:19] <= hi and
                ('crl_worker' in l or 'certificate' in l.lower() or 'revoked' in l.lower())]
        for l in hits[:6]: loglines.write(f'{f}: {l}\n')
        if len(hits) > 6: loglines.write(f'{f}: ... {len(hits)} matching lines in the window\n')
    loglines.flush()
    time.sleep(3.0)
print('done', flush=True)
