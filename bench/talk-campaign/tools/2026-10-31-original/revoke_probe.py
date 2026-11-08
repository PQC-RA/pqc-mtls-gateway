"""One revocation run, timed from this Mac (one clock).

  probe A  fresh connection per request (curl, new TLS handshake each time)
  probe B  one keep-alive connection, a GET every 50 ms (Python ssl on OpenSSL 3.6)
  T0       taken here immediately before the revoke call is sent over an already-open SSH master
  accepted = HTTP 404 (authenticated; this CN has no route). Anything else is a refusal:
           444/000 = connection closed by the data-plane CRL check, 400 = nginx ssl_verify_client refusal
  refusal  first request in each probe that STARTS after T0 and is not accepted
Prints one TSV row: run cn serial t0 freshA_s keepaliveB_s A_last_ok_s B_last_ok_s
"""
import json, os, socket, ssl, subprocess, sys, threading, time

cn, d, serial, run = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
GW = '192.168.1.99'
CURL = '/opt/homebrew/opt/curl/bin/curl'
CTL = os.environ['SSH_CTL']
stop = threading.Event()
A, B = [], []          # (start, end, ok)

def probe_a():
    while not stop.is_set():
        s = time.time()
        r = subprocess.run([CURL, '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '3',
                            '--cacert', f'{d}/ca-chain.crt', '--cert', f'{d}/client.crt', '--key', f'{d}/client.key',
                            f'https://{GW}/'], capture_output=True, text=True)
        A.append((s, time.time(), r.stdout.strip() == '404', r.stdout.strip()))

def probe_b():
    ctx = ssl.create_default_context(cafile=f'{d}/ca-chain.crt')
    ctx.check_hostname = False
    ctx.load_cert_chain(f'{d}/client.crt', f'{d}/client.key')
    sk = ctx.wrap_socket(socket.create_connection((GW, 443), timeout=3))
    while not stop.is_set():
        s = time.time(); ok = False; code = '000'
        try:
            sk.sendall(b'GET / HTTP/1.1\r\nHost: gw\r\nConnection: keep-alive\r\n\r\n')
            buf = b''
            while b'\r\n\r\n' not in buf:
                c = sk.recv(4096)
                if not c: raise ConnectionError('closed')
                buf += c
            hdr, _, body = buf.partition(b'\r\n\r\n')
            n = int([l for l in hdr.split(b'\r\n') if l.lower().startswith(b'content-length')][0].split(b':')[1])
            while len(body) < n: body += sk.recv(4096)
            ok = hdr.split(b'\r\n')[0].split(b' ')[1] == b'404'
            code = hdr.split(b'\r\n')[0].split(b' ')[1].decode()
        except Exception:
            ok = False
        B.append((s, time.time(), ok, code))
        if not ok: return
        time.sleep(0.05)

ta = threading.Thread(target=probe_a); tb = threading.Thread(target=probe_b)
ta.start(); tb.start(); time.sleep(1.5)
healthy = bool(A and all(x[2] for x in A) and B and all(x[2] for x in B))
body = json.dumps({'serial': serial, 'reason': 'cessationOfOperation'})
t0 = time.time()
rv = subprocess.run(['ssh', '-o', f'ControlPath={CTL}', 'root@' + GW,
                     "cd /root/pqc-gw-live && curl -sS --cacert /etc/pki/pqc-ca/ca-chain.crt --cert admin-cert/gateway-admin.crt "
                     "--key admin-cert/gateway-admin.key -H X-PQC-CSRF:1 -H 'Content-Type: application/json' "
                     f"-X POST https://127.0.0.1/admin/certs/revoke -d '{body}'"], capture_output=True, text=True)
deadline = t0 + 15
while time.time() < deadline:
    ra = [x for x in A if x[0] > t0 and not x[2]]
    if ra and (not tb.is_alive()): break
    time.sleep(0.05)
stop.set(); ta.join(); tb.join(timeout=5)

def first_refusal(xs):
    r = [x for x in xs if x[0] > t0 and not x[2]]
    return (r[0][1] - t0) if r else float('nan')
def last_ok(xs):
    r = [x for x in xs if x[2] and x[1] > t0]
    return (r[-1][1] - t0) if r else 0.0
if not healthy:   # the device is still revoked (cleanup), but the run is not timed
    print('\t'.join([run, cn, serial, f'{t0:.3f}', 'nan', 'nan', '0', '0', str(len(A)), str(len(B)),
                     'EXCLUDED probes not healthy before revoke; ' + rv.stdout.strip()[:50]]))
    sys.exit(0)
open(os.environ.get('CODES_OUT','/dev/null'),'a').write(''.join(f'{run}\tA\t{x[0]-t0:.3f}\t{x[3]}\n' for x in A)+''.join(f'{run}\tB\t{x[0]-t0:.3f}\t{x[3]}\n' for x in B))
print('\t'.join([run, cn, serial, f'{t0:.3f}', f'{first_refusal(A):.3f}', f'{first_refusal(B):.3f}',
                 f'{last_ok(A):.3f}', f'{last_ok(B):.3f}', str(len(A)), str(len(B)), rv.stdout.strip()[:80].replace('\t', ' ')]))
