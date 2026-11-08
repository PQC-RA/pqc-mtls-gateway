"""Live renewal semantics on a 120 s demo device (post-cutover gateway), from the Mac over the VPN.
T1 retry with the same key/CSR  -> same certificate (replay)
T2 second, different key        -> refused (one successor per certificate)
T3 keep-alive connection opened with the OLD certificate -> refused on the first request after notAfter
T4 request with the old certificate on a NEW connection after notAfter -> refused"""
import json, os, subprocess, sys, time, hashlib, base64, socket, ssl, threading, tempfile, re, calendar
D=sys.argv[1]; GW='203.0.113.99'
O='/opt/homebrew/opt/openssl@3/bin/openssl'; CURL='/opt/homebrew/opt/curl/bin/curl'
def sh(*a, **k): return subprocess.run(a, capture_output=True, text=True, **k)
def enddate(crt):
    s=sh(O,'x509','-in',crt,'-noout','-enddate').stdout.strip().split('=')[1]
    return calendar.timegm(time.strptime(' '.join(s.split()),'%b %d %H:%M:%S %Y %Z'))
def startdate(crt):
    s=sh(O,'x509','-in',crt,'-noout','-startdate').stdout.strip().split('=')[1]
    return calendar.timegm(time.strptime(' '.join(s.split()),'%b %d %H:%M:%S %Y %Z'))
def serial(crt): return sh(O,'x509','-in',crt,'-noout','-serial').stdout.strip().split('=')[1]
log=[]
def say(m): 
    line=f'{time.strftime("%H:%M:%S",time.gmtime())}Z {m}'; print(line,flush=True); log.append(line)
crt,key,ca=f'{D}/client.crt',f'{D}/client.key',f'{D}/ca-chain.crt'
S1=serial(crt); nb,na=startdate(crt),enddate(crt)
issued=nb+60; at=issued+(na-issued)*2//3
say(f'S1={S1} notBefore={nb} notAfter={na} renew window opens at {at} (in {at-int(time.time())} s)')
# keep-alive probe on the OLD certificate, opened now
res={'ka':[], 'ka_first_refusal':None}
ctx=ssl.create_default_context(cafile=ca); ctx.check_hostname=False; ctx.load_cert_chain(crt,key)
def ka():
    sk=ctx.wrap_socket(socket.create_connection((GW,443),timeout=5))
    while True:
        t=time.time()
        try:
            sk.sendall(b'GET / HTTP/1.1\r\nHost: gw\r\nConnection: keep-alive\r\n\r\n'); buf=b''
            while b'\r\n\r\n' not in buf:
                c=sk.recv(4096)
                if not c: raise ConnectionError('closed')
                buf+=c
            hdr,_,body=buf.partition(b'\r\n\r\n'); code=hdr.split(b'\r\n')[0].split(b' ')[1].decode()
            n=int(re.search(rb'(?i)content-length:\s*(\d+)',hdr).group(1))
            while len(body)<n: body+=sk.recv(4096)
        except Exception as e: code='ERR:'+type(e).__name__
        res['ka'].append((t,code))
        if code!='404':
            res['ka_first_refusal']=(t,code); return
        time.sleep(0.25)
th=threading.Thread(target=ka,daemon=True); th.start()
while time.time()<at+1: time.sleep(0.5)
def mkpend(tag):
    k=f'{D}/{tag}.key'; c=f'{D}/{tag}.csr'
    sh(O,'genpkey','-algorithm','ML-DSA-65','-out',k)
    subj=sh(O,'x509','-in',crt,'-noout','-subject','-nameopt','compat').stdout.strip().replace('subject=','')
    sh(O,'req','-new','-key',k,'-subj',subj,'-out',c,env=dict(os.environ,OPENSSL_CONF='/dev/null'))
    return k,c
def renew(csr):
    der=subprocess.run([O,'req','-in',csr,'-outform','DER'],capture_output=True).stdout
    h=hashlib.sha256(der).hexdigest(); ts=int(time.time())
    msg=f'pqc-renew-v1\n{h}\n{S1}\n{ts}'.encode()
    with tempfile.TemporaryDirectory() as w:
        open(f'{w}/m','wb').write(msg)
        sh(O,'pkeyutl','-sign','-inkey',key,'-rawin','-in',f'{w}/m','-out',f'{w}/s')
        body=json.dumps({'csr':open(csr).read(),'pop':{'timestamp':ts,'signature':base64.b64encode(open(f'{w}/s','rb').read()).decode()}})
        open(f'{w}/b','w').write(body)
        r=sh(CURL,'-sS','--curves','X25519MLKEM768','--resolve',f'pqc-gw.local:443:{GW}','--cacert',ca,'--cert',crt,'--key',key,'--max-time','30','-H','Content-Type: application/json','--data-binary',f'@{w}/b','-o',f'{w}/r','-w','%{http_code}','-X','POST','https://pqc-gw.local/renew')
        txt=open(f'{w}/r').read()
        return r.stdout.strip(),txt
k1,c1=mkpend('pend1'); k2,c2=mkpend('pend2')
code,txt=renew(c1); j=json.loads(txt) if txt.startswith('{') else {}
cert1=j.get('certificate',''); open(f'{D}/succ1.crt','w').write(cert1)
s1=serial(f'{D}/succ1.crt') if cert1 else None
say(f'T1a first renewal: HTTP {code} successor serial {s1} replay={j.get("replay")}')
code,txt=renew(c1); j=json.loads(txt) if txt.startswith('{') else {}
open(f'{D}/succ1b.crt','w').write(j.get('certificate',''))
s1b=serial(f'{D}/succ1b.crt') if j.get('certificate') else None
say(f'T1b retry, same CSR/key: HTTP {code} serial {s1b} replay={j.get("replay")} -> {"SAME certificate" if s1b==s1 else "DIFFERENT"}')
code,txt=renew(c2)
say(f'T2 second, different key from the same certificate: HTTP {code} {txt[:140]}')
# wait for the old certificate to expire
while time.time()<na+3: time.sleep(0.5)
th.join(timeout=5)
fr=res['ka_first_refusal']
if fr: say(f'T3 keep-alive on old cert: first non-404 = {fr[1]} at notAfter{fr[0]-na:+.2f} s; last 404 at {res["ka"][-2][0]-na:+.2f} s; requests {len(res["ka"])}')
else: say('T3 keep-alive still accepted after notAfter (!)')
r=sh(CURL,'-s','-o','/dev/null','-w','%{http_code}','--curves','X25519MLKEM768','--resolve',f'pqc-gw.local:443:{GW}','--cacert',ca,'--cert',crt,'--key',key,'https://pqc-gw.local/')
say(f'T4 new connection with the expired old cert: HTTP {r.stdout.strip()} (curl exit {r.returncode})')
open(f'{D}/semantics.log','w').write('\n'.join(log)+'\n')
