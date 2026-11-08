import sys,ssl,socket,time,re,calendar,subprocess,json
D=sys.argv[1]; GW='192.168.1.99'; O='/opt/homebrew/opt/openssl@3/bin/openssl'; CURL='/opt/homebrew/opt/curl/bin/curl'
s=subprocess.run([O,'x509','-in',f'{D}/client.crt','-noout','-enddate'],capture_output=True,text=True).stdout.strip().split('=')[1]
na=calendar.timegm(time.strptime(' '.join(s.split()),'%b %d %H:%M:%S %Y %Z'))
ctx=ssl.create_default_context(cafile=f'{D}/ca-chain.crt'); ctx.check_hostname=False; ctx.load_cert_chain(f'{D}/client.crt',f'{D}/client.key')
sk=ctx.wrap_socket(socket.create_connection((GW,443),timeout=5)); last_ok=None; first=None; n=0
while True:
    t=time.time()
    try:
        sk.sendall(b'GET / HTTP/1.1\r\nHost: gw\r\nConnection: keep-alive\r\n\r\n'); buf=b''
        while b'\r\n\r\n' not in buf:
            c=sk.recv(4096)
            if not c: raise ConnectionError('closed')
            buf+=c
        hdr,_,body=buf.partition(b'\r\n\r\n'); code=hdr.split(b'\r\n')[0].split(b' ')[1].decode()
        ln=int(re.search(rb'(?i)content-length:\s*(\d+)',hdr).group(1))
        while len(body)<ln: body+=sk.recv(4096)
    except Exception as e: code='ERR:'+type(e).__name__
    n+=1
    if code=='404': last_ok=t
    else: first=(t,code); break
    if t>na+20: break
    time.sleep(0.25)
print(f'T3 keep-alive opened before expiry, same connection: requests={n}, last accepted at notAfter{(last_ok-na):+.2f} s, first refusal {first[1] if first else None} at notAfter{(first[0]-na):+.2f} s' if first else 'T3 still accepted 20 s after notAfter')
r=subprocess.run([CURL,'-s','-o','/dev/null','-w','%{http_code}','--curves','X25519MLKEM768','--resolve',f'pqc-gw.local:443:{GW}','--cacert',f'{D}/ca-chain.crt','--cert',f'{D}/client.crt','--key',f'{D}/client.key','https://pqc-gw.local/'],capture_output=True,text=True)
print('T4 new connection, expired cert: HTTP',r.stdout.strip())
