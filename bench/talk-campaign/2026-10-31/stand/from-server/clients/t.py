import ssl,socket,sys
host,port,ca=sys.argv[1],int(sys.argv[2]),sys.argv[3]; cert=sys.argv[4] if len(sys.argv)>4 else None
try:
    ctx=ssl.create_default_context(cafile=ca); ctx.check_hostname=False
    if cert: ctx.load_cert_chain(cert,sys.argv[5])
    s=ctx.wrap_socket(socket.create_connection((host,port),timeout=5))
    s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'); print('OK', s.recv(64).split(b'\r\n')[0].decode(), s.version(), ssl.OPENSSL_VERSION)
except Exception as e: print('FAIL', type(e).__name__, str(e)[:140], ssl.OPENSSL_VERSION)
