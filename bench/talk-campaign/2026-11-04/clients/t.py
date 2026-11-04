import ssl,socket,sys
host,port,ca=sys.argv[1],int(sys.argv[2]),sys.argv[3]
try:
    ctx=ssl.create_default_context(cafile=ca); ctx.check_hostname=False
    s=ctx.wrap_socket(socket.create_connection((host,port),timeout=5)); print('OK',s.version(),ssl.OPENSSL_VERSION)
except Exception as e: print('FAIL',type(e).__name__,str(e)[:100],ssl.OPENSSL_VERSION)
