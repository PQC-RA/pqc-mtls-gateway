import sys,json,hmac,hashlib,time,urllib.request,os
sec=open(sys.argv[1]).read().strip(); csr=open(sys.argv[2]).read(); tok=sys.argv[3]; base=sys.argv[4]; out=sys.argv[5]
path="/api/admin/certs/sign"; body=json.dumps({"csr":csr,"enrollmentToken":tok}).encode(); ts=str(int(time.time()))
sig=hmac.new(sec.encode(),f"{ts}\nPOST\n{path}\n".encode()+body,hashlib.sha256).hexdigest()
rq=urllib.request.Request(base+path,data=body,method="POST",headers={"Content-Type":"application/json","X-Timestamp":ts,"X-Hub-Signature-256":"sha256="+sig})
try: r=urllib.request.urlopen(rq,timeout=30); code=r.status; txt=r.read().decode()
except urllib.error.HTTPError as e: code=e.code; txt=e.read().decode()
try: j=json.loads(txt)
except Exception: j={"raw":txt[:200]}
print(code, json.dumps({k:(v if k!="certificate" else "<pem>") for k,v in j.items()})[:300])
c=j.get("certificate") or (j.get("data") or {}).get("certificate") if isinstance(j,dict) else None
if c: open(out,"w").write(c)
