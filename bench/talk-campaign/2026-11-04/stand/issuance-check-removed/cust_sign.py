import sys,json,hmac,hashlib,os,time,urllib.request
sec=open(sys.argv[1]).read().strip(); csr=open(sys.argv[2]).read(); url=sys.argv[3]; path="/sign"
body=json.dumps({"csrPem":csr}).encode(); ts=str(int(time.time()*1000)); nonce=os.urandom(16).hex()
sig=hmac.new(sec.encode(),f"v2\nPOST\n{path}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode(),hashlib.sha256).hexdigest()
req=urllib.request.Request(url+path,data=body,method="POST",headers={"Content-Type":"application/json","x-hub-signature-256":"sha256="+sig,"x-custodian-timestamp":ts,"x-custodian-nonce":nonce})
try:
    r=urllib.request.urlopen(req,timeout=20); code=r.status; txt=r.read().decode()
except urllib.error.HTTPError as e: code=e.code; txt=e.read().decode()
j=json.loads(txt); print(code, {k:(v if k!="certificate" else "<pem>") for k,v in j.items()} if isinstance(j,dict) else j)
if isinstance(j,dict) and j.get("certificate"): open(sys.argv[4],"w").write(j["certificate"])
