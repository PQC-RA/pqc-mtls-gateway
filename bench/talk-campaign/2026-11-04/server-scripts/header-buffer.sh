#!/bin/bash
# Default nginx (stock nginx:alpine, default large_client_header_buffers 4 8k) on 127.0.0.1 only, default bridge,
# no live network attached. Send the device certificate the way a TLS-terminating proxy forwards it.
C=/root/talk-campaign-20261104; cd $C
python3 -I -c 'import urllib.parse,sys;p=open(sys.argv[1]).read();e=urllib.parse.quote(p,safe="");print(len(p.encode()),len(e));open(sys.argv[2],"w").write(e)' talk-probe-01.crt cert-urlenc.txt
docker rm -f talk-hdrbuf >/dev/null 2>&1
docker run -d --rm --name talk-hdrbuf -p 127.0.0.1:18080:80 nginx:alpine >/dev/null; sleep 1.5
docker exec talk-hdrbuf sh -c 'nginx -T 2>/dev/null | grep -c large_client_header_buffers' | sed 's/^/explicit large_client_header_buffers lines in stock config: /'
H=$(cat cert-urlenc.txt)
printf 'header\theader_value_bytes\thttp\n'
printf 'X-SSL-Client-Cert (URL-encoded ML-DSA-65 cert)\t%d\t%s\n' ${#H} $(curl -s -o /dev/null -w '%{http_code}' -H "X-SSL-Client-Cert: $H" http://127.0.0.1:18080/)
F=$(sha256sum < talk-probe-01.crt | cut -c1-64)
printf 'X-SSL-Client-Fingerprint (SHA-256)\t%d\t%s\n' ${#F} $(curl -s -o /dev/null -w '%{http_code}' -H "X-SSL-Client-Fingerprint: $F" http://127.0.0.1:18080/)
for n in 8000 8150 8200; do V=$(head -c $n /dev/zero | tr '\0' a); printf 'synthetic\t%d\t%s\n' $n $(curl -s -o /dev/null -w '%{http_code}' -H "X: $V" http://127.0.0.1:18080/); done
docker rm -f talk-hdrbuf >/dev/null
