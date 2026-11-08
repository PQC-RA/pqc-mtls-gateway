#!/bin/bash
# 2026-11-07, test stand: (1) what the session tickets carry, (2) issuance with the live device profile,
# (3) a classical leaf under the post-quantum intermediate (slide 11). Nothing live touched.
set -uo pipefail
cd /root/rerun-20261107; export OPENSSL_CONF=/etc/ssl/openssl.cnf; O=/opt/openssl-3.6.5/bin/openssl
mkdir -p extra; X=extra
# ---- (1) tickets: the same servers with client authentication on and off
sed -e "s/listen 127.0.0.1:31443 ssl;/listen 127.0.0.1:31443 ssl;/" nginx.conf > $X/nginx-tickets.conf
python3 - <<"PY"
p = "extra/nginx-tickets.conf"; s = open(p).read()
blocks = s.split("    server {")
head, pq, cl = blocks[0], "    server {" + blocks[1], "    server {" + blocks[2].rsplit("}", 1)[0]
off = lambda b, port_from, port_to: b.replace(port_from, port_to).replace("ssl_verify_client on;", "ssl_verify_client off;")
s = head + pq + cl + off(pq, "31443", "31445") + off(cl, "31444", "31446") + "}\n"
open(p, "w").write(s)
PY
docker rm -f rerun-nginx >/dev/null 2>&1
docker run -d --name rerun-nginx --network host -v /root/rerun-20261107:/r:ro --entrypoint nginx clean1-gateway:11a5422 -c /r/extra/nginx-tickets.conf -g "daemon off;" >/dev/null; sleep 2
printf "port\tarm\tclient_auth\ttickets\tticket_bytes_each\tsession_der_bytes\n" > $X/tickets.tsv
for spec in "31443 pq on" "31444 cl on" "31445 pq off" "31446 cl off"; do set -- $spec
  for k in 1 2 3; do
    out=$( (printf "GET / HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: close\r\n\r\n"; sleep 0.3) | $O s_client -connect 127.0.0.1:$1 -servername pqc-gw.local -cert pki/$2/device.crt -key pki/$2/device.key -verifyCAfile pki/$2/ca-chain.crt -verify_return_error -ign_eof -sess_out $X/sess-$1-$k.pem 2>&1)
    n=$(grep -c "Post-Handshake New Session Ticket arrived" <<<"$out")
    tl=$($O sess_id -in $X/sess-$1-$k.pem -noout -text | awk "/TLS session ticket:/{f=1;next} f&&/^ *[0-9a-f]{4} -/{n+=NF-1} /^ *$/{if(f)exit} END{print n}")
    der=$($O sess_id -in $X/sess-$1-$k.pem -outform DER | wc -c)
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" $1 $2 $3 $n $tl $der >> $X/tickets.tsv
  done
done
docker rm -f rerun-nginx >/dev/null 2>&1
cat $X/tickets.tsv
