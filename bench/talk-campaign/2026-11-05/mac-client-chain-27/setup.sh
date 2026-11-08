#!/bin/bash
# Mac client chain on the test stand. Throwaway ML-DSA-65 PKI; keys deleted after the run.
set -euo pipefail
export OPENSSL_CONF=/etc/ssl/openssl.cnf; O=/opt/openssl-3.6.5/bin/openssl; cd /root/macchain-20261105
$O req -x509 -newkey ML-DSA-65 -nodes -keyout root.key -out root.crt -days 2 -subj "/O=Test/CN=Mac Chain Root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
$O req -newkey ML-DSA-65 -nodes -keyout int.key -out int.csr -subj "/O=Test/CN=Mac Chain Intermediate" 2>/dev/null
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > int.ext
$O x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -days 2 -out int.crt -extfile int.ext 2>/dev/null
$O req -newkey ML-DSA-65 -nodes -keyout server.key -out server.csr -subj "/CN=stand-27" 2>/dev/null
printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:stand-27\n" > server.ext
$O x509 -req -in server.csr -CA int.crt -CAkey int.key -CAcreateserial -days 2 -out server.crt -extfile server.ext 2>/dev/null
printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n" > client.ext
$O x509 -req -in mac.csr -CA int.crt -CAkey int.key -CAcreateserial -days 2 -out client.crt -extfile client.ext 2>/dev/null
cat int.crt root.crt > ca-chain.crt
printf "ok" > x
for f in root int server client; do echo "$f $($O x509 -in $f.crt -outform DER | wc -c) B DER"; done
