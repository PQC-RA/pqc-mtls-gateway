#!/bin/bash
# Isolated 2x2 matrix test, column B (handshake): throwaway OpenResty (the gateway base image, OpenSSL 3.6.5) on loopback,
# stand PKI (own throwaway ML-DSA-65 CA, NOT the live CA), directive on / removed, patched OpenSSL 3.6.5 client.
W=/root/talk-campaign-20261104/matrix; P=/root/talk-campaign-20261104/bench/pki/pqc; cd $W
O=/opt/openssl/bin/openssl; export OPENSSL_CONF=/dev/null
P8=/root/talk-campaign-20261104/t8b/openssl-8b-3.6.5
printf "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth\n" > leaf.ext
mk(){ n=$1; shift; $O genpkey "$@" -out $n.key 2>/dev/null; $O req -new -key $n.key -subj "/C=BG/O=ACME/OU=M2M-Client/CN=m-$n" -out $n.csr; $O x509 -req -in $n.csr -CA $P/int.crt -CAkey $P/int.key -set_serial 0x$(printf %x $((RANDOM+4000))) -days 1 -extfile leaf.ext -out $n.crt 2>/dev/null; }
mk ecdsa -algorithm EC -pkeyopt ec_paramgen_curve:P-256; mk rsa -algorithm RSA -pkeyopt rsa_keygen_bits:3072
cp $P/client.crt mldsa.crt; cp $P/client.key mldsa.key
cat > nginx.conf <<NG
worker_processes 1; pid /tmp/m.pid; error_log /logs/error.log info; events {}
http { access_log /logs/access.log;
 server { listen 29901 ssl; server_name pqc-gw.local; ssl_certificate /pki/server.crt; ssl_certificate_key /pki/server.key;
   ssl_client_certificate /pki/ca-chain.crt; ssl_verify_client on; ssl_verify_depth 2; ssl_protocols TLSv1.3;
   ssl_conf_command Groups X25519MLKEM768; ssl_conf_command ClientSignatureAlgorithms ML-DSA-65;
   location / { return 200 "OK guard\n"; } }
 server { listen 29902 ssl; server_name pqc-gw.local; ssl_certificate /pki/server.crt; ssl_certificate_key /pki/server.key;
   ssl_client_certificate /pki/ca-chain.crt; ssl_verify_client on; ssl_verify_depth 2; ssl_protocols TLSv1.3;
   ssl_conf_command Groups X25519MLKEM768;
   location / { return 200 "OK noguard\n"; } } }
NG
mkdir -p logs; : > logs/error.log; : > logs/access.log; cp $P/server.crt $P/server.key $P/ca-chain.crt .; chmod 644 server.key
docker rm -f m-matrix >/dev/null 2>&1
docker run -d --rm --name m-matrix --network host -v $W:/conf:ro -v $W:/pki:ro -v $W/logs:/logs --entrypoint /usr/local/openresty/bin/openresty pqc-gateway:adr024-4b -c /conf/nginx.conf -g "daemon off;" >/dev/null; sleep 2
docker exec m-matrix /opt/openssl/bin/openssl version 2>/dev/null; docker exec m-matrix /usr/local/openresty/bin/openresty -V 2>&1 | grep -oE "OpenSSL [0-9.]+[a-z]*|openresty/[0-9.]+" | head -2
req(){ # label client port cert key
  l=$1; cl=$2; port=$3; crt=$4; key=$5
  if [ $cl = patched ]; then R="env TEST8B_FORCE_CLIENT_SIGALG=1 LD_LIBRARY_PATH=$P8/lib64 $P8/bin/openssl"; else R="env LD_LIBRARY_PATH=/opt/openssl/lib64 $O"; fi
  printf "GET / HTTP/1.1\r\nHost: pqc-gw.local\r\nConnection: close\r\n\r\n" | timeout 15 $R s_client -connect 127.0.0.1:$port -servername pqc-gw.local -verifyCAfile $P/ca-chain.crt -no-CAfile -cert $crt -key $key -groups X25519MLKEM768 -ign_eof > out-$l.txt 2>&1
  http=$(grep -m1 -oE "HTTP/1\.[01] [0-9]+" out-$l.txt || echo "no HTTP"); al=$(grep -m1 -oE "alert [a-z ]+(number [0-9]+)?|SSL alert number [0-9]+" out-$l.txt | head -1); fo=$(grep -m1 "TEST8B" out-$l.txt | cut -c1-70)
  printf "%-34s %-8s %-9s %-14s %s %s\n" "$l" "$cl" "port $port" "$http" "$al" "$fo"
}
echo "=== directive ON  (ssl_conf_command ClientSignatureAlgorithms ML-DSA-65)  = matrix rows 1 and 2, column B"
req ON-stock-ecdsa stock 29901 ecdsa.crt ecdsa.key
req ON-forced-ecdsa patched 29901 ecdsa.crt ecdsa.key
req ON-forced-rsa patched 29901 rsa.crt rsa.key
req ON-forced-mldsa-control patched 29901 mldsa.crt mldsa.key
echo "=== directive REMOVED                                                      = matrix rows 3 and 4, column B"
req OFF-stock-ecdsa stock 29902 ecdsa.crt ecdsa.key
req OFF-forced-ecdsa patched 29902 ecdsa.crt ecdsa.key
req OFF-forced-rsa patched 29902 rsa.crt rsa.key
req OFF-stock-mldsa-control stock 29902 mldsa.crt mldsa.key
echo "--- nginx error log (handshake failures)"; grep -E "wrong signature|SSL_do_handshake|peer did not return" logs/error.log | cut -c1-210 | sort | uniq -c | head -6
echo "--- nginx access log"; cat logs/access.log | cut -c1-150
docker rm -f m-matrix >/dev/null 2>&1; shred -u ecdsa.key rsa.key 2>/dev/null; echo done
