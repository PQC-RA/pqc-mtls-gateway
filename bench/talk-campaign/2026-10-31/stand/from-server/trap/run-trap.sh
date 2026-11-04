#!/bin/bash
# Stand only (stand PKI, not the live CA). A classical ECDSA leaf signed by the stand's ML-DSA-65 intermediate,
# offered to two otherwise identical servers: without and with -client_sigalgs ML-DSA-65.
C=/root/talk-campaign-20261031; P=$C/bench/pki/pqc; T=$C/trap; cd $T
O=/opt/openssl/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
for f in noguard.pid guard.pid; do [ -f $f ] && kill $(cat $f) 2>/dev/null; done; sleep 0.3
$O s_server -accept 4445 -www -tls1_3 -no_ticket -no_cache -cert $P/server.crt -key $P/server.key -Verify 2 -verifyCAfile $P/ca-chain.crt -no-CAfile > s_server-noguard.out 2>&1 & echo $! > noguard.pid
$O s_server -accept 4446 -www -tls1_3 -no_ticket -no_cache -cert $P/server.crt -key $P/server.key -Verify 2 -verifyCAfile $P/ca-chain.crt -no-CAfile -client_sigalgs ML-DSA-65 > s_server-guard.out 2>&1 & echo $! > guard.pid
sleep 1.5
for p in 4445 4446; do
  printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 $O s_client -connect 127.0.0.1:$p -verifyCAfile $P/ca-chain.crt -no-CAfile -cert ecdsa.crt -key ecdsa.key -ign_eof > client-$p.txt 2>&1
done
sleep 0.5; kill $(cat noguard.pid) $(cat guard.pid) 2>/dev/null
