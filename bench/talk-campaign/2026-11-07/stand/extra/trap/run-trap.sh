#!/bin/bash
# Slide 11, 2026-11-07, test stand: an ECDSA P-256 leaf signed by the post-quantum (ML-DSA-65) intermediate,
# offered to two otherwise identical servers, without and with -client_sigalgs ML-DSA-65.
# Unlike the 4 Nov copy, the servers refuse any chain error (-verify_return_error).
set -uo pipefail
R=/root/rerun-20261107; P=$R/pki/pq; T=$R/extra/trap; cd $T; O=/opt/openssl-3.6.5/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
$O ecparam -name prime256v1 -genkey -noout -out ecdsa.key
$O req -new -key ecdsa.key -subj "/CN=rerun-classical1" -out ecdsa.csr
$O x509 -req -in ecdsa.csr -CA $P/int.crt -CAkey $P/int.key -set_serial 0x10C0 -days 30 -extfile $R/pki/ext.cnf -extensions device -out ecdsa.crt 2>/dev/null
$O verify -CAfile $P/ca-chain.crt ecdsa.crt
$O x509 -in ecdsa.crt -noout -text | grep -E "Signature Algorithm|Public Key Algorithm" | sort -u
srv() { $O s_server -accept $1 -www -tls1_3 -no_ticket -no_cache -cert $P/server.crt -key $P/server.key -Verify 2 -verify_return_error -verifyCAfile $P/ca-chain.crt -no-CAfile $2 > s_server-$1.out 2>&1 & echo $! > $1.pid; }
srv 31447 ""; srv 31448 "-client_sigalgs ML-DSA-65"; sleep 1.5
for p in 31447 31448; do printf "GET / HTTP/1.0\r\n\r\n" | timeout 10 $O s_client -connect 127.0.0.1:$p -verifyCAfile $P/ca-chain.crt -no-CAfile -cert ecdsa.crt -key ecdsa.key -ign_eof > client-$p.txt 2>&1; done
sleep 0.5; kill $(cat 31447.pid) $(cat 31448.pid) 2>/dev/null; rm -f ecdsa.key *.pid
for p in 31447 31448; do echo "== $p"; grep -E "Requested Signature Algorithms|Peer signature type|Verify return code|^HTTP/1.0|alert|Verification" client-$p.txt | head -8; done
