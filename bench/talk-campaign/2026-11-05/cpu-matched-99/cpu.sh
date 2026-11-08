#!/bin/bash
# CPU per handshake, client side, matched arms (ML-DSA-65 vs ECDSA P-256 PKIs of 4 Nov).
# Test ports on 127.0.0.1 only; no MTU change; nothing live touched. Windows interleaved: classical, pqc, x3.
C=/root/talk-campaign-20261105-cpu; P=/root/talk-campaign-20261104/bench/pki; O=/opt/openssl/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
$O version > $C/env.txt; uptime >> $C/env.txt; nproc >> $C/env.txt
start() { nohup $O s_server -accept 127.0.0.1:$1 -www -tls1_3 -no_ticket -no_cache -cert $P/$2/server.crt -key $P/$2/server.key -Verify 2 -verifyCAfile $P/$2/ca-chain.crt -no-CAfile -groups $3 > $C/arm-$1.log 2>&1 & echo $! >> $C/pids; }
start 14443 pqc X25519MLKEM768; start 14444 classical X25519; sleep 1.5
for w in 1 2 3; do for spec in "classical 14444 X25519" "pqc 14443 X25519MLKEM768"; do set -- $spec
  echo "=== $1 window $w $(date -u +%FT%TZ)" >> $C/s_time-raw.txt
  $O s_time -connect 127.0.0.1:$2 -new -time 10 -cert $P/$1/client.crt -key $P/$1/client.key -CAfile $P/$1/ca-chain.crt >> $C/s_time-raw.txt 2>&1
done; done
kill $(cat $C/pids) 2>/dev/null; uptime >> $C/env.txt
grep -E "^===|connections/user sec" $C/s_time-raw.txt
