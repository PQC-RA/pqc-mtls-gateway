#!/bin/bash
# Matched arms on loopback, same method as the VPN run: curl time_appconnect - time_connect,
# 220 interleaved pairs, the first 20 discarded as warm-up. Arms on 127.0.0.1 only.
set -euo pipefail
C=/root/talk-campaign-20261104; P=$C/bench/pki; O=/opt/openssl/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
OUT=$C/loopback-matched-latency.tsv
start() { nohup $O s_server -accept 127.0.0.1:$1 -www -tls1_3 -no_ticket -no_cache -cert $P/$2/server.crt -key $P/$2/server.key -Verify 2 -verifyCAfile $P/$2/ca-chain.crt -no-CAfile -groups $3 > $C/arm-lo-$1.log 2>&1 & echo $!; }
A=$(start 4443 pqc X25519MLKEM768); B=$(start 4444 classical X25519); sleep 1.5
trap 'kill $A $B 2>&1 || echo "arm already gone"' EXIT
uptime > $C/loopback-matched-uptime.txt
echo -e "i\tarm\tcode\tconnect_s\tappconnect_s\thandshake_ms" > $OUT
for i in $(seq 1 220); do for spec in "pqc 4443 X25519MLKEM768" "classical 4444 X25519"; do set -- $spec
  r=$(curl -s --curves $3 --cacert $P/$1/ca-chain.crt --cert $P/$1/client.crt --key $P/$1/client.key --resolve pqc-gw.local:$2:127.0.0.1 -o /dev/null -w '%{http_code}\t%{time_connect}\t%{time_appconnect}' --max-time 5 https://pqc-gw.local:$2/)
  echo -e "$i\t$1\t$r\t$(awk -F'\t' '{printf "%.3f", ($3-$2)*1000}' <<<"$r")" >> $OUT
done; done
uptime >> $C/loopback-matched-uptime.txt
echo | $O s_client -connect 127.0.0.1:4443 -servername pqc-gw.local -verifyCAfile $P/pqc/ca-chain.crt -no-CAfile -cert $P/pqc/client.crt -key $P/pqc/client.key -groups X25519MLKEM768 2>&1 | grep -E "group:|Peer signature type|Verification" > $C/loopback-matched-proof.txt
