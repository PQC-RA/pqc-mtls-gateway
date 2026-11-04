#!/bin/bash
# matched arms (bench/pki/pqc ML-DSA-65 vs bench/pki/classical ECDSA P-256), mTLS, on 0.0.0.0 so the VPN device can use them too.
C=/root/talk-campaign-20261104; P=$C/bench/pki; O=/opt/openssl/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
pkill -f "s_server -accept 444[34]" 2>/dev/null; sleep 0.5
start() { nohup $O s_server -accept $1 -www -tls1_3 -no_ticket -no_cache -cert $P/$2/server.crt -key $P/$2/server.key -Verify 2 -verifyCAfile $P/$2/ca-chain.crt -no-CAfile -groups $3 > $C/arm-$1.log 2>&1 & }
start 4443 pqc X25519MLKEM768; start 4444 classical X25519; sleep 1.5
ip link set dev lo mtu 1500
printf "arm\trep\tread\twritten\ttotal\tcerts_from_server\tgroup\tpeer_sig\n" > $C/matched-bytes.tsv
for rep in 1 2 3; do for spec in "pqc 4443 X25519MLKEM768" "classical 4444 X25519"; do set -- $spec
  out=$(echo | $O s_client -connect 127.0.0.1:$2 -servername pqc-gw.local -groups $3 -verifyCAfile $P/$1/ca-chain.crt -no-CAfile -cert $P/$1/client.crt -key $P/$1/client.key 2>&1)
  rd=$(grep -oE "read [0-9]+ bytes" <<<"$out"|awk "{print \$2}"); wr=$(grep -oE "written [0-9]+ bytes" <<<"$out"|awk "{print \$2}")
  g=$(grep -oE "group: .*" <<<"$out"|awk "{print \$NF}"); ps=$(grep "Peer signature type" <<<"$out"|awk "{print \$NF}"); nc=$(grep -cE "^ [0-9] s:" <<<"$out")
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" $1 $rep $rd $wr $((rd+wr)) $nc "$g" "$ps" >> $C/matched-bytes.tsv
done; done
ip link set dev lo mtu 65536
cat $C/matched-bytes.tsv
echo "--- CPU, s_time, matched arms (client side, 3 x 10 s)"
for spec in "classical 4444" "pqc 4443"; do set -- $spec; sum=0
  for w in 1 2 3; do u=$($O s_time -connect 127.0.0.1:$2 -new -time 10 -cert $P/$1/client.crt -key $P/$1/client.key -CAfile $P/$1/ca-chain.crt 2>/dev/null | grep -oE "[0-9.]+ connections/user sec" | awk "{print \$1}"); echo "$1 window $w: $u conn/user-s = $(echo "1000/$u"|bc -l|cut -c1-6) ms CPU/HS"; sum=$(echo "$sum+$u"|bc -l); done
  echo "$1 MEAN $(echo "1000/($sum/3)"|bc -l|cut -c1-6) ms CPU/HS"
done
