#!/bin/bash
# one request every 3 s with the CURRENT identity; log utc, http, serial, appconnect
D=$1; OUT=$2; N=$3; C=/opt/homebrew/opt/curl/bin/curl; O=/opt/homebrew/opt/openssl@3/bin/openssl
printf 'utc\thttp\tserial_presented\tappconnect_s\n' > $OUT
for i in $(seq 1 $N); do
  s=$($O x509 -in $D/client.crt -noout -serial | cut -d= -f2)
  r=$($C -s -o /dev/null -w '%{http_code}\t%{time_appconnect}' --max-time 8 --curves X25519MLKEM768 --cacert $D/ca-chain.crt --cert $D/identity.pem --resolve pqc-gw.local:443:192.168.1.99 https://pqc-gw.local/)
  printf '%s\t%s\t%s\n' "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$(cut -f1 <<<"$r")" "$s	$(cut -f2 <<<"$r")" >> $OUT
  sleep 3
done
