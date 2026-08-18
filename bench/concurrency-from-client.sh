#!/bin/bash
# Concurrency sweep run from a separate client machine against the gateway, so
# the load generator's own crypto CPU does not compete with the gateway's.
# Set GW_HOST to the gateway address and EXPORT_DIR to the directory holding
# the bench client certificate and CA chain.
CURL=/opt/curl-pqc/bin/curl
E=${EXPORT_DIR:?set EXPORT_DIR to the bench client certificate directory}
URL=https://${GW_HOST:?set GW_HOST to the gateway address}/api/v1/status
REQS=${1:-200}
echo "| concurrency | requests | HTTP 200 | success | mean HS ms | p95 HS ms |"
echo "|------------:|---------:|---------:|--------:|-----------:|----------:|"
for C in 1 10 20 30 50; do
  T=$(mktemp -d)
  seq 1 $REQS | xargs -P $C -I{} sh -c \
    "$CURL -s -o /dev/null -w '%{http_code} %{time_appconnect} %{time_connect}\n' \
      --cert $E/client.crt --key $E/client.key --cacert $E/ca-chain.crt '$URL' >> $T/r.txt 2>/dev/null"
  ok=$(awk '$1==200' $T/r.txt | wc -l); tot=$(wc -l < $T/r.txt)
  read m p <<<$(awk '$1==200 && $2>0 {v[n++]=($2-$3)*1000; s+=($2-$3)*1000}
    END{if(n==0){print "- -";exit} asort(v); m=s/n; k=int((n-1)*0.95); printf "%.3f %.3f", m, v[k+1]}' $T/r.txt 2>/dev/null)
  [ -z "$m" ] && read m p <<<$(awk '$1==200 && $2>0 {a[n++]=($2-$3)*1000; s+=($2-$3)*1000}
    END{if(n==0){print "- -";exit}
        for(i=0;i<n;i++)for(j=i+1;j<n;j++)if(a[j]<a[i]){t=a[i];a[i]=a[j];a[j]=t}
        printf "%.3f %.3f", s/n, a[int((n-1)*0.95)]}' $T/r.txt)
  pct=$(awk -v o=$ok -v t=$tot 'BEGIN{if(t)printf "%.1f%%",100*o/t; else print "-"}')
  printf "| %11s | %8s | %8s | %7s | %10s | %9s |\n" "$C" "$tot" "$ok" "$pct" "$m" "$p"
  rm -rf $T; sleep 2
done
