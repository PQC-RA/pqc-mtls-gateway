#!/bin/bash
# Client matrix, run from containers on the gateway host against the live gateway (8443 enrol port: server verification; 443: full mTLS).
C=/root/talk-campaign-20261104/clients; GW=203.0.113.99; cd $C
echo -e "client\ttest\tresult"
run() { # name port-label image cmd...
  :
}
for img in node:22-bookworm-slim; do
  for spec in "8443 " "443 /c/leaf.pem /c/leaf.key"; do set -- $spec; p=$1; sh=""
    r=$(docker run --rm --network host -v $C:/c:ro $img node /c/t.js $GW $p /c/ca-chain.crt $2 $3 2>&1 | tail -1)
    echo -e "$img\t$p$([ -n "$2" ] && echo -mTLS)\t$r"; done; done
for img in python:3.12-slim python:3.11-slim-bookworm python:3.9-slim-bullseye; do
  for spec in "8443 " "443 /c/leaf.pem /c/leaf.key"; do set -- $spec; p=$1
    r=$(docker run --rm --network host -v $C:/c:ro $img python3 /c/t.py $GW $p /c/ca-chain.crt $2 $3 2>&1 | tail -1)
    echo -e "$img\t$p$([ -n "$2" ] && echo -mTLS)\t$r"; done; done
for img in curlimages/curl:latest; do
  r=$(docker run --rm --network host -v $C:/c:ro $img sh -c "curl -s --cacert /c/ca-chain.crt -o /dev/null -w '%{http_code}' https://$GW:8443/ -k; echo; curl --version | head -1" 2>&1 | tr '\n' ' ')
  echo -e "$img\t8443(-k)\t$r"
  r=$(docker run --rm --network host -v $C:/c:ro $img sh -c "curl -s --cacert /c/ca-chain.crt --cert /c/leaf.pem --key /c/leaf.key -o /dev/null -w '%{http_code}' --resolve pqc-gw.local:443:$GW https://pqc-gw.local/" 2>&1 | tail -1)
  echo -e "$img\t443-mTLS\t$r"
done
for img in eclipse-temurin:21-jre eclipse-temurin:21-jdk; do
  for p in 8443 443; do
    r=$(docker run --rm --network host -v $C:/c:ro $img java /c/T.java $GW $p 2>&1 | tail -1)
    echo -e "$img\t$p\t$r"; done; done
echo "--- gateway handshake refusal reasons (last 15 min)"; docker logs --since 15m pqc-gateway 2>&1 | grep -oE "reason=[a-z_]+ offered_groups=[A-Za-z0-9,]+" | sort | uniq -c
