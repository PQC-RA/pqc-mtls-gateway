#!/usr/bin/env bash
# Issuance-side negative controls against the LIVE CA, driven from the device side (this Mac, over the VPN).
# 13 s between enrollment POSTs: the gateway allows 5 per minute per IP (pqc_enroll 5r/m).
# Every certificate issued here is revoked at the end.
set -uo pipefail
OUT=$1; mkdir -p "$OUT"; cd "$OUT"; umask 077
GW=192.168.1.99; O=/opt/homebrew/opt/openssl@3/bin/openssl; CURL=/opt/homebrew/opt/curl/bin/curl
CHAIN=$(dirname "$0")/../2026-10-31/device/ca-chain.crt; cp "$CHAIN" ca-chain.crt
ADM="cd /root/pqc-gw-live && curl -sS --cacert /etc/pki/pqc-ca/ca-chain.crt --cert admin-cert/gateway-admin.crt --key admin-cert/gateway-admin.key -H X-PQC-CSRF:1"
token() { ssh -o BatchMode=yes root@$GW "$ADM -X POST 'https://127.0.0.1/admin/certs/enrollment-tokens?cn=$1&ttl=600&profile=client-30d'" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["token"])'; }
enroll() { # enroll CSRFILE TOKEN TAG -> prints http code, saves body
  CSR_FILE=$1 T=$2 python3 -I -c 'import json,os;print(json.dumps({"csr":open(os.environ["CSR_FILE"]).read(),"enrollmentToken":os.environ["T"]}))' > .b.json
  $CURL -sS --cacert ca-chain.crt -X POST "https://$GW:8443/enroll" -H 'Content-Type: application/json' --data-binary @.b.json -o "resp-$3.json" -w '%{http_code}'; rm -f .b.json; }
echo -e "test\texpect\thttp\tdetail" > results.tsv

# 1. classical key, valid token -> refused before the token is spent
T1=$(token talk-neg-1)
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key; $O req -new -key ec.key -subj /CN=talk-neg-1 -out ec.csr
c=$(enroll ec.csr "$T1" 1a); echo -e "1a ECDSA P-256 CSR\t400\t$c\t$(head -c 160 resp-1a.json)" >> results.tsv; sleep 13
$O genpkey -algorithm ML-DSA-65 -out neg1.key; $O req -new -key neg1.key -subj /CN=talk-neg-1 -out neg1.csr
c=$(enroll neg1.csr "$T1" 1b); echo -e "1b same token, ML-DSA-65 CSR\t201\t$c\ttoken was not consumed by 1a" >> results.tsv; sleep 13

# 2. ML-DSA-65 CSR that asks for a CA, every EKU and the gateway's own name
T2=$(token talk-neg-2)
$O genpkey -algorithm ML-DSA-65 -out neg2.key
cat > hostile.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = talk-neg-2
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
extendedKeyUsage = anyExtendedKeyUsage,serverAuth,clientAuth,OCSPSigning
subjectAltName = DNS:pqc-gw.local
EOF
$O req -new -key neg2.key -config hostile.cnf -out neg2.csr
$O req -in neg2.csr -noout -text | grep -A1 -E "Basic Constraints|Key Usage|Subject Alternative" > neg2-csr-requested.txt
c=$(enroll neg2.csr "$T2" 2); echo -e "2 hostile ML-DSA-65 CSR\t201 minimal profile\t$c\t" >> results.tsv
[ "$c" = 201 ] && python3 -I -c 'import json;print(json.load(open("resp-2.json"))["certificate"])' | awk '/BEGIN CERT/,/END CERT/' > neg2.crt && \
  $O x509 -in neg2.crt -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName > neg2-issued-extensions.txt 2>&1
sleep 13

# 3. CN mismatch -> 403 and the token survives
T3=$(token talk-neg-3)
$O genpkey -algorithm ML-DSA-65 -out neg3.key
$O req -new -key neg3.key -subj /CN=talk-neg-3-impostor -out neg3bad.csr; $O req -new -key neg3.key -subj /CN=talk-neg-3 -out neg3.csr
c=$(enroll neg3bad.csr "$T3" 3a); echo -e "3a CSR CN differs from token CN\t403\t$c\t$(head -c 120 resp-3a.json)" >> results.tsv; sleep 13
c=$(enroll neg3.csr "$T3" 3b); echo -e "3b same token, matching CN\t201\t$c\ttoken was not consumed by 3a" >> results.tsv

# cleanup: revoke what was issued
for r in resp-1b.json resp-2.json resp-3b.json; do
  s=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("serialNumber",""))' "$r" 2>/dev/null)
  [ -n "$s" ] && ssh -o BatchMode=yes root@$GW "$ADM -H 'Content-Type: application/json' -X POST https://127.0.0.1/admin/certs/revoke -d '{\"serial\":\"$s\",\"reason\":\"cessationOfOperation\"}'" >> cleanup-revoke.log && echo >> cleanup-revoke.log
done
column -t -s $'\t' results.tsv; echo; cat neg2-csr-requested.txt; echo "--- issued:"; cat neg2-issued-extensions.txt; echo; cat cleanup-revoke.log
