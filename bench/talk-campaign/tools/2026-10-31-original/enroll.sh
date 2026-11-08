#!/usr/bin/env bash
# enroll.sh CN PROFILE OUTDIR
# Admin side (on the gateway host, over SSH): one CN-locked, single-use token.
# Device side (this Mac, over the VPN): own ML-DSA-65 key, CSR, POST to :8443/enroll.
# Writes OUTDIR/{client.key,client.crt,ca-chain.crt,enroll.tsv}. The token is never printed.
set -euo pipefail
CN=$1 PROFILE=$2 OUT=$3
GW=${GW:-203.0.113.99}
O=${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}
CURL=${CURL:-/opt/homebrew/opt/curl/bin/curl}
CHAIN=${CHAIN:-$(dirname "$0")/../2026-10-31/device/ca-chain.crt}
mkdir -p "$OUT"; cp "$CHAIN" "$OUT/ca-chain.crt"; umask 077
now() { python3 -I -c 'import time;print(f"{time.time():.6f}")'; }

TOKEN=$(ssh -o BatchMode=yes root@$GW "cd /root/pqc-gw-live && curl -sS --cacert /etc/pki/pqc-ca/ca-chain.crt \
  --cert admin-cert/gateway-admin.crt --key admin-cert/gateway-admin.key -H X-PQC-CSRF:1 -X POST \
  'https://127.0.0.1/admin/certs/enrollment-tokens?cn=$CN&ttl=600&profile=$PROFILE'" \
  | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["token"])')

t0=$(now); $O genpkey -algorithm ML-DSA-65 -out "$OUT/client.key"
t1=$(now); $O req -new -key "$OUT/client.key" -subj "/CN=$CN" -out "$OUT/client.csr"
t2=$(now)
CSR_FILE="$OUT/client.csr" T="$TOKEN" python3 -I -c 'import json,os
print(json.dumps({"csr":open(os.environ["CSR_FILE"]).read(),"enrollmentToken":os.environ["T"]}))' > "$OUT/.body.json"
meta=$($CURL -sS --cacert "$OUT/ca-chain.crt" -X POST "https://$GW:8443/enroll" -H "Content-Type: application/json" \
  --data-binary @"$OUT/.body.json" -o "$OUT/enroll-resp.json" -w '%{http_code}\t%{time_appconnect}\t%{time_total}')
t3=$(now); rm -f "$OUT/.body.json"
code=$(cut -f1 <<<"$meta")
[ "$code" = 201 ] || { echo "enroll $CN failed: HTTP $code $(head -c 300 "$OUT/enroll-resp.json")" >&2; exit 1; }
python3 -I -c 'import json,sys;open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$OUT/enroll-resp.json" "$OUT/client.crt"
$O verify -CAfile "$OUT/ca-chain.crt" "$OUT/client.crt" >/dev/null
serial=$($O x509 -in "$OUT/client.crt" -noout -serial | cut -d= -f2)
der=$($O x509 -in "$OUT/client.crt" -outform DER | wc -c | tr -d ' ')
printf 'cn\tprofile\tserial\tder_bytes\tkeygen_ms\tcsr_ms\tenroll_http\tappconnect_s\tenroll_total_s\twall_ms\n' > "$OUT/enroll.tsv"
python3 -I -c 'import sys;a=sys.argv;t0,t1,t2,t3=map(float,a[7:11])
print("\t".join(a[1:5]+[f"{(t1-t0)*1e3:.1f}",f"{(t2-t1)*1e3:.1f}"]+a[5].split("\t")+[f"{(t3-t2)*1e3:.1f}"]))' \
  "$CN" "$PROFILE" "$serial" "$der" "$meta" x "$t0" "$t1" "$t2" "$t3" >> "$OUT/enroll.tsv"
tail -1 "$OUT/enroll.tsv"
