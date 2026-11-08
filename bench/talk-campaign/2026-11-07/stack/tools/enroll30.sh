#!/usr/bin/env bash
# enroll30.sh [N]: N devices enrolled one after another against the throwaway stack rs1107,
# client on the stand itself, no added delay. Per device:
#   admin   one CN-locked, single-use token over the normal admin path (mTLS :443, admin cert,
#           X-PQC-CSRF), profile client-30d, ttl 600 s. The token is never printed or stored.
#   device  its own ML-DSA-65 key (openssl genpkey) and CSR (openssl req), then POST /enroll on
#           the post-quantum-only enrollment port (:8443 in the container, 38443 here) with curl.
# Clock: bash $EPOCHREALTIME (no process started to read it). key_ms and csr_ms are the wall
# time of one openssl process each, its start-up included. The request is curl's own timers.
# Pacing: /enroll is rate limited in the shipped nginx.conf (zone pqc_enroll, 5 r/m per address,
# burst 3, 429 beyond), so consecutive POSTs are started at least PACE s apart (default 13).
# START resumes a series at device START (rows are appended).
# Writes results/enroll/enroll.tsv; device keys stay in devices/ (deleted at teardown).
set -euo pipefail
D=/root/rerun-stack-20261107; R=$D/repo; N=${1:-30}
OUT=${OUT:-$D/results/enroll}; DEV=$D/devices; PFX=${PFX:-rs1107-dev}; mkdir -p "$OUT" "$DEV"; chmod 700 "$DEV"
O=/opt/openssl/bin/openssl; CURL=/usr/bin/curl
export OPENSSL_CONF=/etc/ssl/openssl.cnf   # the /opt build has no readable default config (see gen-enroll-classical-cert.sh)
CHAIN=$D/host/var-lib-pqc-ca-public/ca-chain.crt
ADM_C=$R/admin-cert/gateway-admin.crt; ADM_K=$R/admin-cert/gateway-admin.key
GW=https://127.0.0.1:39443; EN=https://127.0.0.1:38443/enroll; PROFILE=client-30d
W='%{http_code}\t%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_pretransfer}\t%{time_starttransfer}\t%{time_total}\t%{size_upload}\t%{size_download}'
TSV=$OUT/enroll.tsv; START=${START:-1}; PACE=${PACE:-13}; next_at=0
[ "$START" -gt 1 ] || printf 'i\tcn\tserial\tder_bytes\ttoken_http\ttoken_total_s\tkey_ms\tcsr_ms\tenroll_http\tnamelookup_s\tconnect_s\tappconnect_s\tpretransfer_s\tstarttransfer_s\ttotal_s\tupload_bytes\tdownload_bytes\tcurl_start_unix\tcurl_end_unix\n' > "$TSV"
ms(){ python3 -I -c 'import sys;print(f"{(float(sys.argv[2])-float(sys.argv[1]))*1e3:.2f}")' "$1" "$2"; }
for i in $(seq -w "$START" "$N"); do
  python3 -I -c 'import sys,time;time.sleep(max(0.0,float(sys.argv[1])-time.time()))' "$next_at"
  CN=$PFX-$i; d=$DEV/$CN; mkdir -p "$d"; umask 077
  cp "$CHAIN" "$d/ca-chain.crt"
  # admin side
  tok_meta=$($CURL -sS --cacert "$CHAIN" --cert "$ADM_C" --key "$ADM_K" -H 'X-PQC-CSRF: 1' -X POST \
    "$GW/admin/certs/enrollment-tokens?cn=$CN&ttl=600&profile=$PROFILE" -o "$d/.tok.json" -w '%{http_code}\t%{time_total}')
  [ "$(cut -f1 <<<"$tok_meta")" = 201 ] || [ "$(cut -f1 <<<"$tok_meta")" = 200 ] || { echo "token $CN: HTTP $tok_meta" >&2; exit 1; }
  # device side
  t0=$EPOCHREALTIME; $O genpkey -algorithm ML-DSA-65 -out "$d/client.key"
  t1=$EPOCHREALTIME; $O req -new -key "$d/client.key" -subj "/CN=$CN" -out "$d/client.csr"
  t2=$EPOCHREALTIME
  python3 -I -c 'import json,sys
tok=json.load(open(sys.argv[1]))["token"]
open(sys.argv[3],"w").write(json.dumps({"csr":open(sys.argv[2]).read(),"enrollmentToken":tok}))' "$d/.tok.json" "$d/client.csr" "$d/.body.json"
  rm -f "$d/.tok.json"
  cs=$EPOCHREALTIME
  meta=$($CURL -sS --cacert "$d/ca-chain.crt" -X POST "$EN" -H 'Content-Type: application/json' \
    --data-binary @"$d/.body.json" -o "$d/enroll-resp.json" -w "$W")
  ce=$EPOCHREALTIME; next_at=$(python3 -I -c 'import sys;print(float(sys.argv[1])+float(sys.argv[2]))' "$cs" "$PACE")
  rm -f "$d/.body.json"
  [ "$(cut -f1 <<<"$meta")" = 201 ] || { echo "enroll $CN failed: HTTP $(cut -f1 <<<"$meta") $(head -c 300 "$d/enroll-resp.json")" >&2; exit 1; }
  python3 -I -c 'import json,sys;open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$d/enroll-resp.json" "$d/client.crt"
  $O verify -CAfile "$d/ca-chain.crt" "$d/client.crt" >/dev/null
  serial=$($O x509 -in "$d/client.crt" -noout -serial | cut -d= -f2)
  der=$($O x509 -in "$d/client.crt" -outform DER | wc -c)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$CN" "$serial" "$der" "$tok_meta" \
    "$(ms "$t0" "$t1")" "$(ms "$t1" "$t2")" "$meta" "$cs" "$ce" >> "$TSV"
  tail -1 "$TSV"
done
echo "enrolled $N into $TSV"
