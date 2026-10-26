#!/usr/bin/env bash
# concurrency-repeat-stand.sh: the two renewal races of e2e-renew-stand-2.sh
# (cases C and D) repeated N times each on the ISOLATED stand, with the start
# and end of every request logged in milliseconds so the overlap is shown, not
# assumed (independent check 2026-10-25, gap: "n=1, overlap not shown").
#
#   C  two renewals of one certificate with the SAME new key, sent together:
#      both 201 with one and the same successor
#   D  two renewals of one certificate with DIFFERENT new keys, sent together:
#      one 201 and one 409 renewal_conflict; the predecessor revoked keyCompromise
#   E  a renewal and a bootstrap enrollment (new token) for the same CN, sent
#      together: exactly one new certificate for the CN
#
# Both request bodies are built first; then both curls start together.
# Usage: concurrency-repeat-stand.sh WORKDIR [N]
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stand-env.sh"
W=${1:?workdir}; N=${2:-10}; mkdir -p "$W"
HERE=$(cd "$(dirname "$0")" && pwd)
die(){ echo "GUARD ABORT: $*"; exit 90; }
pass=0 fail=0
check(){ if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

stand_guard "$W"

TS=$(date -u +%H%M%S)
serial_of(){ $O x509 -in "$1" -noout -serial | cut -d= -f2; }
token(){ # token CN [PROFILE]
	local q="cn=$1&ttl=300"; [ -n "${2:-}" ] && q="$q&profile=$2"
	curl -sS "${RES[@]}" --cacert $CA --cert $ADM_C --key $ADM_K -H X-PQC-CSRF:1 --max-time 15 -X POST "$ADMIN/admin/certs/enrollment-tokens?$q" \
		| python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")' 2>/dev/null
}
enroll_with(){ # enroll_with TOKEN DIR -> HTTP code; client.crt on 201
	local t=$1 d=$2 cn body
	cn=$(sed -n 's#.*/CN=\([^/]*\).*#\1#p' "$d/subject")
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$d/enroll.key" -out "$d/enroll.csr" -subj "$(cat "$d/subject")" 2>/dev/null
	body=$(CSR_FILE="$d/enroll.csr" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	curl -sS "${RES[@]}" --cacert $CA --max-time 20 -X POST "$ENROLL" -H 'Content-Type: application/json' -d "$body" -o "$d/enroll.json" -w '%{http_code}'
}
bootstrap(){ # bootstrap CN PROFILE DIR
	mkdir -p "$3"; cp $CA "$3/ca-chain.crt"; echo "/C=BG/O=ACME/OU=M2M-Client/CN=$1" > "$3/subject"
	local t; t=$(token "$1" "$2"); [ -n "$t" ] || return 1
	[ "$(enroll_with "$t" "$3")" = 201 ] || return 1
	python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$3/enroll.json" "$3/client.crt"
	mv "$3/enroll.key" "$3/client.key"
}
# raw_renew DIR NEWKEY OUTPREFIX: one /renew request signed by DIR's current key for NEWKEY.
raw_renew(){
	local d=$1 nk=$2 out=$3 serial ts h
	OPENSSL_CONF=/dev/null $O req -new -key "$nk" -subj "$(cat "$d/subject")" -out "$out.csr" 2>/dev/null
	serial=$(serial_of "$d/client.crt"); ts=$(date -u +%s)
	h=$($O req -in "$out.csr" -outform DER | $O dgst -sha256 -r | cut -d' ' -f1)
	printf 'pqc-renew-v1\n%s\n%s\n%s' "$h" "$serial" "$ts" > "$out.msg"
	$O pkeyutl -sign -inkey "$d/client.key" -rawin -in "$out.msg" -out "$out.sig"
	CSR_FILE="$out.csr" SIG="$out.sig" TS=$ts python3 -I -c 'import base64,json,os; print(json.dumps({"csr":open(os.environ["CSR_FILE"]).read(),"pop":{"timestamp":int(os.environ["TS"]),"signature":base64.b64encode(open(os.environ["SIG"],"rb").read()).decode()}}))' > "$out.body"
	curl -sS "${RES[@]}" --cacert $CA --cert "$d/client.crt" --key "$d/client.key" --max-time 30 -H 'Content-Type: application/json' \
		--data-binary @"$out.body" -o "$out.json" -w '%{http_code}' -X POST "$URL/renew" > "$out.code" || echo 000 > "$out.code"
}
resp_serial(){ python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("serialNumber",""))' "$1" 2>/dev/null; }
wait_open(){ # wait until renewal opens (half the lifetime after the real issue time)
	local nb na; nb=$(date -u -d "$($O x509 -in "$1/client.crt" -noout -startdate | cut -d= -f2)" +%s); na=$(date -u -d "$($O x509 -in "$1/client.crt" -noout -enddate | cut -d= -f2)" +%s)
	local open=$(( nb + 60 + (na - nb - 60) / 2 + 2 )); local now; now=$(date -u +%s)
	[ "$now" -lt "$open" ] && sleep $(( open - now )); return 0
}
CLIENT=(bash "$HERE/renew-client.sh" --url $URL --resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1)
gen_key(){ $O genpkey -algorithm ML-DSA-65 -out "$1" 2>/dev/null; }
LAST=0; pace(){ local w=$(( LAST + 20 - $(date +%s) ));   # 20 s: E adds an enrollment per iteration
 [ $w -gt 0 ] && sleep $w; LAST=$(date +%s); }
prep(){ # prep DIR NEWKEY OUT: build the signed /renew body
	local d=$1 nk=$2 out=$3 serial ts h
	OPENSSL_CONF=/dev/null $O req -new -key "$nk" -subj "$(cat "$d/subject")" -out "$out.csr" 2>/dev/null
	serial=$(serial_of "$d/client.crt"); ts=$(date -u +%s)
	h=$($O req -in "$out.csr" -outform DER | $O dgst -sha256 -r | cut -d' ' -f1)
	printf 'pqc-renew-v1\n%s\n%s\n%s' "$h" "$serial" "$ts" > "$out.msg"
	$O pkeyutl -sign -inkey "$d/client.key" -rawin -in "$out.msg" -out "$out.sig"
	CSR_FILE="$out.csr" SIG="$out.sig" TS=$ts python3 -I -c 'import base64,json,os; print(json.dumps({"csr":open(os.environ["CSR_FILE"]).read(),"pop":{"timestamp":int(os.environ["TS"]),"signature":base64.b64encode(open(os.environ["SIG"],"rb").read()).decode()}}))' > "$out.body"
}
fire(){ # fire DIR OUT: send a prepared body, log start and end in ms
	local d=$1 out=$2 s e
	s=$(date +%s%3N)
	curl -sS "${RES[@]}" --cacert $CA --cert "$d/client.crt" --key "$d/client.key" --max-time 30 -H 'Content-Type: application/json' \
		--data-binary @"$out.body" -o "$out.json" -w '%{http_code}' -X POST "$URL/renew" > "$out.code" 2>/dev/null || echo 000 > "$out.code"
	e=$(date +%s%3N); echo "$s $e" > "$out.t"
}
fire_enroll(){ # fire_enroll DIR OUT TOKEN: a bootstrap enrollment for DIR's CN, timed
	local d=$1 out=$2 t=$3 s e body
	OPENSSL_CONF=/dev/null $O req -new -newkey ML-DSA-65 -nodes -keyout "$out.key" -out "$out.csr" -subj "$(cat "$d/subject")" 2>/dev/null
	body=$(CSR_FILE="$out.csr" TOKEN=$t python3 -I -c 'import json,os; print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(), "enrollmentToken": os.environ["TOKEN"]}))')
	echo "$body" > "$out.body"; s=$(date +%s%3N)
	curl -sS "${RES[@]}" --cacert $CA --max-time 30 -X POST "$ENROLL" -H 'Content-Type: application/json' --data-binary @"$out.body" -o "$out.json" -w '%{http_code}' > "$out.code" 2>/dev/null || echo 000 > "$out.code"
	e=$(date +%s%3N); echo "$s $e" > "$out.t"
}
race(){ # race KIND DIR: wait for the window, then fire the pair together
	local k=$1 d=$2
	wait_open "$d"
	if [ "$k" = C ]; then gen_key "$d/nk.key"; prep "$d" "$d/nk.key" "$d/r1"; prep "$d" "$d/nk.key" "$d/r2"
	elif [ "$k" = D ]; then gen_key "$d/k1.key"; gen_key "$d/k2.key"; prep "$d" "$d/k1.key" "$d/r1"; prep "$d" "$d/k2.key" "$d/r2"
	else gen_key "$d/k1.key"; prep "$d" "$d/k1.key" "$d/r1"; awk -F'\t' -v cn="CN=$(sed -n 's#.*/CN=##p' "$d/subject")" '$6 ~ cn"$"' "$IDX" | wc -l > "$d/rows0"
		fire "$d" "$d/r1" & fire_enroll "$d" "$d/r2" "$(cat "$d/etoken")" & wait; return; fi
	fire "$d" "$d/r1" & fire "$d" "$d/r2" & wait
}
for i in $(seq -w 1 "$N"); do
	for k in C D E; do
		d="$W/$k$i"; pace; bootstrap "cc-$k$i-$TS" demo-120s "$d" || { echo "bootstrap $k$i failed"; continue; }
		serial_of "$d/client.crt" > "$d/pred"
		[ "$k" = E ] && token "cc-$k$i-$TS" demo-120s > "$d/etoken"
		race "$k" "$d" &
	done
done
wait; sleep 3
python3 -I - "$W" "$N" "$DB/index.txt" <<'PY'
import json, os, sys
W, N, idx = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rows = [l.rstrip("\n").split("\t") for l in open(idx)]
def rd(p):
    try: return open(p).read().strip()
    except OSError: return ""
def js(p):
    try: return json.load(open(p))
    except Exception: return {}
res = {"C": [0, 0, 0], "D": [0, 0, 0], "E": [0, 0, 0]}   # runs, passed, overlapped
for k in "CDE":
    for i in range(1, N + 1):
        d = f"{W}/{k}{i:0{len(str(N))}d}"
        if not os.path.exists(f"{d}/r1.t"): print(f"   {k}{i}: not run"); continue
        res[k][0] += 1
        c1, c2 = rd(f"{d}/r1.code"), rd(f"{d}/r2.code")
        (s1, e1), (s2, e2) = [map(int, rd(f"{d}/{r}.t").split()) for r in ("r1", "r2")]
        ov = max(s1, s2) < min(e1, e2); res[k][2] += ov
        j1, j2 = js(f"{d}/r1.json"), js(f"{d}/r2.json")
        if k == "C":
            ok = c1 == c2 == "201" and j1.get("serialNumber") and j1.get("serialNumber") == j2.get("serialNumber")
        elif k == "E":
            cn = open(f"{d}/subject").read().strip().split("CN=")[-1]
            now_rows = sum(1 for r in rows if len(r) > 5 and r[5].endswith("CN=" + cn))
            ok = now_rows - int(rd(f"{d}/rows0") or 0) == 1 and "201" in (c1, c2)
        else:
            pred = rd(f"{d}/pred")
            win = (j1 if c1 == "201" else j2).get("serialNumber", "")
            rev = lambda ser: any(r[0] == "R" and r[3] == ser and "keyCompromise" in r[2] for r in rows)
            revoked = rev(pred) and bool(win) and rev(win)   # both the predecessor and the 201 winner
            conflict = "renewal_conflict" in json.dumps(j1) + json.dumps(j2)
            ok = sorted([c1, c2]) == ["201", "409"] and conflict and revoked
        res[k][1] += bool(ok)
        print(f"   {k}{i}: {c1} {c2} start gap {abs(s1 - s2)} ms, overlap {'yes' if ov else 'NO'}, durations {e1 - s1}/{e2 - s2} ms -> {'PASS' if ok else 'FAIL'}")
for k, (n, p, o) in res.items():
    print(f"== {k}: {p} of {n} passed, {o} of {n} overlapped")
ok = all(p == n == o and n == N for n, p, o in res.values())
print("== result:", "all passed" if ok else "FAILED")
sys.exit(0 if ok else 1)
PY
