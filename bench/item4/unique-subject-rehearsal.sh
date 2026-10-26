#!/usr/bin/env bash
# unique-subject-rehearsal.sh: ADR-019 decision 7, the live-index rehearsal of
# stage 2's unique_subject switch and its rollback, on a SCRATCH CA.
#
# The scratch CA signs with the stand's throwaway intermediate key and holds a
# read-only COPY of the live index, index.txt.attr, serial and crlnumber, so
# -updatedb, the duplicate check and both switches run on live's real rows.
# Nothing is written under /etc/pki/pqc-ca; the live files are hashed before
# and after.
#
#   1. live state as copied (unique_subject = yes): -gencrl works; check
#   2. set-no (stage 2)
#   3. stage-2 rows: two valid leaves and one already expired leaf, one subject
#   4. check reports the duplicate; set-yes is REFUSED and leaves no in place
#   5. the hazard set-yes prevents, on a second copy: attr forced to yes by hand,
#      then -updatedb, -gencrl and -revoke all fail
#   6. one leaf revoked, the expired one marked E by -updatedb: check reports
#      none; set-yes succeeds (rollback stage 2 to stage 1); -gencrl works
#   0, 5b, 7 (added after the independent review): the tool refuses without the
#      stage-1 lock file; set-no repairs the broken state of step 5; the set-yes
#      rollback branch (a forced -updatedb failure after the switch) restores no
#      and keeps the pre-run backups. db/ is owned by 1001 as on live; the files
#      must stay readable and lockable by uid 1001 after every tool step.
#
# Usage: unique-subject-rehearsal.sh WORKDIR
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/lib" && pwd)/pq-openssl.sh"; export OPENSSL=$O
W=${1:?workdir}; HERE=$(cd "$(dirname "$0")" && pwd); TOOL="$HERE/../../scripts/ca-unique-subject.sh"
LIVE=/etc/pki/pqc-ca/intermediate; STAND=${STAND_DIR:?source STAND_DIR/stand.env first}/pki/intermediate
[ -e "$W" ] && { echo "$W exists"; exit 2; }
fail=0; step() { printf '\n== %s\n' "$*"; }
ok() { echo "PASS: $*"; }; bad() { echo "FAIL: $*"; fail=$((fail+1)); }
livehash() { sha256sum $LIVE/db/index.txt $LIVE/db/index.txt.attr $LIVE/db/serial $LIVE/db/crlnumber $LIVE/openssl-intermediate.cnf | cut -c1-16 | tr '\n' ' '; }
L0=$(livehash)

mkca() { # mkca DIR: scratch CA = stand key and certificate + copy of the live db
	local s=$1; mkdir -p "$s"/{certs,private,db,issued,crl}; chmod 700 "$s/private"
	cp $STAND/certs/intermediate-ca.crt "$s/certs/"; cp $STAND/private/intermediate-ca.key "$s/private/"
	cp $LIVE/db/index.txt $LIVE/db/index.txt.attr $LIVE/db/serial $LIVE/db/crlnumber "$s/db/"
	chown 1001:1001 "$s/db" "$s/db/index.txt" "$s/db/index.txt.attr" "$s/db/serial"; chmod 775 "$s/db"   # as live
	sed -e "s#^dir[[:space:]]*=.*#dir               = $s#" \
	    -e 's|^unique_subject[[:space:]]*=.*|unique_subject    = yes               # as live|' \
	    $STAND/openssl-intermediate.cnf > "$s/openssl-intermediate.cnf"
}
S="$W/scratch"; mkca "$S"; C="$S/openssl-intermediate.cnf"
echo "scratch CA $S; live index copied: $(wc -l < "$S/db/index.txt") rows, attr: $(cat "$S/db/index.txt.attr")"
cmp -s $STAND/certs/intermediate-ca.crt "$S/certs/intermediate-ca.crt" && ! cmp -s $LIVE/certs/intermediate-ca.crt "$S/certs/intermediate-ca.crt" \
	&& ok "scratch signs with the STAND key, not live's" || { bad "key check"; exit 1; }

as1001() { setpriv --reuid 1001 --regid 1001 --clear-groups "$@"; }
owned() { # owned DIR: index files owned by 1001, lockable and readable by uid 1001
	local d=$1 f bad_=""
	for f in index.txt index.txt.attr index.txt.old index.txt.attr.old; do
		[ -e "$d/db/$f" ] && [ "$(stat -c %u "$d/db/$f")" != 1001 ] && bad_="$bad_ $f"
	done
	as1001 flock -w 2 "$d/db/.ca-db.lock" cat "$d/db/index.txt" >/dev/null 2>&1 || bad_="$bad_ (uid 1001 cannot lock or read)"
	[ -z "$bad_" ] && ok "db files owned by 1001, lockable and readable by uid 1001" || bad "ownership:$bad_"
}

step "0. no stage-1 lock file: the tool refuses"
bash "$TOOL" "$C" check; rc=$?; [ "$rc" = 2 ] && [ ! -e "$S/db/.ca-db.lock" ] && ok "refused (exit 2), no lock file created" || bad "rc=$rc"
install -o 1001 -g 1001 -m 664 /dev/null "$S/db/.ca-db.lock"; echo "    lock file created as stage 1 would: 1001:1001 0664"

step "1. live state as copied, unique_subject = yes"
t0=$(date +%s%N); $O ca -config "$C" -gencrl -out "$S/crl/a.crl" 2>&1 | tail -2; rc=${PIPESTATUS[0]}; t1=$(date +%s%N)
[ "$rc" = 0 ] && ok "-gencrl on live's rows with yes ($(( (t1-t0)/1000000 )) ms)" || bad "-gencrl rc=$rc"
bash "$TOOL" "$C" check; rc=$?; [ "$rc" = 0 ] && ok "live's rows have no duplicate V subject" || bad "check rc=$rc on live's rows"

step "2. stage 2: set-no"
t0=$(date +%s%N); bash "$TOOL" "$C" set-no; rc=$?; t1=$(date +%s%N)
[ "$rc" = 0 ] && grep -q '^unique_subject = no' "$S/db/index.txt.attr" && grep -qE '^unique_subject[[:space:]]*=[[:space:]]*no' "$C" \
	&& ok "attr and cnf say no ($(( (t1-t0)/1000000 )) ms)" || bad "set-no rc=$rc"
owned "$S"

step "3. stage-2 rows for one subject: two valid leaves and one expired"
SUBJ="/C=BG/O=ACME/OU=M2M-Client/CN=us-rehearsal"
for n in a b c; do $O req -new -newkey ML-DSA-65 -nodes -keyout "$W/$n.key" -out "$W/$n.csr" -subj "$SUBJ" 2>/dev/null; done
$O ca -config "$C" -batch -notext -days 1 -in "$W/a.csr" -out "$W/a.crt" >/dev/null 2>&1; ra=$?
$O ca -config "$C" -batch -notext -days 1 -in "$W/b.csr" -out "$W/b.crt" >/dev/null 2>&1; rb=$?
$O ca -config "$C" -batch -notext -startdate "$(date -u -d '-10 min' +%Y%m%d%H%M%SZ)" -enddate "$(date -u -d '-5 min' +%Y%m%d%H%M%SZ)" -in "$W/c.csr" -out "$W/c.crt" >/dev/null 2>&1; rc3=$?
[ "$ra$rb$rc3" = 000 ] && ok "three leaves for one subject issued with no" || bad "issue rc=$ra$rb$rc3"
awk -F'\t' '$6 ~ /CN=us-rehearsal$/' "$S/db/index.txt" | cut -f1,2,4,6 | sed 's/^/    /'

step "4. check finds the duplicate; set-yes is refused"
bash "$TOOL" "$C" check; rc=$?; [ "$rc" = 1 ] && ok "check exit 1 (duplicate)" || bad "check rc=$rc"
cp -a "$S" "$W/hazard"   # step 5 starts from this state
bash "$TOOL" "$C" set-yes; rc=$?
[ "$rc" = 1 ] && grep -q '^unique_subject = no' "$S/db/index.txt.attr" && ok "set-yes refused, attr still no" || bad "set-yes rc=$rc"
awk -F'\t' '$6 ~ /CN=us-rehearsal$/ {print $1}' "$S/db/index.txt" | tr '\n' ' ' | sed 's/^/    statuses after -updatedb: /'; echo

step "5. the hazard: attr forced to yes by hand, two V rows for one subject"
H="$W/hazard"; sed -i "s#$S#$H#" "$H/openssl-intermediate.cnf"; echo "unique_subject = yes" > "$H/db/index.txt.attr"
SER_A=$($O x509 -in "$W/a.crt" -noout -serial | cut -d= -f2)
for a in "-updatedb" "-gencrl -out $H/crl/h.crl" "-revoke $W/a.crt"; do
	out=$($O ca -config "$H/openssl-intermediate.cnf" $a 2>&1); r=$?
	if [ "$r" != 0 ] && echo "$out" | grep -qi 'error creating name index'; then ok "openssl ca ${a%% *} fails on the name index (rc=$r): $(echo "$out" | grep -m1 -i 'name index')"
	else bad "openssl ca ${a%% *}: rc=$r, $(echo "$out" | tail -1 | cut -c1-120)"; fi
done

step "5b. set-no repairs that broken state"
bash "$TOOL" "$H/openssl-intermediate.cnf" set-no; rc=$?
[ "$rc" = 0 ] && grep -q '^unique_subject = no' "$H/db/index.txt.attr" && $O ca -config "$H/openssl-intermediate.cnf" -gencrl -out "$H/crl/h2.crl" >/dev/null 2>&1 \
	&& ok "set-no despite the failing -updatedb; -gencrl works again" || bad "repair rc=$rc"

step "6. rollback stage 2 to stage 1: one leaf revoked, the expired one becomes E"
$O ca -config "$C" -revoke "$W/a.crt" -crl_reason superseded 2>&1 | tail -1
bash "$TOOL" "$C" check; rc=$?; [ "$rc" = 0 ] && ok "check: none" || bad "check rc=$rc"
awk -F'\t' '$6 ~ /CN=us-rehearsal$/ {print $1}' "$S/db/index.txt" | tr '\n' ' ' | sed 's/^/    statuses: /'; echo
bash "$TOOL" "$C" set-yes; rc=$?
[ "$rc" = 0 ] && grep -q '^unique_subject = yes' "$S/db/index.txt.attr" && ok "set-yes done" || bad "set-yes rc=$rc"
$O ca -config "$C" -gencrl -out "$S/crl/b.crl" >/dev/null 2>&1 && ok "-gencrl with yes after the rollback" || bad "-gencrl after rollback"
$O crl -in "$S/crl/b.crl" -noout -text 2>/dev/null | grep -q "Serial Number: $SER_A" && ok "the revoked leaf is on the CRL" || bad "revoked leaf not on CRL"
owned "$S"

step "7. set-yes rollback branch: -updatedb forced to fail after the switch"
RB="$W/rb"; cp -a "$S" "$RB"; sed -i "s#$S#$RB#" "$RB/openssl-intermediate.cnf"
sed -i 's/^unique_subject.*/unique_subject = no/' "$RB/db/index.txt.attr"; sed -i -E 's/^(unique_subject[[:space:]]*=[[:space:]]*)yes/\1no/' "$RB/openssl-intermediate.cnf"
cat > "$W/openssl-fail2" <<WRAP
#!/bin/sh
# fails the SECOND -updatedb, passes everything else to the real openssl
case " \$* " in *" -updatedb "*) n=\$(cat "$W/n" 2>/dev/null || echo 0); n=\$((n+1)); echo \$n > "$W/n"; [ \$n = 2 ] && { echo "forced failure"; exit 1; } ;; esac
exec $O "\$@"
WRAP
chmod +x "$W/openssl-fail2"
OPENSSL="$W/openssl-fail2" bash "$TOOL" "$RB/openssl-intermediate.cnf" set-yes; rc=$?
pre=$(ls "$RB/db/" | grep -m1 '^index.txt.attr.pre-'); rbk=$(ls "$RB/db/" | grep -m1 '^index.txt.attr.rollback-')
[ "$rc" = 3 ] && grep -q '^unique_subject = no' "$RB/db/index.txt.attr" && grep -qE '^unique_subject[[:space:]]*=[[:space:]]*no' "$RB/openssl-intermediate.cnf" \
	&& ok "exit 3, attr and cnf back to no" || bad "rollback branch rc=$rc"
grep -q 'unique_subject = no' "$RB/db/$pre" && grep -q 'unique_subject = yes' "$RB/db/$rbk" \
	&& ok "pre-run backup ($pre) still holds no; the rollback backup holds yes" || bad "backups: $pre / $rbk"
owned "$RB"

step "live untouched"
L1=$(livehash); echo "    before $L0"; echo "    after  $L1"
[ "$L0" = "$L1" ] && ok "live index, attr, serial, crlnumber and cnf unchanged" || bad "LIVE FILES CHANGED"
find "$W" -name '*.key' -exec shred -u {} +; rm -f "$S/private/intermediate-ca.key" "$H/private/intermediate-ca.key" "$RB/private/intermediate-ca.key"
echo; [ $fail = 0 ] && echo "RESULT: all passed" || echo "RESULT: $fail failed"
exit $fail
