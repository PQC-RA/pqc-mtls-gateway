#!/usr/bin/env bash
# run-migrate-ca-state-unit.sh: offline test of scripts/migrate-ca-state.sh
# (ADR-024 PR 4a). One throwaway container with no network: setup-pki.sh makes
# a fresh PKI at the default paths inside it, the old renewer and the custodian
# are played with `openssl ca` (the custodian as its own uid 1003, through the
# migrated configuration), and the migration runs forward, back and forward
# again. Nothing outside the container is touched.
#
# The deployment migrated FROM is built the way it really was: with the
# pre-ADR-024 setup-pki.sh (the tree at PRE_ADR024, main before the cut-over),
# since today's setup-pki.sh already ends in the custodian's layout.
#
# Usage: run-migrate-ca-state-unit.sh <custodian-image>
#   Any image with bash, flock, setpriv and OpenSSL 3.5+ at /opt/openssl will
#   do; the custodian image has all of them.
set -euo pipefail
IMG=${1:?usage: run-migrate-ca-state-unit.sh <custodian-image>}
repo=$(cd "$(dirname "$0")/../.." && pwd)
PRE_ADR024=${PRE_ADR024:-ec423fa}
old=$(mktemp -d); trap 'rm -rf "$old"' EXIT
git -C "$repo" archive "$PRE_ADR024" | tar -x -C "$old"
docker run --rm --network none --user 0:0 -v "$repo:/repo:ro" -v "$old:/old:ro" --entrypoint bash "$IMG" -c '
set -uo pipefail
export OPENSSL_CONF=/dev/null
O=/opt/openssl/bin/openssl; M=/tmp/r/scripts/migrate-ca-state.sh
P=/etc/pki/pqc-ca; INT=$P/intermediate
PASS=0; FAIL=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
crlno(){ $O crl -in "$1" -noout -crlnumber | sed "s/crlNumber=0x//"; }
serials(){ $O crl -in "$1" -noout -text | sed -n "s/^ *Serial Number: *//p" | sort -u; }
treehash(){ (cd "$1" && find . -type f ! -name "*.lock" -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16); }
as_ca(){ setpriv --reuid=1003 --regid=1003 --clear-groups "$@"; }

cp -r /repo /tmp/r; cp -r /old /tmp/old
( cd /tmp/old && PKI_DIR=$P SSL_DIR=/etc/ssl/pqc SERVER_IP=127.0.0.1 ./scripts/setup-pki.sh ) > /tmp/setup.log 2>&1 \
  || { tail -20 /tmp/setup.log; exit 1; }

# --- the old design at work: sign three, revoke one, the renewer publishes ---
leaf(){ $O req -new -newkey ML-DSA-65 -nodes -subj "/CN=$1" -keyout /tmp/$1.key -out /tmp/$1.csr 2>/dev/null
        $O ca -config $INT/openssl-intermediate.cnf -batch -in /tmp/$1.csr -out /tmp/$1.crt 2>/dev/null
        $O x509 -in /tmp/$1.crt -noout -serial | cut -d= -f2; }
renewer(){ $O ca -config $INT/openssl-intermediate.cnf -gencrl -out $INT/crl/intermediate-ca.crl 2>/dev/null
           cat $INT/crl/intermediate-ca.crl $P/root/crl/root-ca.crl > $P/hybrid-combined-crl.pem; cp $P/hybrid-combined-crl.pem $P/combined-crl.pem; }
S1=$(leaf old-a); S2=$(leaf old-b); S3=$(leaf old-c)
$O ca -config $INT/openssl-intermediate.cnf -revoke /tmp/old-a.crt 2>/dev/null; renewer
N=$(crlno $INT/crl/intermediate-ca.crl)
echo "old tree: serials $S1 $S2 $S3, $S1 revoked, last CRL number $N"
BEFORE=$(treehash $P)
TRUST=/etc/pki/pqc-trust

# --- setup-pki.sh of this release, re-run on the old deployment: changes nothing --
( cd /tmp/r && PKI_DIR=$P SSL_DIR=/etc/ssl/pqc SERVER_IP=127.0.0.1 ./scripts/setup-pki.sh ) > /tmp/rerun.log 2>&1; rc=$?
check "setup-pki.sh re-run on a pre-ADR-024 deployment: exit 0, the tree unchanged, no trust directory made" "[ $rc = 0 ] && [ \"$(treehash $P)\" = \"$BEFORE\" ] && [ ! -e $TRUST ] && grep -q \"internal TLS left as it is\" /tmp/rerun.log" || tail -8 /tmp/rerun.log

# --- forward -----------------------------------------------------------------
$M forward > /tmp/fwd.log 2>&1; rc=$?
check "forward succeeds" "[ $rc = 0 ]" || tail -5 /tmp/fwd.log
check "forward leaves the old tree byte for byte unchanged" "[ \"$(treehash $P)\" = \"$BEFORE\" ]"
. /tmp/r/scripts/lib/ca-layout.sh
check "layout owners and modes match the spec" "ca_layout_check >/dev/null"
check "key: 0400, owned by the custodian uid, only in the key directory" "[ \"$(stat -c %u:%a $CA_KEY_FILE)\" = 1003:400 ] && ! grep -rlq \"PRIVATE KEY\" $CA_STATE_DIR $CA_INBOX_DIR $CA_PUBLIC_DIR $CA_STATUS_DIR"
check "OCSP key: only in its own directory, root:1002 0640" "[ \"$(stat -c %u:%g:%a $OCSP_KEY_DIR/ocsp-pq.key)\" = 0:1002:640 ]"
check "trust anchors copied to $TRUST: root, 0755, files 0644, identical to the copies in the old tree" "[ \"$(stat -c %u:%g:%a $TRUST)\" = 0:0:755 ] && [ \"$(stat -c %u:%g:%a $TRUST/internal-tls-ca.crt)\" = 0:0:644 ] && cmp -s $TRUST/internal-tls-ca.crt $P/internal-tls-ca.crt && cmp -s $TRUST/internal-tls-ca-mldsa.crt $P/internal-tls-ca-mldsa.crt && ! grep -rlq \"PRIVATE KEY\" $TRUST"
check "configuration points at the new layout" "grep -qx \"dir               = $CA_STATE_DIR\" $CA_CNF_FILE && grep -qx \"private_key       = $CA_KEY_FILE\" $CA_CNF_FILE"
as_ca sh -c "echo x > $CA_STATUS_DIR/probe"
check "a file the custodian writes into the status directory is readable by group 1002 (setgid)" "[ \"$(stat -c %g $CA_STATUS_DIR/probe)\" = 1002 ]"
rm -f $CA_STATUS_DIR/probe
check "public and status directories start empty (the custodian publishes)" "[ -z \"$(find $CA_PUBLIC_DIR $CA_STATUS_DIR -mindepth 1)\" ]"
$M forward > /tmp/fwd2.log 2>&1; rc=$?
check "a second forward refuses (target not empty)" "[ $rc != 0 ] && grep -q \"not empty\" /tmp/fwd2.log"

# --- verify catches a changed copy ---------------------------------------------
$M verify > /tmp/v.log 2>&1; check "verify passes on the fresh copy" "[ $? = 0 ]"
F=$(ls $CA_STATE_DIR/issued/* | head -1); cp -p $F /tmp/keep; echo tamper >> $F
$M verify > /tmp/v2.log 2>&1; rc=$?
check "verify fails on a changed copy and names it" "[ $rc != 0 ] && grep -q \"CHANGED $F\" /tmp/v2.log"
cp -p /tmp/keep $F

# --- the custodian at work on the new layout, as uid 1003 -----------------------
as_ca $O ca -config $CA_CNF_FILE -gencrl -out $CA_STATE_DIR/crl/intermediate-ca.crl 2>/dev/null
check "as uid 1003 the migrated configuration signs CRL N+1" "[ $((16#$(crlno $CA_STATE_DIR/crl/intermediate-ca.crl))) = $((16#$N + 1)) ]"
check "CRL N+1 is a superset of CRL N" "[ -z \"$(comm -23 <(serials $INT/crl/intermediate-ca.crl) <(serials $CA_STATE_DIR/crl/intermediate-ca.crl))\" ]"

# --- check-next: the ADR switch step 4 gate, before any reader moves -------------
cat $CA_STATE_DIR/crl/intermediate-ca.crl $CA_STATE_DIR/crl/root-ca.crl > $CA_PUBLIC_DIR/hybrid-combined-crl.pem
$M check-next > /tmp/cn.log 2>&1; rc=$?
check "check-next passes a good N+1 (verifies, N+1, superset, intermediate first, 6+ days)" "[ $rc = 0 ]" || cat /tmp/cn.log
cat $CA_STATE_DIR/crl/root-ca.crl $CA_STATE_DIR/crl/intermediate-ca.crl > $CA_PUBLIC_DIR/hybrid-combined-crl.pem
$M check-next > /tmp/cn.log 2>&1; rc=$?
check "check-next refuses a root-first combined CRL (exit 1)" "[ $rc != 0 ] && grep -q \"not the intermediate\" /tmp/cn.log"
cat $CA_STATE_DIR/crl/intermediate-ca.crl $CA_STATE_DIR/crl/root-ca.crl > $CA_PUBLIC_DIR/hybrid-combined-crl.pem
# An N with one more revocation than N+1 carries: a copy of the old tree in
# which a third certificate is revoked (the live tree stays as it is).
cp -a $P /tmp/fakeP
sed -i "s#^dir[[:space:]]*=.*#dir               = /tmp/fakeP/intermediate#" /tmp/fakeP/intermediate/openssl-intermediate.cnf
$O ca -config /tmp/fakeP/intermediate/openssl-intermediate.cnf -revoke /tmp/old-c.crt > /tmp/fake.log 2>&1
$O ca -config /tmp/fakeP/intermediate/openssl-intermediate.cnf -gencrl -out /tmp/fakeP/intermediate/crl/intermediate-ca.crl >> /tmp/fake.log 2>&1
$M check-next --from /tmp/fakeP > /tmp/cn.log 2>&1; rc=$?
check "check-next refuses an N+1 that misses a serial revoked in N (exit 1, names it)" "[ $rc != 0 ] && grep -q \"missing from N+1: $S3\" /tmp/cn.log"
cp /tmp/old-b.crt /tmp/b.crt; chmod 644 /tmp/b.crt
as_ca $O ca -config $CA_CNF_FILE -revoke /tmp/b.crt 2>/dev/null
as_ca $O ca -config $CA_CNF_FILE -gencrl -out $CA_STATE_DIR/crl/intermediate-ca.crl 2>/dev/null
NC=$(crlno $CA_STATE_DIR/crl/intermediate-ca.crl)
cat $CA_STATE_DIR/crl/intermediate-ca.crl $CA_STATE_DIR/crl/root-ca.crl > $CA_PUBLIC_DIR/hybrid-combined-crl.pem
cp $CA_PUBLIC_DIR/hybrid-combined-crl.pem $CA_PUBLIC_DIR/combined-crl.pem
check "the custodian revoked $S2 in the new layout (CRL $NC)" "serials $CA_STATE_DIR/crl/intermediate-ca.crl | grep -qx $S2"
check "the old tree did not see it" "! serials $P/hybrid-combined-crl.pem | grep -qx $S2"
$M check-next > /tmp/cn.log 2>&1; rc=$?
check "check-next refuses N+2 (it must be the first CRL of the custodian, N+1)" "[ $rc != 0 ] && grep -q \"expected 0x\" /tmp/cn.log"

# --- retire ---------------------------------------------------------------------
$M retire > /tmp/ret.log 2>&1; rc=$?
check "retire renames the old intermediate, ocsp and public files" "[ $rc = 0 ] && [ ! -d $INT ] && [ ! -d $P/ocsp ] && [ ! -f $P/hybrid-combined-crl.pem ] && ls -d $INT.migrated-* $P/ocsp.migrated-* $P/public.migrated-* >/dev/null"
check "the writer lock a host tool created belongs to the custodian (uid 1003), so it can still start" "[ \"$(stat -c %u $CA_WRITER_LOCK)\" = 1003 ]"
check "retire keeps the host-only CAs where they are" "[ -f $P/root/private/root-ca.key ] && [ -f $P/internal-tls/internal-tls-ca.key ]"
check "retire renames the old trust-file copies (the trust directory holds them now)" "[ ! -e $P/internal-tls-ca.crt ] && ls $P/public.migrated-*/internal-tls-ca.crt >/dev/null && [ -f $TRUST/internal-tls-ca.crt ]"

# --- the writer lock keeps a host writer out ------------------------------------
( flock -x 9; sleep 4 ) 9>>$CA_WRITER_LOCK & sleep 0.5
$M reverse > /tmp/rev0.log 2>&1; rc=$?
check "reverse refuses while the custodian holds the writer lock" "[ $rc != 0 ] && grep -q \"holds\" /tmp/rev0.log"
wait

# --- a reverse whose checks fail changes nothing ----------------------------------
PB=$(treehash $P); NB=$(treehash $CA_ROOT)
cp -p $CA_PUBLIC_DIR/hybrid-combined-crl.pem /tmp/keepcomb
cat $CA_STATE_DIR/crl/root-ca.crl $CA_STATE_DIR/crl/intermediate-ca.crl > $CA_PUBLIC_DIR/hybrid-combined-crl.pem
$M reverse > /tmp/revf.log 2>&1; rc=$?
check "reverse refuses a root-first combined CRL (exit 1)" "[ $rc != 0 ] && grep -q \"does not start with the intermediate\" /tmp/revf.log"
check "and leaves the old tree byte for byte as it was (still retired, no staging left)" "[ \"$(treehash $P)\" = \"$PB\" ] && [ ! -d $INT ] && [ -z \"$(find $P -maxdepth 1 -name \".reverse-staging-*\")\" ]"
check "and the new layout too" "[ \"$(treehash $CA_ROOT)\" = \"$NB\" ]"
cp -p /tmp/keepcomb $CA_PUBLIC_DIR/hybrid-combined-crl.pem
cp -p $CA_STATE_DIR/db/index.txt /tmp/keepidx
awk -F"\t" -v OFS="\t" -v s=$S1 "\$4==s{\$1=\"V\";\$3=\"\"}1" /tmp/keepidx > $CA_STATE_DIR/db/index.txt
$M reverse > /tmp/revu.log 2>&1; rc=$?
check "reverse refuses a state index that would un-revoke $S1, and changes nothing" "[ $rc != 0 ] && grep -q \"un-revoke\" /tmp/revu.log && grep -q $S1 /tmp/revu.log && [ \"$(treehash $P)\" = \"$PB\" ]"
cp -p /tmp/keepidx $CA_STATE_DIR/db/index.txt

# --- reverse --------------------------------------------------------------------
# An ADR-022 switch after the cut-over changed the trust file: the ML-DSA-65 CA only.
cp $TRUST/internal-tls-ca-mldsa.crt /tmp/trust-new.crt
cat /tmp/trust-new.crt /tmp/trust-new.crt > $TRUST/internal-tls-ca.crt
TRUST_NOW=$(sha256sum < $TRUST/internal-tls-ca.crt)
$M reverse > /tmp/rev.log 2>&1; rc=$?
check "reverse succeeds" "[ $rc = 0 ]" || tail -8 /tmp/rev.log
check "the old tree is back in place" "[ -d $INT ] && [ -f $P/hybrid-combined-crl.pem ] && [ -d $P/ocsp ]"
check "the revocation made in the new layout is in the old index" "grep -q \"^R.*	$S2	\" $INT/db/index.txt"
check "the old combined CRL is the latest one: $S1 and $S2 revoked, intermediate first" "serials $P/hybrid-combined-crl.pem | grep -qx $S1 && serials $P/hybrid-combined-crl.pem | grep -qx $S2 && $O crl -in $P/hybrid-combined-crl.pem -noout -issuer | grep -q Intermediate"
check "crlnumber was copied back: the next CRL is above $NC" "[ $((16#$(cat $INT/db/crlnumber))) -gt $((16#$NC)) ]"
check "the previous old tree is kept, renamed, and no staging is left" "ls -d $INT.pre-reverse-* >/dev/null && [ -z \"$(find $P -maxdepth 1 -name \".reverse-staging-*\")\" ]"
check "the trust file as it is now is back where the previous release reads it; the trust directory set aside" "[ \"$(sha256sum < $P/internal-tls-ca.crt)\" = \"$TRUST_NOW\" ] && [ -f $P/internal-tls-ca-mldsa.crt ] && [ ! -e $TRUST ] && ls -d $TRUST.reversed-* >/dev/null"
check "the new layout is set aside, not deleted" "[ ! -d $CA_ROOT ] && ls -d $CA_ROOT.reversed-* $CA_PUBLIC_DIR.reversed-* >/dev/null"

# --- the old renewer runs again: numbers keep rising ------------------------------
renewer
NR=$(crlno $INT/crl/intermediate-ca.crl)
check "the old renewer'"'"'s next CRL ($NR) is above the custodian'"'"'s ($NC): no number used twice" "[ $((16#$NR)) -gt $((16#$NC)) ]"

# --- forward again ----------------------------------------------------------------
$M forward > /tmp/fwd3.log 2>&1; rc=$?
check "forward again after a reverse" "[ $rc = 0 ]" || tail -5 /tmp/fwd3.log
as_ca $O ca -config $CA_CNF_FILE -gencrl -out $CA_STATE_DIR/crl/intermediate-ca.crl 2>/dev/null
check "and the custodian'"'"'s next CRL is above the renewer'"'"'s $NR" "[ $((16#$(crlno $CA_STATE_DIR/crl/intermediate-ca.crl))) -gt $((16#$NR)) ]"
check "every revocation survived the round trip" "serials $CA_STATE_DIR/crl/intermediate-ca.crl | grep -qx $S1 && serials $CA_STATE_DIR/crl/intermediate-ca.crl | grep -qx $S2"

echo "$PASS/$((PASS+FAIL)) passed"
[ "$FAIL" = 0 ]'
