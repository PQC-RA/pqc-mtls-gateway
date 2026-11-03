#!/usr/bin/env bash
# ca-unique-subject.sh: check and switch OpenSSL's unique_subject for a CA
# database, safely (item 4, ADR-019 decisions 3 to 5).
#
#   OPENSSL=/path/to/openssl ca-unique-subject.sh CNF check
#       -updatedb, then list subjects with more than one V row
#   OPENSSL=... ca-unique-subject.sh CNF set-no
#       -updatedb (a failure is tolerated: no is always safe), then unique_subject = no
#   OPENSSL=... ca-unique-subject.sh CNF set-yes
#       -updatedb, the duplicate check must report none, then unique_subject = yes;
#       switched back to no if -updatedb then fails
#
# Optional env: CUSTODIAN_CONTAINER (for example pqc-ca-custodian): set-yes
# then refuses while that container's RENEWAL_ENABLED=1.
#
# Why this way (ADR-019 review, objection 1):
#   * OpenSSL's name index covers every row with status V, by the EXACT subject
#     DN (strcmp), whether it has expired or not (apps.c index_name_qual). So
#     does the check.
#   * The index is built before -updatedb runs (ca.c), so with unique_subject = yes
#     and two V rows for one subject EVERY `openssl ca` call fails, -gencrl and
#     -revoke included, and the CRL lapses. Hence the check runs AFTER -updatedb,
#     and set-yes is refused while any duplicate is left.
#   * index.txt.attr overrides the cnf (apps.c), so the switch edits index.txt.attr;
#     the cnf line is changed too so the two never disagree.
# The custodian is the only writer of CA state (ADR-024) and holds its writer
# lock ($dir/.writer.lock) while it runs. This tool takes that lock without
# waiting, for the whole step, and refuses if it cannot: stop the custodian
# first. Files the tool or openssl rewrite get the owner of db/ back (the
# custodian runs as a non-root user and must still read them).
#
# Exit: 0 ok, 1 duplicates (check, set-yes refused), 2 usage or a precondition,
# 3 an openssl ca step failed (state restored where possible), 4 unexpected error.
set -Eeuo pipefail
umask 022
CNF=${1:-}; ACTION=${2:-}
[ -f "$CNF" ] && [[ "$ACTION" =~ ^(check|set-no|set-yes)$ ]] || { sed -n '2,15p' "$0" >&2; exit 2; }
[ -n "${OPENSSL:-}" ] && [ -x "$OPENSSL" ] || { echo "set OPENSSL to the rehearsed openssl binary (3.6.2)" >&2; exit 2; }
export OPENSSL_CONF=/dev/null
CNF=$(readlink -f "$CNF")
# database = $dir/db/index.txt, with dir taken from the cnf.
DIR=$(sed -n 's/^[[:space:]]*dir[[:space:]]*=[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CNF" | head -1)
DB=$(sed -n 's/^[[:space:]]*database[[:space:]]*=[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CNF" | head -1)
DB=${DB//\$dir/$DIR}
[ -f "$DB" ] || { echo "index not found: $DB" >&2; exit 2; }
DBDIR=$(dirname "$DB"); ATTR="$DB.attr"; LOCK="$DIR/.writer.lock"
TS=$(date -u +%Y%m%dT%H%M%SZ)

log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
current() { sed -n 's/^unique_subject[[:space:]]*=[[:space:]]*//p' "$ATTR" 2>/dev/null | head -1; }
trap 'rc=$?; log "UNEXPECTED ERROR (line $LINENO, rc $rc): attr says $(current || true), cnf says $(grep -E "^[[:space:]]*unique_subject" "$CNF" | head -1 || true)"; exit 4' ERR

# Preconditions.
CNFVAL=$(sed -nE 's/^[[:space:]]*unique_subject[[:space:]]*=[[:space:]]*([^[:space:]#]*).*/\1/p' "$CNF" | head -1)
if [ -n "$CNFVAL" ] && [[ ! "$CNFVAL" =~ ^(yes|no)$ ]]; then log "REFUSED: the cnf says unique_subject = $CNFVAL; only a literal yes or no is handled"; exit 2; fi
# docker inspect reads the environment of a stopped container too.
if [ "$ACTION" = set-yes ] && [ -n "${CUSTODIAN_CONTAINER:-}" ] \
	&& docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CUSTODIAN_CONTAINER" 2>/dev/null | grep -qx RENEWAL_ENABLED=1; then
	log "REFUSED: RENEWAL_ENABLED=1 in $CUSTODIAN_CONTAINER; switch renewal off first (ADR-019 decision 5)"; exit 2
fi

# Created, if missing, owned like the directory it is in (the custodian's), or
# the custodian could not open it afterwards.
[ -e "$LOCK" ] || install -m 0600 -o "$(stat -c %u "$DIR")" -g "$(stat -c %g "$DIR")" /dev/null "$LOCK"
exec 9>>"$LOCK"
flock -n 9 || { log "REFUSED: the custodian holds $LOCK; stop it first"; exit 2; }

OWNER=$(stat -c %u:%g "$DBDIR")
fixowner() { # openssl and this tool write as root; give db files back to db/'s owner
	for f in "$DB" "$DB.old" "$ATTR" "$ATTR.old"; do [ -e "$f" ] && chown "$OWNER" "$f"; done; return 0
}
updatedb() { local rc=0; "$OPENSSL" ca -config "$CNF" -updatedb > >(sed 's/^/    /') 2>&1 || rc=$?; fixowner; return $rc; }
# Subjects with more than one row of status V (column 1), keyed by the exact
# subject DN (column 6), expiry ignored, as OpenSSL's name index does.
dups() { awk -F'\t' '$1=="V"{n[$6]++} END{for(s in n) if(n[s]>1) printf "    %d x %s\n", n[s], s}' "$DB" | sort; }
replace_file() { # replace_file TARGET NEWFILE: same directory, owner and mode, then one rename
	chown --reference="$1" "$2"; chmod --reference="$1" "$2"; mv "$2" "$1"
}
setattr() { # setattr yes|no SUFFIX: index.txt.attr and the cnf line, each with a backup
	local v=$1 sfx=$2
	cp -p "$ATTR" "$ATTR.$sfx"
	if grep -q '^unique_subject' "$ATTR"; then sed "s/^unique_subject.*/unique_subject = $v/" "$ATTR" > "$ATTR.new-$TS"
	else { cat "$ATTR"; echo "unique_subject = $v"; } > "$ATTR.new-$TS"; fi
	replace_file "$ATTR" "$ATTR.new-$TS"
	if [ -n "$CNFVAL" ]; then
		cp -p "$CNF" "$CNF.$sfx"
		sed -E "s/^([[:space:]]*unique_subject[[:space:]]*=[[:space:]]*)(yes|no)/\1$v/" "$CNF" > "$CNF.new-$TS"
		replace_file "$CNF" "$CNF.new-$TS"
	fi
	[ "$(current)" = "$v" ] || { log "attr does not say $v after the write"; return 1; }
	if [ -n "$CNFVAL" ]; then
		[ "$(sed -nE 's/^[[:space:]]*unique_subject[[:space:]]*=[[:space:]]*([^[:space:]#]*).*/\1/p' "$CNF" | head -1)" = "$v" ] \
			|| { log "cnf does not say $v after the write"; return 1; }
	fi
}

log "unique_subject now: $(current || echo '(no attr file)'); $(awk -F'\t' '{c[$1]++} END{for(k in c) printf "%s=%d ", k, c[k]}' "$DB")"
log "-updatedb"
if ! updatedb; then
	if [ "$ACTION" = set-no ]; then
		log "-updatedb FAILED (with unique_subject = yes this means duplicates already exist); writing no anyway, which is always safe"
		setattr no "pre-$TS"; log "unique_subject = no written"
		updatedb || { log "-updatedb still fails after set-no"; exit 3; }
		log "unique_subject now: $(current)"; exit 0
	fi
	log "-updatedb FAILED (with unique_subject = yes this means duplicates already exist; run set-no)"; exit 3
fi
D=$(dups)
if [ -n "$D" ]; then log "duplicate V subjects:"; echo "$D"; else log "duplicate V subjects: none"; fi

case "$ACTION" in
check) [ -z "$D" ] || exit 1 ;;
set-no)
	setattr no "pre-$TS"; log "unique_subject = no written"
	updatedb || { log "-updatedb failed after set-no"; exit 3; } ;;
set-yes)
	[ -z "$D" ] || { log "REFUSED: unique_subject stays $(current)"; exit 1; }
	setattr yes "pre-$TS"; log "unique_subject = yes written"
	if ! updatedb; then
		log "-updatedb FAILED after set-yes: restoring no"; setattr no "rollback-$TS"; updatedb || true; exit 3
	fi ;;
esac
log "unique_subject now: $(current)"
