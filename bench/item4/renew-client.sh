#!/usr/bin/env bash
# renew-client.sh: reference client for certificate renewal over mTLS (item 4,
# ADR-014 and ADR-015).
#
# The directory given with --dir holds the client's identity:
#   client.crt, client.key   the CURRENT certificate and its ML-DSA-65 key
#   ca-chain.crt             the chain that issued the gateway's certificate
#   identity.pem             key and certificate in ONE file, replaced by a single
#                            rename; a service reading its identity while a renewal
#                            swaps the files should use this (curl --cert identity.pem)
# and, while a renewal is in flight:
#   pending.key, pending.csr the NEW key and its CSR, written BEFORE the request,
#                            so a lost response is retried with the same key and
#                            the server returns the same successor (idempotency)
#
# Renews at 2/3 of the certificate's lifetime (the server refuses before 1/2).
#
# After a renewal, a service must open NEW connections to use the new
# certificate. The gateway checks expiry on every request (client_cert_expiry.lua):
# a request still sent on a connection authenticated with the old certificate
# is refused once that certificate expires (HTTP/1.1: 400 and the connection is
# closed; HTTP/2: 400 for every stream until the client reconnects). With
# 30-day leaves the old certificate has about 10 days left at renewal and nginx
# ends every connection after 1 h, so this only matters for the 120 s demo.
#
# Each renewal request opens a new TLS connection (curl does), so the renewal always
# carries a fresh CertificateVerify and the access log shows the serial used.
#
# Proof of possession: an ML-DSA-65 signature by the CURRENT key over
#   "pqc-renew-v1\n<sha256 hex of the CSR DER>\n<current serial>\n<unix seconds>"
#
# Usage:
#   renew-client.sh --dir DIR --url https://pqc-gw.local:19443 [--resolve host:port:addr]
#                   [--once | --loop] [--retry 5] [--clock-offset N]
#   --once  renew now if the window is open (exit 3 if it is not yet)
#   --loop  wait for 2/3 of each lifetime, renew, repeat (the demo)
set -euo pipefail

# OpenSSL 3.5+ (ML-DSA-65): $OPENSSL, else the first one scripts/lib/pq-openssl.sh finds.
if [ -z "${OPENSSL:-}" ]; then
	. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/lib" && pwd)/pq-openssl.sh"; OPENSSL=$O
fi
# The PQ OpenSSL build ships no openssl.cnf; nothing here needs one.
export OPENSSL_CONF=${OPENSSL_CONF:-/dev/null}
# The custodian backdates notBefore by this much (ADR-014); the lifetime and the
# 2/3 point are counted from the real issue time.
BACKDATE=${BACKDATE:-60}
DIR="" URL="" RESOLVE=() MODE=once RETRY=5 SKEW=0

while [ $# -gt 0 ]; do
	case "$1" in
	--dir) DIR=$2; shift 2 ;;
	--url) URL=${2%/}; shift 2 ;;
	--resolve) RESOLVE+=(--resolve "$2"); shift 2 ;;
	--once) MODE=once; shift ;;
	--loop) MODE=loop; shift ;;
	--retry) RETRY=$2; shift 2 ;;
	--clock-offset) SKEW=$2; shift 2 ;;   # TEST AID: act as if this client's clock were off by N seconds
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$DIR" ] && [ -n "$URL" ] || { echo "usage: $0 --dir DIR --url URL [--resolve h:p:a] [--once|--loop]" >&2; exit 2; }
for f in client.crt client.key ca-chain.crt; do [ -s "$DIR/$f" ] || { echo "missing $DIR/$f" >&2; exit 2; }; done
umask 077
[ -s "$DIR/identity.pem" ] || { cat "$DIR/client.key" "$DIR/client.crt" > "$DIR/identity.pem.new" && mv "$DIR/identity.pem.new" "$DIR/identity.pem"; }

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
epoch() { date -u -d "$1" +%s; }
serial_of() { "$OPENSSL" x509 -in "$1" -noout -serial | cut -d= -f2; }
spki_of_key() { "$OPENSSL" pkey -in "$1" -pubout -outform DER | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1; }
spki_of_crt() { "$OPENSSL" x509 -in "$1" -noout -pubkey | "$OPENSSL" pkey -pubin -outform DER | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1; }

window() { # prints: notBefore notAfter renewAt (unix seconds)
	local nb na
	nb=$(epoch "$("$OPENSSL" x509 -in "$DIR/client.crt" -noout -startdate | cut -d= -f2)")
	na=$(epoch "$("$OPENSSL" x509 -in "$DIR/client.crt" -noout -enddate | cut -d= -f2)")
	local issued=$((nb + BACKDATE))
	echo "$nb $na $((issued + (na - issued) * 2 / 3))"
}

prepare_pending() {
	# Reuse an existing pending key: it is what makes a retry idempotent.
	if [ ! -s "$DIR/pending.key" ]; then
		"$OPENSSL" genpkey -algorithm ML-DSA-65 -out "$DIR/pending.key.tmp"
		mv "$DIR/pending.key.tmp" "$DIR/pending.key"
		rm -f "$DIR/pending.csr"
	fi
	if [ ! -s "$DIR/pending.csr" ]; then
		local subj
		subj=$("$OPENSSL" x509 -in "$DIR/client.crt" -noout -subject -nameopt compat | sed 's/^subject=//')
		OPENSSL_CONF=/dev/null "$OPENSSL" req -new -key "$DIR/pending.key" -subj "$subj" -out "$DIR/pending.csr.tmp"
		mv "$DIR/pending.csr.tmp" "$DIR/pending.csr"
	fi
}

renew_once() { # returns 0 renewed, 3 too early, 4 retry later, 1 refused
	prepare_pending
	local serial ts csrhash work code
	serial=$(serial_of "$DIR/client.crt")
	ts=$(( $(date -u +%s) + SKEW ))
	csrhash=$("$OPENSSL" req -in "$DIR/pending.csr" -outform DER | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1)
	work=$(mktemp -d)
	printf 'pqc-renew-v1\n%s\n%s\n%s' "$csrhash" "$serial" "$ts" > "$work/pop.msg"
	"$OPENSSL" pkeyutl -sign -inkey "$DIR/client.key" -rawin -in "$work/pop.msg" -out "$work/pop.sig"
	CSR_FILE="$DIR/pending.csr" SIG_FILE="$work/pop.sig" TS="$ts" python3 -I -c '
import base64, json, os
print(json.dumps({"csr": open(os.environ["CSR_FILE"]).read(),
                  "pop": {"timestamp": int(os.environ["TS"]),
                          "signature": base64.b64encode(open(os.environ["SIG_FILE"], "rb").read()).decode()}}))' > "$work/body.json"
	code=$(curl -sS "${RESOLVE[@]}" --cacert "$DIR/ca-chain.crt" --cert "$DIR/client.crt" --key "$DIR/client.key" \
		--max-time 30 -H 'Content-Type: application/json' --data-binary @"$work/body.json" \
		-o "$work/resp.json" -w '%{http_code}' -X POST "$URL/renew") || code=000
	case "$code" in
	201)
		python3 -I -c 'import json,sys; open(sys.argv[2],"w").write(json.load(open(sys.argv[1]))["certificate"])' "$work/resp.json" "$work/new.crt"
		# The returned certificate must carry OUR pending key and chain to the CA.
		if [ "$(spki_of_crt "$work/new.crt")" != "$(spki_of_key "$DIR/pending.key")" ]; then
			log "REFUSED: the returned certificate does not carry the pending key"; rm -rf "$work"; return 1
		fi
		"$OPENSSL" verify -attime $(( $(date -u +%s) + SKEW )) -CAfile "$DIR/ca-chain.crt" "$work/new.crt" >/dev/null || { log "REFUSED: the returned certificate does not verify"; rm -rf "$work"; return 1; }
		# Swap: certificate first into place under a temporary name, then both renames.
		cp "$DIR/client.crt" "$DIR/prev.crt"; cp "$DIR/client.key" "$DIR/prev.key"
		cp "$work/new.crt" "$DIR/client.crt.new"
		{ cat "$DIR/pending.key"; "$OPENSSL" x509 -in "$work/new.crt"; } > "$DIR/identity.pem.new"
		mv "$DIR/identity.pem.new" "$DIR/identity.pem"   # the one atomic switch
		mv "$DIR/pending.key" "$DIR/client.key"
		mv "$DIR/client.crt.new" "$DIR/client.crt"
		rm -f "$DIR/pending.csr"
		log "RENEWED serial $serial -> $(serial_of "$DIR/client.crt"), notAfter $("$OPENSSL" x509 -in "$DIR/client.crt" -noout -enddate | cut -d= -f2)$(python3 -I -c 'import json,sys; print(" (replay)" if json.load(open(sys.argv[1])).get("replay") else "")' "$work/resp.json")"
		rm -rf "$work"; return 0 ;;
	409)
		if grep -q '"reason":"too_early"' "$work/resp.json"; then log "too early: $(cat "$work/resp.json")"; rm -rf "$work"; return 3; fi
		log "REFUSED 409: $(cat "$work/resp.json")"; rm -rf "$work"; return 1 ;;
	000|429|502|503|504)
		log "retry later (HTTP $code): $(head -c 300 "$work/resp.json" 2>/dev/null)"; rm -rf "$work"; return 4 ;;
	*)
		log "REFUSED $code: $(head -c 500 "$work/resp.json" 2>/dev/null)"; rm -rf "$work"; return 1 ;;
	esac
}

if [ "$MODE" = once ]; then
	renew_once; exit $?
fi

log "loop: serial $(serial_of "$DIR/client.crt")"
while :; do
	read -r nb na at < <(window)
	now=$(( $(date -u +%s) + SKEW ))
	if [ "$now" -ge "$na" ]; then log "EXPIRED: the certificate ran out before it could renew; a new bootstrap enrollment is needed"; exit 1; fi
	if [ "$now" -lt "$at" ]; then sleep $(( at - now )); continue; fi
	rc=0; renew_once || rc=$?
	case $rc in
	0) ;;
	3|4) sleep "$RETRY" ;;
	*) exit 1 ;;
	esac
done
