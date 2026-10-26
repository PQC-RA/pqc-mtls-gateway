#!/usr/bin/env bash
# check-tls-log-evidence.sh: prove, case by case, that the mTLS listener's logs
# record what each connection negotiated, and that every kind of refusal leaves
# an entry that names the reason. Asserts; prints PASS/FAIL per case.
#
#   A  valid ML-DSA-65 client  -> access: kex X25519MLKEM768, client_sig and
#                                 server_sig id-ml-dsa-65, client_key ML-DSA-65
#   B  no client certificate   -> access: 400, verify NONE; handshake log:
#                                 "client sent no required SSL certificate"
#   C  classical-keyed client certificate (optional, see BYPASS_*)
#                              -> identical to B on the server side: an OpenSSL
#                                 client cannot sign the ML-DSA-65-only
#                                 CertificateRequest, so it sends no
#                                 certificate. The server cannot tell C from B.
#   D  classical-only key exchange (X25519) and E (secp256r1)
#                              -> no request at all; handshake log:
#                                 "PQC-TLS refusing handshake: reason=no_pq_group"
#                                 and nginx's "no suitable key share"
#   F  pure ML-KEM-768 (no hybrid)  -> as D
#   G  TLS 1.2 only            -> "reason=no_tls13" and "unsupported protocol"
#
# Env:
#   GW_HOST (127.0.0.1)  GW_PORT (443)  SNI (pqc-gw.local)
#   CA        CA bundle that validates the server   (default /etc/pki/pqc-ca/ca-chain.crt)
#   LOG_DIR   host path of the gateway's /var/log/nginx volume
#             (default /var/lib/docker/volumes/pqc-gw_pqc-logs-nginx/_data)
#   CLIENT_CRT/CLIENT_KEY      a valid ML-DSA-65 client identity (required)
#   curl must be linked against an OpenSSL with ML-KEM and ML-DSA (see README.md)
#
# Read-only on the gateway: it sends seven requests and reads two log files.
# It defaults to the deployment on this host (port 443, the pqc-gw log volume);
# point GW_PORT/LOG_DIR/CA elsewhere for another stack.
#   BYPASS_CRT/BYPASS_KEY      optional classical-keyed cert signed by the PQ CA;
#                              this script never mints one (that needs a CA key)
set -uo pipefail
GW_HOST=${GW_HOST:-127.0.0.1}; GW_PORT=${GW_PORT:-443}; SNI=${SNI:-pqc-gw.local}
CA=${CA:-/etc/pki/pqc-ca/ca-chain.crt}
LOG_DIR=${LOG_DIR:-/var/lib/docker/volumes/pqc-gw_pqc-logs-nginx/_data}
ACC=$LOG_DIR/pqc-mtls-access.log; HS=$LOG_DIR/pqc-mtls-handshake.log
: "${CLIENT_CRT:?set CLIENT_CRT}" "${CLIENT_KEY:?set CLIENT_KEY}"
FAILS=0; RUN=0
for f in "$ACC" "$HS"; do [ -r "$f" ] || { echo "FATAL: cannot read $f"; exit 2; }; done

curl_gw(){ curl -s -o /dev/null -w '%{http_code}' --max-time 8 --cacert "$CA" \
  --resolve "$SNI:$GW_PORT:$GW_HOST" "$@" "https://$SNI:$GW_PORT/tls-evidence"; }

check(){ # check <label> <expect-in-access-regex|-> <expect-in-handshake-regex|-> <curl args...>
  local label=$1 ea=$2 eh=$3; shift 3
  local a0 h0 code al hl ok=1
  a0=$(wc -l < "$ACC"); h0=$(wc -l < "$HS")
  code=$(curl_gw "$@"); sleep 0.8
  al=$(tail -n +$((a0+1)) "$ACC"); hl=$(tail -n +$((h0+1)) "$HS")
  RUN=$((RUN+1))
  if [ "$ea" != "-" ]; then echo "$al" | grep -Eq "$ea" || ok=0; else [ -z "$al" ] || ok=0; fi
  if [ "$eh" != "-" ]; then echo "$hl" | grep -Eq "$eh" || ok=0; fi
  if [ $ok = 1 ]; then echo "PASS  $label (client saw HTTP ${code})"
  else
    FAILS=$((FAILS+1)); echo "FAIL  $label (client saw HTTP ${code})"
    echo "      access   : $(echo "$al" | head -2)"; echo "      handshake: $(echo "$hl" | head -3)"
  fi
  [ -n "$al" ] && echo "      access   : $(echo "$al" | tail -1)"
  [ -n "$hl" ] && echo "$hl" | grep -E 'PQC-TLS refusing|SSL_do_handshake|no required SSL|verify error' | sed -E 's/^[0-9\/: ]+/      handshake: /' | cut -c1-230
}

check "A valid ML-DSA-65 client" \
  '"kex":"X25519MLKEM768".*"client_sig":"id-ml-dsa-65","server_sig":"id-ml-dsa-65","client_key":"ML-DSA-65"' - \
  --cert "$CLIENT_CRT" --key "$CLIENT_KEY"
check "B no client certificate" \
  '"verify":"NONE".*"status":400.*"client_sig":"","server_sig":"id-ml-dsa-65","client_key":""' \
  'client sent no required SSL certificate'
if [ -n "${BYPASS_CRT:-}" ]; then
  check "C classical-keyed cert signed by the PQ CA ($(openssl x509 -in "$BYPASS_CRT" -noout -text 2>/dev/null | grep -m1 'Public Key Algorithm' | sed 's/.*: //'))" \
    '"verify":"NONE".*"status":400.*"client_key":""' 'client sent no required SSL certificate' \
    --cert "$BYPASS_CRT" --key "$BYPASS_KEY"
else
  echo "NOT RUN  C classical-keyed cert (no BYPASS_CRT given; this script does not mint one)"
fi
check "D classical-only key exchange X25519" - \
  'PQC-TLS refusing handshake: reason=no_pq_group offered_groups=X25519 ' \
  --curves X25519 --cert "$CLIENT_CRT" --key "$CLIENT_KEY"
check "E classical-only key exchange secp256r1" - \
  'PQC-TLS refusing handshake: reason=no_pq_group offered_groups=secp256r1' \
  --curves P-256 --cert "$CLIENT_CRT" --key "$CLIENT_KEY"
check "F pure ML-KEM-768, no hybrid" - \
  'PQC-TLS refusing handshake: reason=no_pq_group offered_groups=MLKEM768' \
  --curves MLKEM768 --cert "$CLIENT_CRT" --key "$CLIENT_KEY"
check "G TLS 1.2 only" - \
  'PQC-TLS refusing handshake: reason=no_tls13' \
  --tlsv1.2 --tls-max 1.2 --cert "$CLIENT_CRT" --key "$CLIENT_KEY"

# The refusals in D-G must ALSO appear as nginx's own handshake failures.
n_keyshare=$(tail -n 200 "$HS" | grep -c 'no suitable key share'); n_proto=$(tail -n 200 "$HS" | grep -c 'unsupported protocol')
echo "nginx's own lines in the last 200 handshake-log lines: 'no suitable key share'=$n_keyshare 'unsupported protocol'=$n_proto"
[ "$n_keyshare" -ge 3 ] && [ "$n_proto" -ge 1 ] || { FAILS=$((FAILS+1)); echo "FAIL  nginx handshake-failure lines missing"; }

echo; [ "$FAILS" = 0 ] && echo "TLS LOG EVIDENCE OK ($RUN cases)" || echo "*** $FAILS TLS LOG EVIDENCE CHECK(S) FAILED ***"
exit "$FAILS"
