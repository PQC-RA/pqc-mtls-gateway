# shellcheck shell=bash
# pq-openssl.sh: sourced by the stand and item-4 scripts. Finds an OpenSSL that
# can do ML-DSA-65 and X25519MLKEM768 (3.5 or later) and exports it as $O, with
# its library directory on LD_LIBRARY_PATH and OPENSSL_CONF=/dev/null.
#
# Looked for, in order: $OSSL, /opt/openssl/bin/openssl (the path the images
# use), /opt/openssl-*/bin/openssl, `openssl` on PATH. Build one with
# docker/base/openssl, or set OSSL.
pq_openssl_find() {
	local c v lib
	for c in ${OSSL:-} /opt/openssl/bin/openssl /opt/openssl-*/bin/openssl "$(command -v openssl 2>/dev/null)"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		lib=$(dirname "$(dirname "$c")")/lib64
		v=$(LD_LIBRARY_PATH=$lib OPENSSL_CONF=/dev/null "$c" version 2>/dev/null | awk '{print $2}')
		case "$v" in 3.[5-9]*|3.[1-9][0-9]*|[4-9].*) echo "$c"; return 0 ;; esac
	done
	return 1
}
O=$(pq_openssl_find) || { echo "no OpenSSL 3.5+ found (set OSSL to one)" >&2; exit 1; }
PQ_OPENSSL_LIB=$(dirname "$(dirname "$O")")/lib64
if [ -d "$PQ_OPENSSL_LIB" ]; then LD_LIBRARY_PATH=$PQ_OPENSSL_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}; export LD_LIBRARY_PATH; fi
export OPENSSL_CONF=/dev/null O
