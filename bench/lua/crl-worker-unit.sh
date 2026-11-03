#!/usr/bin/env bash
# crl-worker-unit.sh: unit tests of crl_worker.lua's nextUpdate handling
# (ADR-024, pqc_crl_next_update_seconds). No nginx, no network, nothing kept.
#
#   1. crl-worker-unit.lua: the date parser against fixed vectors, and against a
#      real CRL's nextUpdate as `openssl crl` prints it in both date formats.
#   2. crl-worker-poll-unit.lua: one real poll of crl_worker.lua with a stub
#      ngx, against a real ML-DSA-65 CRL with one revoked certificate. Needs
#      /opt/openssl and the CRL at the path crl_worker.lua hard-codes, so it runs
#      in a throwaway container built from the two pinned base images in
#      base.lock (Docker required; skipped with SKIP_POLL_TEST=1).
#
# Environment: OPENSSL (default /opt/openssl/bin/openssl, else openssl on PATH),
#              LUA (default luajit, else lua).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/../.." && pwd)
O=${OPENSSL:-/opt/openssl/bin/openssl}; [ -x "$O" ] || O=$(command -v openssl)
L=${LUA:-$(command -v luajit || command -v lua)}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# A throwaway CA: ca <dir> <openssl> <key algorithm args...>
mkca() {
  local d=$1 o=$2; shift 2
  mkdir -p "$d/db"; : > "$d/db/index.txt"; echo 1000 > "$d/db/crlnumber"; echo 1000 > "$d/db/serial"
  cat > "$d/ca.cnf" <<CNF
[ca]
default_ca = c
[c]
dir              = $d
database         = \$dir/db/index.txt
crlnumber        = \$dir/db/crlnumber
serial           = \$dir/db/serial
new_certs_dir    = \$dir
certificate      = \$dir/ca.crt
private_key      = \$dir/ca.key
default_md       = default
default_days     = 1
default_crl_days = 7
policy           = p
[p]
commonName       = supplied
CNF
  OPENSSL_CONF=/dev/null "$o" req -x509 "$@" -nodes -subj /CN=crl-worker-unit -days 1 \
    -keyout "$d/ca.key" -out "$d/ca.crt" 2>/dev/null
}

echo "== 1. date parser"
mkca "$T/a" "$O" -newkey ec -pkeyopt ec_paramgen_curve:P-256
"$O" ca -config "$T/a/ca.cnf" -gencrl -out "$T/a/c.crl" 2>/dev/null
rfc=$("$O" crl -in "$T/a/c.crl" -noout -text | sed -n 's/^ *Next Update: *//p' | head -1)
iso=$("$O" crl -in "$T/a/c.crl" -noout -nextupdate -dateopt iso_8601 | sed 's/^nextUpdate=//')
"$L" "$here/crl-worker-unit.lua" "$rfc" "$iso"

[ "${SKIP_POLL_TEST:-0}" = 1 ] && { echo "== 2. poll test SKIPPED (SKIP_POLL_TEST=1)"; exit 0; }
echo "== 2. one real poll, ML-DSA-65 CRL, OpenSSL and LuaJIT from base.lock"
lock() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$repo/base.lock"; }
OB="$(lock image)@$(lock digest)"; RB="$(lock openresty_image)@$(lock openresty_digest)"
cat > "$T/Dockerfile" <<DF
FROM $OB AS o
FROM $RB
COPY --from=o /opt /opt
ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib:/usr/local/openresty/luajit/lib OPENSSL_CONF=/dev/null
DF
img=crl-worker-unit:local
docker build -q -t "$img" "$T" >/dev/null
docker run --rm --network none -v "$repo:/r:ro" --entrypoint sh "$img" -c '
set -eu; O=/opt/openssl/bin/openssl; d=$(mktemp -d)
mkdir -p $d/db /etc/pki/pqc-ca; : > $d/db/index.txt; echo 1000 > $d/db/crlnumber; echo 1000 > $d/db/serial
printf "[ca]\ndefault_ca=c\n[c]\ndir=$d\ndatabase=$d/db/index.txt\ncrlnumber=$d/db/crlnumber\nserial=$d/db/serial\nnew_certs_dir=$d\ncertificate=$d/ca.crt\nprivate_key=$d/ca.key\ndefault_md=default\ndefault_days=1\ndefault_crl_days=7\npolicy=p\n[p]\ncommonName=supplied\n" > $d/ca.cnf
$O req -x509 -newkey ML-DSA-65 -nodes -subj /CN=crl-worker-unit -days 1 -keyout $d/ca.key -out $d/ca.crt 2>/dev/null
$O req -new -newkey ML-DSA-65 -nodes -subj /CN=leaf -keyout $d/l.key -out $d/l.csr 2>/dev/null
$O ca -config $d/ca.cnf -batch -in $d/l.csr -out $d/l.crt 2>/dev/null
$O ca -config $d/ca.cnf -revoke $d/l.crt 2>/dev/null
$O ca -config $d/ca.cnf -gencrl -out /etc/pki/pqc-ca/hybrid-combined-crl.pem 2>/dev/null
serial=$($O x509 -in $d/l.crt -noout -serial | sed "s/serial=//" | tr A-F a-f)
nu=$($O crl -in /etc/pki/pqc-ca/hybrid-combined-crl.pem -noout -nextupdate -dateopt iso_8601 | sed "s/^nextUpdate=//")
epoch=$(date -u -d "${nu%Z}" +%s)
cd /r/bench/lua && /usr/local/openresty/luajit/bin/luajit crl-worker-poll-unit.lua "$epoch" "$serial"'
