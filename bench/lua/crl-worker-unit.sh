#!/usr/bin/env bash
# crl-worker-unit.sh: unit tests of crl_worker.lua's nextUpdate handling
# (ADR-024, pqc_crl_next_update_seconds). No nginx, no network, nothing kept.
#
#   1. crl-worker-unit.lua: the date parser against fixed vectors, and against a
#      real CRL's nextUpdate as `openssl crl` prints it in both date formats.
#      Without a Lua on the host (a CI runner) it runs inside the image of 2.
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
if [ -n "${LUA:-}" ]; then L=$LUA; elif ! L=$(command -v luajit || command -v lua); then L=""; fi
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
    -keyout "$d/ca.key" -out "$d/ca.crt" > "$d/req.log" 2>&1 || { cat "$d/req.log"; exit 1; }
}

# The image for the poll test (and for part 1 without a host Lua): OpenSSL and
# LuaJIT from the two pinned base images in base.lock.
img=crl-worker-unit:local
build_img() {
  lock() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$repo/base.lock"; }
  local OB RB
  OB="$(lock image)@$(lock digest)"; RB="$(lock openresty_image)@$(lock openresty_digest)"
  cat > "$T/Dockerfile" <<DF
FROM $OB AS o
FROM $RB
COPY --from=o /opt /opt
ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib:/usr/local/openresty/luajit/lib OPENSSL_CONF=/dev/null
DF
  docker build -q -t "$img" "$T" >/dev/null
}

echo "== 1. date parser"
if [ -z "$L" ]; then
  echo "   (no Lua on this host: running it with the image's LuaJIT)"
  build_img
  docker run --rm --network none -v "$repo:/r:ro" -e SKIP_POLL_TEST=1 \
    -e LUA=/usr/local/openresty/luajit/bin/luajit -e OPENSSL=/opt/openssl/bin/openssl \
    --entrypoint bash "$img" /r/bench/lua/crl-worker-unit.sh
else
  mkca "$T/a" "$O" -newkey ec -pkeyopt ec_paramgen_curve:P-256
  "$O" ca -config "$T/a/ca.cnf" -gencrl -out "$T/a/c.crl" > "$T/gencrl.log" 2>&1 || { cat "$T/gencrl.log"; exit 1; }
  rfc=$("$O" crl -in "$T/a/c.crl" -noout -text | sed -n 's/^ *Next Update: *//p' | head -1)
  iso=$("$O" crl -in "$T/a/c.crl" -noout -nextupdate -dateopt iso_8601 | sed 's/^nextUpdate=//')
  "$L" "$here/crl-worker-unit.lua" "$rfc" "$iso"
fi

[ "${SKIP_POLL_TEST:-0}" = 1 ] && { echo "== 2. poll test SKIPPED (SKIP_POLL_TEST=1)"; exit 0; }
echo "== 2. one real poll, ML-DSA-65 CRL, OpenSSL and LuaJIT from base.lock"
build_img
docker run --rm --network none -v "$repo:/r:ro" --entrypoint sh "$img" -c '
set -eu; O=/opt/openssl/bin/openssl; d=$(mktemp -d); mkdir -p /etc/pki/pqc-ca
q() { "$@" > /tmp/q.log 2>&1 || { echo "FAILED: $*"; cat /tmp/q.log; exit 1; }; }   # quiet unless it fails
# A root and an intermediate as the gateway has them, one revoked leaf.
mkca() { # mkca DIR: an openssl ca database and configuration in DIR
	mkdir -p "$1/db"; : > "$1/db/index.txt"; echo 1000 > "$1/db/crlnumber"; echo 1000 > "$1/db/serial"
	printf "[ca]\ndefault_ca=c\n[c]\ndir=$1\ndatabase=$1/db/index.txt\ncrlnumber=$1/db/crlnumber\nserial=$1/db/serial\nnew_certs_dir=$1\ncertificate=$1/ca.crt\nprivate_key=$1/ca.key\ndefault_md=default\ndefault_days=1\ndefault_crl_days=7\npolicy=p\n[p]\ncommonName=supplied\n[v3_ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n" > "$1/ca.cnf"
}
mkca $d/root; mkca $d/int
q $O req -x509 -newkey ML-DSA-65 -nodes -subj "/O=unit/CN=Unit Root CA" -days 2 -keyout $d/root/ca.key -out $d/root/ca.crt
q $O req -new -newkey ML-DSA-65 -nodes -subj "/O=unit/CN=Unit Intermediate CA" -keyout $d/int/ca.key -out $d/int/ca.csr
q $O ca -config $d/root/ca.cnf -batch -extensions v3_ca -in $d/int/ca.csr -out $d/int/ca.crt
q $O req -new -newkey ML-DSA-65 -nodes -subj /CN=leaf -keyout $d/l.key -out $d/l.csr
q $O ca -config $d/int/ca.cnf -batch -in $d/l.csr -out $d/l.crt
q $O ca -config $d/int/ca.cnf -revoke $d/l.crt
q $O ca -config $d/int/ca.cnf -gencrl -out $d/int.crl
q $O ca -config $d/root/ca.cnf -gencrl -crldays 30 -out $d/root.crl
cat $d/int/ca.crt $d/root/ca.crt > /etc/pki/pqc-ca/hybrid-ca-chain.crt
serial=$($O x509 -in $d/l.crt -noout -serial | sed "s/serial=//" | tr A-F a-f)
nu=$($O crl -in $d/int.crl -noout -nextupdate -dateopt iso_8601 | sed "s/^nextUpdate=//")
epoch=$(date -u -d "${nu%Z}" +%s)
cd /r/bench/lua
echo "-- combined CRL intermediate first"
cat $d/int.crl $d/root.crl > /etc/pki/pqc-ca/hybrid-combined-crl.pem
/usr/local/openresty/luajit/bin/luajit crl-worker-poll-unit.lua "$epoch" "$serial"
echo "-- combined CRL root first"
cat $d/root.crl $d/int.crl > /etc/pki/pqc-ca/hybrid-combined-crl.pem
/usr/local/openresty/luajit/bin/luajit crl-worker-poll-unit.lua withdrawn "$serial"
echo "-- chain file unreadable"
cat $d/int.crl $d/root.crl > /etc/pki/pqc-ca/hybrid-combined-crl.pem
rm /etc/pki/pqc-ca/hybrid-ca-chain.crt
/usr/local/openresty/luajit/bin/luajit crl-worker-poll-unit.lua nochain "$serial"
'
