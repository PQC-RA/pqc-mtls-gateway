#!/usr/bin/env bash
# trust-dir-unit.sh: the public trust directory /etc/pki/pqc-trust (ADR-024 §3,
# Rumen 2026-11-03), with scripts/setup-pki.sh and scripts/lib/internal-tls.sh,
# in one throwaway container with no network. Nothing is kept.
#
#   - a fresh bootstrap puts the internal TLS trust anchors there (root, 0755,
#     0644, public certificates only) and none in /etc/pki/pqc-ca; the keys
#     stay in /etc/pki/pqc-ca/internal-tls, 0700;
#   - a re-run changes nothing;
#   - itls_install replaces a file by rename (a new inode, the mode set, no
#     temporary left), so a reader holding the old file still reads it whole;
#   - a migrated host whose trust files are still in /etc/pki/pqc-ca gets them
#     copied, never a new internal CA over the key they depend on.
#
# Usage: trust-dir-unit.sh <custodian-image>   (bash, OpenSSL 3.5+ at /opt/openssl)
set -euo pipefail
IMG=${1:?usage: trust-dir-unit.sh <custodian-image>}
repo=$(cd "$(dirname "$0")/../.." && pwd)
docker run --rm --network none --user 0:0 -v "$repo:/repo:ro" --entrypoint bash "$IMG" -c '
set -uo pipefail
PASS=0; FAIL=0
check(){ if eval "$2"; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1"; FAIL=$((FAIL+1)); return 1; fi; }
P=/etc/pki/pqc-ca; S=/etc/ssl/pqc; TR=/etc/pki/pqc-trust
setup(){ ( cd /tmp/r && PKI_DIR=$P SSL_DIR=$S SERVER_IP=127.0.0.1 ./scripts/setup-pki.sh ) > "$1" 2>&1; }
sums(){ sha256sum $TR/* $P/internal-tls/internal-tls-ca.key | sha256sum; }
cp -r /repo /tmp/r

setup /tmp/s1.log || { tail -20 /tmp/s1.log; exit 1; }
check "fresh: $TR is root, 0755" "[ \"\$(stat -c %u:%g:%a $TR)\" = 0:0:755 ]"
check "  ... holds the trust file and the ML-DSA-65 CA, root, 0644" "[ \"\$(stat -c %u:%g:%a $TR/internal-tls-ca.crt $TR/internal-tls-ca-mldsa.crt | sort -u)\" = 0:0:644 ]"
check "  ... public certificates only" "! grep -rlq \"PRIVATE KEY\" $TR && [ \"\$(ls $TR | grep -cv \"\\.crt\$\")\" = 0 ]"
check "  ... the trust file verifies the :8081 leaf" "/opt/openssl/bin/openssl verify -CAfile $TR/internal-tls-ca.crt $S/internal-tls.crt >/dev/null"
check "  ... no internal TLS certificate in $P any more" "! compgen -G \"$P/internal-tls-ca*.crt\" >/dev/null"
check "  ... the CA key in $P/internal-tls, 0700 directory, 0600 key" "[ \"\$(stat -c %a $P/internal-tls)\" = 700 ] && [ \"\$(stat -c %a $P/internal-tls/internal-tls-ca.key)\" = 600 ]"

before=$(sums)
setup /tmp/s2.log
check "re-run: current (skip), nothing changed" "grep -q \"current (skip)\" /tmp/s2.log && [ \"\$(sums)\" = \"$before\" ]"

# itls_install, as setup-pki.sh and internal-tls-switch.sh use it.
PKI_DIR=$P SSL_DIR=$S OPENSSL=/opt/openssl/bin/openssl; . /tmp/r/scripts/lib/internal-tls.sh
cp $TR/internal-tls-ca.crt /tmp/old.crt
ino=$(stat -c %i $ITLS_BUNDLE)
exec 7< $ITLS_BUNDLE                      # a reader that opened the old file
cat $TR/internal-tls-ca-mldsa.crt $TR/internal-tls-ca-mldsa.crt > /tmp/new.crt
cp /tmp/new.crt /tmp/new.src
itls_install /tmp/new.src $ITLS_BUNDLE 644
check "itls_install: replaced by rename (new inode), mode 0644, content new" "[ \"\$(stat -c %i $ITLS_BUNDLE)\" != $ino ] && [ \"\$(stat -c %a $ITLS_BUNDLE)\" = 644 ] && cmp -s /tmp/new.crt $ITLS_BUNDLE"
check "  ... no temporary left, the source removed" "[ -z \"\$(ls -A $TR | grep \"^\\.\")\" ] && [ ! -e /tmp/new.src ]"
check "  ... a reader of the old file still reads it whole" "cmp -s /tmp/old.crt /dev/fd/7"
exec 7<&-
cp /tmp/old.crt /tmp/back.src; itls_install /tmp/back.src $ITLS_BUNDLE 644

# A migrated host whose trust files are still where they were before ADR-024.
mkdir -p /var/lib/pqc-ca/state                # what makes setup-pki.sh treat it as migrated
mv $TR/internal-tls-ca.crt $TR/internal-tls-ca-mldsa.crt $P/
rmdir $TR
key=$(sha256sum < $P/internal-tls/internal-tls-ca.key)
setup /tmp/s3.log
check "legacy trust files: copied into $TR, not re-created" "cmp -s $P/internal-tls-ca.crt $TR/internal-tls-ca.crt && cmp -s $P/internal-tls-ca-mldsa.crt $TR/internal-tls-ca-mldsa.crt && grep -q \"copied $P/internal-tls-ca.crt\" /tmp/s3.log" || tail -8 /tmp/s3.log
check "  ... the internal CA key untouched" "[ \"\$(sha256sum < $P/internal-tls/internal-tls-ca.key)\" = \"$key\" ]"

echo "$PASS/$((PASS+FAIL)) passed"
[ "$FAIL" = 0 ]'
