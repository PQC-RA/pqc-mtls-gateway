#!/usr/bin/env bash
# Builds the TEST-ONLY patched OpenSSL client used by bench/test8b and by the 2x2 enforcement matrix.
# The patch (bench/test8b/test8b-force-client-sigalg.patch) makes a TLS 1.3 client ignore the server's
# signature_algorithms list and sign with its own classical algorithm, only when TEST8B_FORCE_CLIENT_SIGALG
# is set. Never install it as a system OpenSSL. The source tarball must match OPENSSL_SHA256 in
# docker/base/versions.env.
#
# Usage: build-test8b-openssl.sh TARBALL PREFIX
set -euo pipefail
TARBALL=${1:?path to openssl-3.6.5.tar.gz}; PREFIX=${2:?install prefix, e.g. /opt/openssl-8b}
HERE=$(cd "$(dirname "$0")" && pwd); PATCH="$HERE/../../test8b/test8b-force-client-sigalg.patch"
want=$(sed -n 's/^OPENSSL_SHA256=//p' "$HERE/../../../docker/base/versions.env")
have=$(sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$want" = "$have" ] || { echo "checksum mismatch: $have != $want" >&2; exit 1; }
W=$(mktemp -d); tar -xf "$TARBALL" -C "$W"; cd "$W"/openssl-*
patch -p0 < "$PATCH"
./Configure --prefix="$PREFIX" no-docs no-tests
make -j"$(nproc)"; make install_sw
echo "built: $PREFIX/bin/openssl (run with LD_LIBRARY_PATH=$PREFIX/lib64 and TEST8B_FORCE_CLIENT_SIGALG=1)"
