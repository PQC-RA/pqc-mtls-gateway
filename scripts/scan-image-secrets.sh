#!/usr/bin/env bash
# scan-image-secrets.sh — hard gate that FAILS (exit 1) if a built container
# image leaks private-key or secret material. Intended for CI (run before an
# image is pushed/published) and for manual spot checks.
#
#   Usage: scan-image-secrets.sh <image-ref>
#   Exit:  0  PASS  — no private-key/secret material found
#          1  FAIL  — image leaks secret material (offending paths printed)
#          2  usage / environment error (bad args, docker missing, no such image)
#
# On a PKI/CA product a private key or shared HMAC secret baked into an image
# layer is a critical leak (it also lands in the registry build cache). This
# script is the belt to the .dockerignore's braces.
#
# What it checks:
#   [A] Build history  (docker history --no-trunc): a private-key PEM embedded in
#       a build instruction (e.g. `RUN echo "-----BEGIN ... PRIVATE KEY-----"`).
#   [B] Final filesystem (docker create + docker export = the merged rootfs that
#       actually ships):
#         B.1  A REAL PEM private-key block — `-----BEGIN [...]PRIVATE KEY-----`
#              followed by a base64 body and a matching `-----END` line. Binary
#              files are skipped and mere header *mentions* in source/docs (e.g.
#              the `jose` library, npm docs) are ignored via a two-stage detect,
#              so the gate does not false-positive on dependency code. CSRs
#              (`BEGIN CERTIFICATE REQUEST`) and certs (`BEGIN CERTIFICATE`) are
#              intentionally NOT flagged — only private keys.
#         B.2  ANY file baked under /secrets or /run/secrets (the secret
#              mountpoints) — e.g. an HMAC `*.key` that should only ever be
#              bind-mounted at runtime, never baked in.
#         B.3  Known secret filenames anywhere in the image (`*-hmac.key`,
#              `gateway-signing*.key`) — catches an HMAC/signing key copied to a
#              non-standard path (HMAC keys are hex, so B.1's PEM check misses
#              them).

set -euo pipefail

PROG="$(basename "$0")"

usage() {
	cat <<EOF
Usage: $PROG <image-ref>

Fails (exit 1) if <image-ref> leaks private-key or secret material.

Example:
  $PROG pqc-gw-management-api:latest
EOF
}

# ── argument / environment validation ────────────────────────────────────────
if [ $# -ne 1 ]; then
	usage >&2
	exit 2
fi
case "$1" in
	-h|--help) usage; exit 0 ;;
esac
IMAGE="$1"

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker not found in PATH" >&2
	exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
	echo "ERROR: image not found locally: $IMAGE" >&2
	exit 2
fi

# ── temp workspace + guaranteed cleanup ──────────────────────────────────────
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/scan-image-secrets.XXXXXX")"
CID=""
cleanup() {
	if [ -n "$CID" ]; then
		docker rm -f "$CID" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Header appears in binaries/docs too; a real key additionally has a base64 body
# framed by a matching END line. Two REs implement the two-stage detection.
HEADER_RE='-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----'
BLOCK_RE='-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{50,}\n-----END ([A-Z0-9]+ )?PRIVATE KEY-----'

FINDINGS=()
add_finding() { FINDINGS+=("$1"); }

echo "==> Scanning image for leaked secrets: $IMAGE"

# ── [A] build history ─────────────────────────────────────────────────────────
echo "--> [A] build history (docker history --no-trunc)"
# Same trap as the rootfs extraction below: if `docker history` fails, HISTORY is
# empty, this check finds nothing, and the section silently reports no findings.
# A scanner must not be able to pass a stage by failing it.
if ! HISTORY="$(docker history --no-trunc --format '{{.CreatedBy}}' "$IMAGE" 2>/dev/null)"; then
	echo "FATAL: 'docker history $IMAGE' failed — cannot scan build history." >&2
	echo "       Refusing to report a verdict on a check that did not run." >&2
	exit 2
fi
while IFS= read -r line; do
	[ -n "$line" ] || continue
	add_finding "build step embeds a private-key PEM: $(printf '%.120s' "$line")"
done < <(printf '%s\n' "$HISTORY" | grep -aE -- "$HEADER_RE" || true)

# ── [B] final filesystem (merged rootfs via docker export) ───────────────────
echo "--> [B] exporting final image filesystem (docker create + docker export)"
# Report WHY these fail. Under `set -e` a bare `docker create` / `docker export`
# aborts the script with exit 1 and no message, which is what happened in CI on
# 2026-08-04: the step logged "[B] exporting..." and then died silently after
# ~10s, giving nothing to diagnose. A scanner that fails without saying why is
# only marginally better than one that passes without looking.
if ! CID="$(docker create "$IMAGE" 2>&1)"; then
	echo "FATAL: docker create failed for ${IMAGE}" >&2
	echo "       ${CID}" >&2
	exit 3
fi
FS_TAR="$WORKDIR/fs.tar"
if ! _err="$(docker export "$CID" -o "$FS_TAR" 2>&1)"; then
	echo "FATAL: docker export failed for ${IMAGE} (container ${CID})" >&2
	echo "       ${_err}" >&2
	echo "       free space on $(dirname "$FS_TAR"): $(df -h "$(dirname "$FS_TAR")" | tail -1 | awk '{print $4}')" >&2
	docker rm -f "$CID" >/dev/null 2>&1 || true
	exit 3
fi
if [ ! -s "$FS_TAR" ]; then
	echo "FATAL: docker export produced an empty tar for ${IMAGE}" >&2
	docker rm -f "$CID" >/dev/null 2>&1 || true
	exit 3
fi
echo "    exported $(du -h "$FS_TAR" | cut -f1) rootfs tar"
docker rm "$CID" >/dev/null 2>&1 || true
CID=""

ROOTFS="$WORKDIR/rootfs"
mkdir -p "$ROOTFS"
# Extraction warnings (special files, ownership on a read-only host) are benign:
# we only ever read regular files back out, so ignore a non-zero tar exit.
tar -xf "$FS_TAR" -C "$ROOTFS" 2>/dev/null || true

# ...but a WHOLLY failed extraction must not read as a clean image. Every check
# below scans $ROOTFS; if it is empty they all find nothing and the script prints
# a pass. That is the worst possible failure mode for a secret scanner run before
# a repo goes public: it succeeds by not looking.
#
# Any container rootfs has thousands of files. 50 is a floor no real image can be
# under and no failed extraction can reach.
# No `head` here, deliberately. `find | head -100` makes find die of SIGPIPE the
# moment head has its 100 lines; under `set -o pipefail` that 141 propagates and
# `set -e` kills the script with no message. This scanner had NEVER completed a
# run because of it -- the guard against "succeeds by not looking" was itself
# failing by not looking. Counting every file costs milliseconds on a rootfs.
extracted=$(find "$ROOTFS" -type f 2>/dev/null | wc -l | tr -d " ")
if [ "$extracted" -lt 50 ]; then
	echo "FATAL: image filesystem extraction produced only ${extracted} files." >&2
	echo "       Refusing to report a verdict — an empty rootfs scans as clean." >&2
	exit 2
fi

echo "--> [B.1] real PEM private-key blocks (binaries skipped, mentions ignored)"
# Stage 1: text files that mention a private-key header. `grep -I` auto-skips
# binary files (shared libs embed the header as a format string).
while IFS= read -r f; do
	[ -n "$f" ] || continue
	# Stage 2: confirm an actual BEGIN..base64..END block, not a code/doc mention.
	if grep -aPzoq -- "$BLOCK_RE" "$f" 2>/dev/null; then
		add_finding "private key baked into image: /${f#"$ROOTFS"/}"
	fi
done < <(grep -rlIE -- "$HEADER_RE" "$ROOTFS" 2>/dev/null || true)

echo "--> [B.2] secret files baked under /secrets or /run/secrets"
while IFS= read -r f; do
	[ -n "$f" ] || continue
	add_finding "secret file baked under a secrets mountpoint: /${f#"$ROOTFS"/}"
done < <(find "$ROOTFS/secrets" "$ROOTFS/run/secrets" -type f 2>/dev/null || true)

echo "--> [B.3] known secret filenames anywhere in image"
while IFS= read -r f; do
	[ -n "$f" ] || continue
	add_finding "secret-looking key file baked into image: /${f#"$ROOTFS"/}"
done < <(find "$ROOTFS" -type f \( -name '*-hmac.key' -o -name 'gateway-signing*.key' \) 2>/dev/null || true)

# ── verdict ──────────────────────────────────────────────────────────────────
echo
if [ ${#FINDINGS[@]} -eq 0 ]; then
	echo "PASS: no private-key or secret material found in $IMAGE"
	exit 0
fi

echo "FAIL: $IMAGE leaks ${#FINDINGS[@]} secret item(s):"
for x in "${FINDINGS[@]}"; do
	echo "  - $x"
done
exit 1
