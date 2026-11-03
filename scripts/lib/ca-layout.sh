# shellcheck shell=bash
# shellcheck disable=SC2034  # the CA_* names are used by the scripts that source this
# ca-layout.sh: the one place that defines where CA key, CA state and the
# published CA files live, who owns them and with which modes (ADR-024).
# Sourced by scripts/migrate-ca-state.sh (and by setup-pki.sh once the
# cut-over lands). Every path is the same on the host and inside the container
# that mounts it, so the CA configuration's paths hold in both.
#
#   $CA_KEY_DIR     intermediate CA key           custodian only, read-only mount
#   $CA_STATE_DIR   index, serial, crlnumber,     custodian only, read-write
#                   issued/, certs/, crl/, the
#                   custodian's JSON state, the
#                   CA configuration
#   $CA_INBOX_DIR   root CRL from the offline     custodian only, read-only;
#                   root-CRL procedure            root writes it
#   $CA_PUBLIC_DIR  CA certificates, chains,      custodian writes; gateway,
#                   CRLs (DER at the URL names)   ocsp-pq, pki-dist read-only
#   $CA_STATUS_DIR  OCSP index snapshot           custodian writes; ocsp-pq reads
#   $OCSP_KEY_DIR   delegated OCSP key and cert   ocsp-pq only, read-only
#
# Nothing private is in a directory another container mounts, so no container
# needs an empty-directory mask.

CA_UID="${CA_UID:-1003}"          # the custodian's own uid and gid, shared with no other service
CA_GID="${CA_GID:-1003}"
OCSP_GID="${OCSP_GID:-1002}"      # ocsp-pq's uid and gid (docker-compose.yml)

CA_ROOT="${CA_ROOT:-/var/lib/pqc-ca}"
CA_KEY_DIR="$CA_ROOT/key"
CA_STATE_DIR="$CA_ROOT/state"
CA_INBOX_DIR="$CA_ROOT/inbox"
CA_PUBLIC_DIR="${CA_PUBLIC_DIR:-/var/lib/pqc-ca-public}"
CA_STATUS_DIR="${CA_STATUS_DIR:-/var/lib/pqc-ca-status}"
OCSP_KEY_DIR="${OCSP_KEY_DIR:-/var/lib/pqc-ocsp}"
# Public trust anchors only (ADR-024 §3, Rumen 2026-11-03): the internal TLS CA
# certificates that management-api and the gateway pin, root-owned, 0755/0644,
# mounted read-only as a directory. Not the custodian's; written by
# scripts/setup-pki.sh and scripts/internal-tls-switch.sh (scripts/lib/internal-tls.sh).
TRUST_DIR="${TRUST_DIR:-/etc/pki/pqc-trust}"

CA_KEY_FILE="$CA_KEY_DIR/intermediate-ca.key"
CA_CNF_FILE="$CA_STATE_DIR/openssl-intermediate.cnf"

# owner:group mode, per directory. The single source for both creating the
# layout and checking it. The status directory is setgid (2750): the custodian
# (gid 1003) writes the OCSP snapshot there and ocsp-pq (gid 1002) must read
# it, so every file it creates takes the directory's group. Found in the
# rehearsal on a copy of the live tree: without it the files were 1003:1003.
ca_layout_spec() {
    cat <<EOF
$CA_ROOT 0:0 0755
$CA_KEY_DIR $CA_UID:$CA_GID 0700
$CA_STATE_DIR $CA_UID:$CA_GID 0700
$CA_STATE_DIR/db $CA_UID:$CA_GID 0700
$CA_STATE_DIR/issued $CA_UID:$CA_GID 0700
$CA_STATE_DIR/certs $CA_UID:$CA_GID 0700
$CA_STATE_DIR/crl $CA_UID:$CA_GID 0700
$CA_INBOX_DIR 0:$CA_GID 0750
$CA_PUBLIC_DIR $CA_UID:$CA_GID 0755
$CA_STATUS_DIR $CA_UID:$OCSP_GID 2750
$OCSP_KEY_DIR 0:$OCSP_GID 0750
EOF
}

# Creates every directory of the layout with its owner and mode; existing
# directories are brought to the same owner and mode.
ca_layout_create() {
    local dir owner mode
    while read -r dir owner mode; do
        install -d -o "${owner%%:*}" -g "${owner##*:}" -m "$mode" "$dir"
    done < <(ca_layout_spec)
}

# Prints one line per directory whose owner or mode differs from the spec, or
# that is missing; returns 1 if there is any.
ca_layout_check() {
    local dir owner mode got bad=0
    while read -r dir owner mode; do
        if [ ! -d "$dir" ]; then echo "missing: $dir"; bad=1; continue; fi
        got=$(stat -c '%u:%g %a' "$dir")
        if [ "${got% *}" != "$owner" ] || [ $((8#${got#* })) != $((8#$mode)) ]; then
            echo "$dir: $got, expected $owner $mode"; bad=1
        fi
    done < <(ca_layout_spec)
    return "$bad"
}

# Sets owner and mode of the files inside the layout (directories come from
# the spec): key 0400, custodian state 0600, root CRL in the inbox 0640, public
# files 0644, status files 0640, OCSP key 0640 and certificate 0644.
ca_layout_file_perms() {
    find "$CA_KEY_DIR" "$CA_STATE_DIR" -type f -exec chown "$CA_UID:$CA_GID" {} + -exec chmod 0600 {} +
    [ -f "$CA_KEY_FILE" ] && chmod 0400 "$CA_KEY_FILE"
    find "$CA_INBOX_DIR" -type f -exec chown "0:$CA_GID" {} + -exec chmod 0640 {} +
    find "$CA_PUBLIC_DIR" -type f -exec chown "$CA_UID:$CA_GID" {} + -exec chmod 0644 {} +
    find "$CA_STATUS_DIR" -type f -exec chown "$CA_UID:$OCSP_GID" {} + -exec chmod 0640 {} +
    find "$OCSP_KEY_DIR" -type f -name '*.key' -exec chown "0:$OCSP_GID" {} + -exec chmod 0640 {} +
    find "$OCSP_KEY_DIR" -type f ! -name '*.key' -exec chown "0:$OCSP_GID" {} + -exec chmod 0644 {} +
}

# The custodian holds an exclusive lock on this file for as long as it runs.
# Anything that writes CA state from the host (migration, break-glass) takes
# it first and refuses if it cannot, so there is one writer at any moment.
CA_WRITER_LOCK="$CA_STATE_DIR/.writer.lock"

# Takes the writer lock on fd 9 without waiting; returns 1 if the custodian
# (or another host tool) holds it. The file belongs to the custodian: a host
# tool running as root that created it, or a file left root-owned 0644, would
# be one the custodian (uid 1003) cannot open, and it would refuse to start;
# so the owner and mode are set whether the file is new or not. The state
# directory is the custodian's, so a symbolic link here is refused outright:
# root would otherwise open, create or chown whatever it points at.
ca_take_writer_lock() {
    if [ -L "$CA_WRITER_LOCK" ] || { [ -e "$CA_WRITER_LOCK" ] && [ ! -f "$CA_WRITER_LOCK" ]; }; then
        echo "ERROR: $CA_WRITER_LOCK is not a regular file (a symbolic link?); refusing to use it" >&2
        exit 1
    fi
    [ -e "$CA_WRITER_LOCK" ] || install -m 0600 -o "$CA_UID" -g "$CA_GID" /dev/null "$CA_WRITER_LOCK"
    chown "$CA_UID:$CA_GID" "$CA_WRITER_LOCK"
    chmod 0600 "$CA_WRITER_LOCK"
    exec 9>>"$CA_WRITER_LOCK"
    flock -n 9
}

# ca_regular_tree PATH...: every entry under each PATH (and PATH itself) is a
# regular file or a directory, never a symbolic link, device or socket.
# Prints the offenders and returns 1 otherwise. Root reads CA state written
# by an unprivileged custodian: following a link there would copy whatever it
# points at (a CA key, any host file) across the trust boundary.
ca_regular_tree() {
    local p bad=""
    for p in "$@"; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        if [ -L "$p" ]; then bad="$bad $p"; continue; fi
        bad="$bad $(find "$p" ! -type f ! -type d -print | tr '\n' ' ')"
    done
    bad=$(echo "$bad" | xargs)
    [ -z "$bad" ] && return 0
    echo "not a regular file or directory: $bad" >&2
    return 1
}

# ca_refuse_unmigrated PKI_DIR: a deployment from before ADR-024 (the
# intermediate still in the shared tree, no custodian state) is not deployed
# over: this release's compose would mount empty layout directories, the
# custodian would crash-loop and the gateway would stop serving. The cut-over
# is the runbook's ordered steps (README, "The CA custodian becomes the only holder of the CA key"; the
# tool is scripts/migrate-ca-state.sh), not a deploy. Returns 1 with the
# reason on such a host.
ca_refuse_unmigrated() {
    if [ -d "$1/intermediate" ] && [ ! -d "$CA_STATE_DIR" ]; then
        echo "ERROR: $1/intermediate exists and $CA_STATE_DIR does not: this deployment predates ADR-024." >&2
        echo "  This release cannot be deployed over it; nothing was changed. Move it with the" >&2
        echo "  cut-over runbook (README, \"The CA custodian becomes the only holder of the CA key\")." >&2
        return 1
    fi
}
