#!/usr/bin/env bash
# envoy-pqc-probe.sh: can a service-mesh data plane do post-quantum authentication?
#
# WHY THIS EXISTS: service meshes are how mutual TLS reaches scale, and their
# data plane is almost always Envoy. If Envoy cannot handle ML-DSA certificates
# then PQ mutual authentication is unavailable there whatever the PKI above it,
# and a native-OpenSSL edge is the workable path rather than a stopgap. That is
# a claim about someone else's software, so it is measured, dated and scripted
# rather than asserted.
#
# THREE CAPABILITIES, MEASURED SEPARATELY. They are different code paths and a
# single "does Envoy work" answer hides which one fails:
#   A  present downstream , Envoy serves TLS with an ML-DSA-65 server cert
#   B  present upstream:    Envoy offers an ML-DSA-65 client cert to an upstream
#   C  validate:            Envoy trusts an ML-DSA-65 CA and verifies a real
#                            client certificate over a live handshake
#
# EVERY TEST HAS A CLASSICAL CONTROL, and the control MUST pass. Certificates
# come from mk-matched-pki.sh, so the arms differ in the signature algorithm and
# in nothing else: same distinguished names, same pinned serials, same extension
# set, same PKCS#8 key container, same file permissions. Without that control
# this probe reports configuration mistakes as cryptographic findings, which is
# exactly what happened on the first run here, where root-only key files made
# BOTH arms fail and briefly looked like an ML-DSA result.
#
# Usage:
#   ./envoy-pqc-probe.sh                       # default version list
#   ENVOY_TAGS="v1.39-latest" ./envoy-pqc-probe.sh
set -uo pipefail

PKI=${PKI:-$(cd "$(dirname "$0")/.." && pwd)/pki}
OUT=${OUT:-$(cd "$(dirname "$0")" && pwd)/results/envoy}
ENVOY_TAGS=${ENVOY_TAGS:-"v1.35-latest v1.37-latest v1.39-latest"}
OSSL=${OSSL:-$([ -x /opt/openssl/bin/openssl ] && echo /opt/openssl/bin/openssl || echo /opt/openssl-3.6.2/bin/openssl)}
PORT=${PORT:-10443}

for f in "$PKI/pqc/server.crt" "$PKI/classical/server.crt" "$PKI/pqc/client.crt"; do
  [ -f "$f" ] || { echo "ERROR: $f missing, run mk-matched-pki.sh first" >&2; exit 1; }
done
command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }

mkdir -p "$OUT"
LOG="$OUT/envoy-probe.txt"; : > "$LOG"
say(){ echo "$@" | tee -a "$LOG"; }

# Envoy runs as uid 101 and mounts are read-only, so the material is staged in a
# world-readable copy. This is a harness concern, not a security one: these are
# throwaway benchmark keys, never the deployment's.
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"; docker rm -f envoy-probe >/dev/null 2>&1 || true' EXIT
cp "$PKI/pqc/server.crt" "$STAGE/pq.crt";  $OSSL pkcs8 -topk8 -nocrypt -in "$PKI/pqc/server.key"       -out "$STAGE/pq.key" 2>/dev/null
cp "$PKI/classical/server.crt" "$STAGE/cl.crt"; $OSSL pkcs8 -topk8 -nocrypt -in "$PKI/classical/server.key" -out "$STAGE/cl.key" 2>/dev/null
cp "$PKI/pqc/ca-chain.crt" "$STAGE/pq-ca.crt"; cp "$PKI/classical/ca-chain.crt" "$STAGE/cl-ca.crt"
cp "$PKI/pqc/client.crt" "$STAGE/pq-client.crt"; cp "$PKI/pqc/client.key" "$STAGE/pq-client.key"
cp "$PKI/classical/client.crt" "$STAGE/cl-client.crt"; cp "$PKI/classical/client.key" "$STAGE/cl-client.key"
# mktemp -d yields mode 0700, so uid 101 cannot traverse into the mount however
# readable the files themselves are. Both the directory and its contents matter.
chmod 755 "$STAGE"; chmod 644 "$STAGE"/*

# ---------------------------------------------------------------- config shapes
cfg_downstream(){ # cfg_downstream <crt> <key>
cat <<EOF
static_resources:
  listeners:
  - name: l
    address: {socket_address: {address: 0.0.0.0, port_value: $PORT}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: t
          route_config: {virtual_hosts: [{name: v, domains: ["*"], routes: [{match: {prefix: "/"}, direct_response: {status: 200, body: {inline_string: "ok"}}}]}]}
          http_filters: [{name: envoy.filters.http.router, typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}]
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates: [{certificate_chain: {filename: /c/$1}, private_key: {filename: /c/$2}}]
EOF
}

cfg_upstream(){ # cfg_upstream <crt> <key> , Envoy as a CLIENT presenting a cert
cat <<EOF
static_resources:
  clusters:
  - name: up
    connect_timeout: 1s
    type: STATIC
    load_assignment: {cluster_name: up, endpoints: [{lb_endpoints: [{endpoint: {address: {socket_address: {address: 127.0.0.1, port_value: 9999}}}}]}]}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          tls_certificates: [{certificate_chain: {filename: /c/$1}, private_key: {filename: /c/$2}}]
EOF
}

cfg_validate(){ # cfg_validate <server-crt> <server-key> <trusted-ca>
cat <<EOF                       # server cert always CLASSICAL: isolates validation
static_resources:
  listeners:
  - name: l
    address: {socket_address: {address: 0.0.0.0, port_value: $PORT}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: t
          route_config: {virtual_hosts: [{name: v, domains: ["*"], routes: [{match: {prefix: "/"}, direct_response: {status: 200, body: {inline_string: "ok"}}}]}]}
          http_filters: [{name: envoy.filters.http.router, typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}]
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates: [{certificate_chain: {filename: /c/$1}, private_key: {filename: /c/$2}}]
            validation_context: {trusted_ca: {filename: /c/$3}}
EOF
}

# ---------------------------------------------------------------- runner
# Returns: STARTED | the first "Failed to ..." line Envoy emitted.
#
# Deterministic by construction: run in the FOREGROUND under `timeout`. Envoy
# either rejects the configuration and exits within a second, or serves until
# the timeout kills it. Exit 124 therefore means "it started"; anything else
# means it gave up, and the reason is in its own output. An earlier version
# backgrounded the container and read `docker logs` after a sleep, which raced
# and produced control failures that were artefacts of the harness.
try_start(){ # try_start <tag> <configfile> [<seconds>]
  local tag=$1 cfgf=$2 secs=${3:-6} out rc
  docker rm -f envoy-probe >/dev/null 2>&1
  out=$(timeout --signal=KILL "$secs" docker run --rm --name envoy-probe --network host \
        -v "$STAGE:/c:ro" -v "$cfgf:/etc/envoy/envoy.yaml:ro" \
        "envoyproxy/envoy:$tag" -c /etc/envoy/envoy.yaml --log-level warn 2>&1); rc=$?
  docker rm -f envoy-probe >/dev/null 2>&1
  if [ "$rc" -eq 137 ] || [ "$rc" -eq 124 ]; then printf 'STARTED'; return; fi
  local msg; msg=$(printf '%s' "$out" | grep -oE 'Failed to [^`]*' | head -1)
  printf '%s' "${msg:-exited rc=$rc}"
}

say "=============================================================="
say " Envoy post-quantum authentication probe, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say " certificates: mk-matched-pki.sh (identical DNs, serials, extensions)"
say " tags: $ENVOY_TAGS"
say "=============================================================="

fail=0
for tag in $ENVOY_TAGS; do
  docker pull -q "envoyproxy/envoy:$tag" >/dev/null 2>&1 || { say "  $tag: pull failed, skipped"; continue; }
  ver=$(docker run --rm "envoyproxy/envoy:$tag" --version 2>&1 | grep -oE '1\.[0-9]+\.[0-9]+' | head -1)
  stack=$(docker run --rm "envoyproxy/envoy:$tag" --version 2>&1 | grep -oE '(BoringSSL|OpenSSL)' | head -1)
  say
  say "### Envoy $ver ($stack)"

  # --- A: present downstream --------------------------------------------------
  cfg_downstream cl.crt cl.key > "$STAGE/a-cl.yaml"; ctl=$(try_start "$tag" "$STAGE/a-cl.yaml")
  cfg_downstream pq.crt pq.key > "$STAGE/a-pq.yaml"; pqc=$(try_start "$tag" "$STAGE/a-pq.yaml")
  say "  A present downstream   classical: $ctl"
  say "                         ML-DSA-65: $pqc"
  [ "$ctl" = "STARTED" ] || { say "  *** CONTROL FAILED, this run proves nothing about ML-DSA ***"; fail=1; }

  # --- B: present upstream ----------------------------------------------------
  cfg_upstream cl-client.crt cl-client.key > "$STAGE/b-cl.yaml"; ctl=$(try_start "$tag" "$STAGE/b-cl.yaml")
  cfg_upstream pq-client.crt pq-client.key > "$STAGE/b-pq.yaml"; pqc=$(try_start "$tag" "$STAGE/b-pq.yaml")
  say "  B present upstream     classical: $ctl"
  say "                         ML-DSA-65: $pqc"
  [ "$ctl" = "STARTED" ] || { say "  *** CONTROL FAILED ***"; fail=1; }

  # --- C: validate ------------------------------------------------------------
  # Server certificate is CLASSICAL in both arms so only the trust store varies.
  cfg_validate cl.crt cl.key cl-ca.crt > "$STAGE/c-cl.yaml"; ctl=$(try_start "$tag" "$STAGE/c-cl.yaml")
  cfg_validate cl.crt cl.key pq-ca.crt > "$STAGE/c-pq.yaml"; pqc=$(try_start "$tag" "$STAGE/c-pq.yaml")
  say "  C validate (trust ML-DSA CA)"
  say "                         classical CA: $ctl"
  say "                         ML-DSA-65 CA: $pqc"
  [ "$ctl" = "STARTED" ] || { say "  *** CONTROL FAILED ***"; fail=1; }

  # Accepting the trust store at config load is NOT the same as being able to
  # verify a peer with it. Probe the live handshake, and probe the classical one
  # too: if the classical handshake does not succeed, the probe is broken and
  # the post-quantum result means nothing.
  handshake(){ # handshake <configfile> <client-crt> <client-key> -> "<curl-code> <detail>"
    local cfgf=$1 crt=$2 key=$3 code err
    docker rm -f envoy-probe >/dev/null 2>&1
    docker run -d --rm --name envoy-probe --network host -v "$STAGE:/c:ro" \
      -v "$cfgf:/etc/envoy/envoy.yaml:ro" "envoyproxy/envoy:$tag" \
      -c /etc/envoy/envoy.yaml --log-level warn >/dev/null 2>&1
    # wait for the listener rather than sleeping a guessed interval
    for _ in $(seq 1 25); do
      (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && { exec 3<&- 3>&-; break; }
      sleep 0.4
    done
    err=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 \
          --cert "$crt" --key "$key" "https://127.0.0.1:$PORT/" 2>&1)
    code=$(printf '%s' "$err" | tail -c 3)
    printf '%s' "$code"
    docker rm -f envoy-probe >/dev/null 2>&1
  }
  if [ "$pqc" = "STARTED" ]; then
    cl_hs=$(handshake "$STAGE/c-cl.yaml" "$STAGE/cl-client.crt" "$STAGE/cl-client.key")
    pq_hs=$(handshake "$STAGE/c-pq.yaml" "$STAGE/pq-client.crt" "$STAGE/pq-client.key")
    say "                         live handshake, classical client: HTTP $cl_hs"
    say "                         live handshake, ML-DSA-65 client: HTTP $pq_hs"
    if [ "$cl_hs" != "200" ]; then
      say "  *** HANDSHAKE CONTROL FAILED, the ML-DSA handshake result is not usable ***"
      fail=1
    fi
  else
    say "                         live handshake: not attempted (trust store refused)"
  fi
done

say
say "Legend: STARTED = Envoy accepted the configuration. Anything else is the"
say "first failure it reported. A classical control that does not say STARTED"
say "invalidates its row: the cause is the harness, not the algorithm."
say
say "evidence -> $LOG"
[ $fail -eq 0 ] || { say "*** at least one control failed, do not cite this run ***"; exit 1; }
