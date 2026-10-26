# Migration listener (off by default)

This directory is mounted into the gateway at `/etc/nginx/migration`. Every
`*.conf` here is included inside `http { }`; with none present, the gateway runs
exactly as before.

The migration listener puts the gateway in front of an existing service under the
service's own name and port. Post-quantum clients get ML-DSA-65 and
X25519MLKEM768; classical clients get the service's classical certificate and a
classical group. Every connection is classified (`pq`, `pq-kex`, `classical`), the
class goes to the backend as `X-PQ-Class` and into the log, and an inventory per
client and endpoint is served at `https://<gateway>:8081/migration/inventory`
(control-plane listener). Nobody is refused for being classical unless
`policy.json` says `pq-required` for that client.

To enable:

1. Copy `listener.conf.example` to `listener.conf` and set `server_name`, the
   upstream, the port and `ssl_verify_client` (`on` if the service already
   required client certificates, else `optional`). The port must be the
   listener's own: never the gateway's `:443` or `:8443`, whose TLS settings it
   would otherwise share.
2. Put the service's existing classical server certificate and key here as
   `classical-server.crt` / `classical-server.key`.
3. Build `client-ca-bundle.pem`: the gateway's ML-DSA-65 chain
   (`/etc/pki/pqc-ca/hybrid-ca-chain.crt`) followed by the CA(s) that issued the
   service's existing classical client certificates.
4. Put the current CRL of each of those classical CAs, concatenated, in
   `crl-bundle.pem`, and keep it current (for example a cron job that fetches
   each CA's CRL distribution point). It is re-read within a second of a change,
   without a reload; each CRL is used only if its signature verifies against
   `client-ca-bundle.pem`. The gateway's own CRL is read from its usual place.
5. Optional: `policy.json` (see `policy.json.example`). Identities are
   `sha256:<64 hex of the client certificate>` or `ip:<address>` for clients
   without a certificate; `"default"` sets the policy for everyone else. A change
   takes effect at the next `nginx -s reload`.
6. Publish the listener's port in the compose file and recreate the gateway.

The strict `:443` listener is not changed by any of this.

## Reading the inventory

`GET /migration/inventory` on `:8081` needs an HMAC under the inventory's own
key, in the scheme `/update-routes` uses: `X-Timestamp: <unix seconds>` and
`X-Hub-Signature-256: sha256=<hex HMAC-SHA256(inventory key,
"<timestamp>\nGET\n/migration/inventory\n")>`. The key is
`inventory-hmac.key` in this directory (at least 16 bytes, mode 600, read once
at start, never the routing key); without it the inventory answers 503.

```sh
openssl rand -hex 32 > config/nginx/migration/inventory-hmac.key
chmod 600 config/nginx/migration/inventory-hmac.key
ts=$(date +%s)
sig=$(printf '%s\nGET\n/migration/inventory\n' "$ts" |
      openssl dgst -sha256 -hmac "$(cat config/nginx/migration/inventory-hmac.key)" -r | cut -d' ' -f1)
curl -s --cacert internal-tls-ca.crt -H "X-Timestamp: $ts" \
     -H "X-Hub-Signature-256: sha256=$sig" https://gateway:8081/migration/inventory
```

Counts are per request and best effort. A full inventory stops recording new
clients (logged once a minute) rather than dropping old ones.

## Know the limits

- **Every client that offers ML-DSA gets the ML-DSA-65 certificate, and must
  trust its root.** OpenSSL picks the certificate from the signature algorithms
  the client offers, not from what it trusts. Current Chromium offers
  `mldsa44/65/87` first: with the gateway's CA in its trust store it is served
  fully post-quantum; without it, it fails with `ERR_CERT_AUTHORITY_INVALID`,
  although the classical certificate is there. OpenSSL 3.5+ clients behave the
  same way. So put the ML-DSA-65 certificate only on names whose clients have
  been given its root (machine-to-machine APIs, managed fleets); a name that
  browsers or other unmanaged clients reach gets a listener with the classical
  certificate alone, and is still classified and inventoried.

- **Policy per certificate needs the certificate.** Under
  `ssl_verify_client optional` a client may leave its certificate out; it is then
  identified by address and gets the `default` policy. Use
  `ssl_verify_client on`, or `"default": "pq-required"`, where that matters.
- **Revocation is only as fresh as `crl-bundle.pem`.** Every request is checked
  against the CRL of its certificate's issuer (by issuer and serial). A client
  certificate is refused with 403 when it is revoked (`certificate_revoked`),
  when its issuer has no usable CRL (`no_crl_for_issuer`; set
  `$pqc_migration_crl_required off` to accept such clients knowingly), or when
  its issuer's CRL is past nextUpdate or has none (`crl_stale`;
  `$pqc_migration_crl_stale accept` to accept knowingly). A revocation, once
  loaded, is never dropped until the gateway restarts. OCSP for client
  certificates is not consulted. What is loaded, per issuer, is listed under
  `crls` in the inventory. The same holds for the gateway's own CRL: if the
  crl-renewer stops, its clients are refused here once that CRL passes
  nextUpdate, as on the strict listeners.
- **What counts as a usable CRL.** A full CRL (a delta CRL alone is read as
  complete), signed by the CA itself, whose certificate is in
  `client-ca-bundle.pem`, intermediates included, even if clients also send
  them. Only the client's own certificate is checked: withdraw a compromised
  intermediate by removing it from the bundle. If the bundle holds two CA
  certificates with the same name (a key rolled over under the same name),
  that name has no usable CRL and its clients are refused until one of the two
  is removed. If a CRL's revocations do not all fit in `lua_shared_dict
  migration_crl` (about 4,000 per MB, 32 MB in `nginx.conf`), its issuer has no
  usable CRL.
- **Upgrading from the first version of this listener** (no CRL handling): with
  no `crl-bundle.pem`, every client certificate from a customer CA is now
  refused (`no_crl_for_issuer`). Add the CRLs, or set
  `$pqc_migration_crl_required off` knowingly.
- **No session resumption.** The example turns it off: a resumed connection does
  not show which server certificate the session began with, so it is classified
  at most `pq-kex`. With resumption on, migrated clients would be refused by
  `pq-required` on every resumed connection.
