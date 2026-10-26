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
4. Optional: `policy.json` (see `policy.json.example`). Identities are
   `sha256:<64 hex of the client certificate>` or `ip:<address>` for clients
   without a certificate; `"default"` sets the policy for everyone else. A change
   takes effect at the next `nginx -s reload`.
5. Publish the listener's port in the compose file and recreate the gateway.

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
- **Revocation of classical client certificates is not handled yet.** A
  certificate the customer's CA has revoked is still accepted here and reaches
  the backend with `X-Client-Verify: SUCCESS`. Do not trust a customer CA in
  `client-ca-bundle.pem` if you may need to revoke its certificates before this
  is fixed. The gateway's own CRL is checked on every request, by serial number
  alone, so a customer certificate whose serial equals one the gateway's CA
  revoked is refused. `ssl_crl` is no way out: it needs every CA's CRL in one
  file, is read only at reload, and refuses all clients of a CA once its CRL
  passes nextUpdate.
- **No session resumption.** The example turns it off: a resumed connection does
  not show which server certificate the session began with, so it is classified
  at most `pq-kex`. With resumption on, migrated clients would be refused by
  `pq-required` on every resumed connection.
