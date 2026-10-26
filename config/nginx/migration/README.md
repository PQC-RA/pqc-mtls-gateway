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

`GET /migration/inventory` on `:8081` needs the control-plane HMAC, as
`/update-routes` does: `X-Timestamp: <unix seconds>` and
`X-Hub-Signature-256: sha256=<hex HMAC-SHA256(control-plane-hmac,
"<timestamp>\nGET\n/migration/inventory\n")>`.

```sh
ts=$(date +%s)
sig=$(printf '%s\nGET\n/migration/inventory\n' "$ts" |
      openssl dgst -sha256 -hmac "$(cat secrets/control-plane-hmac.key)" -r | cut -d' ' -f1)
curl -s --cacert internal-tls-ca.crt -H "X-Timestamp: $ts" \
     -H "X-Hub-Signature-256: sha256=$sig" https://gateway:8081/migration/inventory
```

Counts are per request and best effort. A full inventory stops recording new
clients (logged once a minute) rather than dropping old ones.

## Know the limits

- **Policy per certificate needs the certificate.** Under
  `ssl_verify_client optional` a client may leave its certificate out; it is then
  identified by address and gets the `default` policy. Use
  `ssl_verify_client on`, or `"default": "pq-required"`, where that matters.
- **Revocation of classical client certificates is not handled yet.** The
  gateway's own CRL is checked on every request, by serial number. A customer
  CA's revocations are not, and its certificates are matched against the
  gateway's CRL by serial alone: a customer certificate whose serial equals a
  serial revoked by the gateway's CA is refused. `ssl_crl` would need every CA's
  CRL in one file, read only at reload, and refuses all clients of a CA once its
  CRL passes nextUpdate.
- **No session resumption.** The example turns it off: a resumed connection does
  not show which server certificate the session began with, so it is classified
  at most `pq-kex`. With resumption on, migrated clients would be refused by
  `pq-required` on every resumed connection.
