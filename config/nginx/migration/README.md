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

1. Copy `listener.conf.example` to `listener.conf` and set the upstream, the port
   and `ssl_verify_client` (`on` if the service already required client
   certificates, else `optional`).
2. Put the service's existing classical server certificate and key here as
   `classical-server.crt` / `classical-server.key`.
3. Build `client-ca-bundle.pem`: the gateway's ML-DSA-65 chain
   (`/etc/pki/pqc-ca/hybrid-ca-chain.crt`) followed by the CA(s) that issued the
   service's existing classical client certificates. If you trust a classical CA
   and enable `ssl_crl`, its CRL must be in `crl-bundle.pem` too, or its clients
   are refused.
4. Optional: `policy.json` (see `policy.json.example`). Identities are
   `sha256:<64 hex of the client certificate>` or `ip:<address>` for clients
   without a certificate; `"default"` sets the policy for everyone else.
5. Publish the listener's port in the compose file and recreate the gateway.

The strict `:443` listener is not changed by any of this.
