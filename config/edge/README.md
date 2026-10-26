# Edge box (stage 1 of an edge link)

An edge box sits beside a legacy device that cannot speak post-quantum TLS
(Modbus/TCP, IEC 60870-5-104, DNP3 over TCP, ...). The central gateway connects
to it over post-quantum mutual TLS; the box passes the plain connection on to
the device:

```
SCADA/historian -> central gateway :1502 (config/nginx/stream/)
                   ==TLS 1.3, X25519MLKEM768, ML-DSA-65 both sides, both verified==>
                   edge box :8502 (this directory) -> device :502 (plain)
```

The box runs the gateway image with `entrypoint.sh` from this directory as its
entrypoint (nginx with `/etc/pqc-edge/nginx.conf`, plus a watcher that reloads it
when the CRL or the allowed clients change). Mount this directory's `nginx.conf`
and `lua/` together with:

| File in `/etc/pqc-edge` | What |
|---|---|
| `edge-server.crt`, `edge-server.key` | the box's ML-DSA-65 certificate: `serverAuth`, SAN = the name the central side checks (`proxy_ssl_name`) |
| `central-ca.pem` | the ML-DSA-65 chain (root and intermediate) that issued the central gateway's client certificate, and nothing else (a classical CA here would let a classical chain through) |
| `central-crl.pem` | the CRLs of **every** CA in that chain, concatenated (the gateway's `hybrid-combined-crl.pem` form): nginx checks the whole chain, and a missing one refuses every handshake. Required (nginx does not start without it) and kept current: past nextUpdate every handshake is refused |
| `allowed-clients.txt` | SHA-256 fingerprints of the client certificates allowed through: one per line, 64 hex characters (`openssl x509 -in c.crt -outform DER \| sha256sum`, not the colon form of `-fingerprint`). The CA issues other client certificates too; only these reach the device. Absent, empty or unreadable: nobody. It is read by the worker processes (user `nobody`), so it must be readable by them, and re-read on `nginx -s reload`. |

Set the device's address in `proxy_pass` (an address, not a name: nginx resolves
a name once at start and will not start if it cannot; a changed address needs a
reload). `proxy_timeout` is an idle timer: a session quiet for longer is cut, so
set it above the protocol's poll interval. TCP keep-alive (`so_keepalive`,
`proxy_socket_keepalive`) finds half-open sessions after a link cut. Outside the
gateway's entrypoint nothing rotates `/var/log/nginx`; arrange it.

## Rules

- **The device must be reachable only through the box**: the box on two network
  ports, the device on its own segment. Otherwise the box adds an encrypted path,
  it does not protect the device. The test (`bench/edge/edge-link-test.sh`, E3)
  checks this.
- **Never in a control path for a first pilot.** Historian or read-only traffic,
  in parallel to the existing path. A refused handshake (expired certificate,
  wrong clock, a gateway down) must never cost control of a process.
- The segment from the box to the device stays plain.

## Revocation of open sessions

A stream session is checked once, at its handshake, and Modbus, IEC 104 or DNP3
sessions stay open for days. So a CRL change causes a reload, and after a reload
the old workers close what they still hold after `worker_shutdown_timeout`
(10 s here, 60 s on the central gateway); the clients reconnect and the revoked
identity is refused in the new handshake. Measured (`bench/edge/edge-link-test.sh`
R1, R2): a revoked box loses its open session 60 s after the central gateway's
reload, a revoked central identity 11 s after the box's CRL file changes. Every
session on that box or gateway reconnects once at each reload: plan for it. The
central gateway reloads whenever its own CRL changes, which is on every
revocation of any of its clients and once a day; the box, whenever
`central-crl.pem` changes.

Operating rules that follow:

- **Mount `/etc/pqc-edge` as a directory.** A single file bind-mounted on its own
  keeps its old content when it is replaced on the host, and the revocation is
  silently not enforced. The same holds for `edge-crl.pem` on the central side.
- **Deliver the CRL well inside its validity** (the gateway's intermediate CRL is
  valid for 7 days): a box that misses it refuses every new session.
- **Keep the box's clock synchronised.** OpenSSL allows no skew: a box running
  behind the CA rejects a fresh CRL (lastUpdate in the future) and refuses every
  new session until its clock catches up.

## Not in this stage

- Issuance and renewal of the box's `serverAuth` certificate through the gateway's
  custodian (it issues `clientAuth` only today).
- Stream-side telemetry beyond the access log; ARM64 packaging; TPM sealing of the
  key file.
