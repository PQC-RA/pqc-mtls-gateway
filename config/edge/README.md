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

The box runs the gateway image with `nginx -c /etc/pqc-edge/nginx.conf`. Mount
this directory's `nginx.conf` and `lua/` together with:

| File in `/etc/pqc-edge` | What |
|---|---|
| `edge-server.crt`, `edge-server.key` | the box's ML-DSA-65 certificate: `serverAuth`, SAN = the name the central side checks (`proxy_ssl_name`) |
| `central-ca.pem` | the ML-DSA-65 CA that issued the central gateway's client certificate, and nothing else (a classical CA here would let a classical chain through) |
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

## Not in this stage

- **Revocation that closes live sessions.** A stream session is checked once, at
  the handshake; Modbus, IEC 104 and DNP3 sessions stay open for days. Until this
  exists, revoking a certificate stops new sessions only.
- Issuance and renewal of the box's `serverAuth` certificate through the gateway's
  custodian (it issues `clientAuth` only today).
- Stream-side telemetry beyond the access log; ARM64 packaging; TPM sealing of the
  key file.
