# Stream listeners (off by default)

This directory is mounted into the gateway at `/etc/nginx/stream`. Every `*.conf`
here is included inside `stream { }`; with none present, nothing changes.

`edge-link.conf.example` is the central side of an edge link: a plain TCP
listener for the SCADA or historian, carried over post-quantum mutual TLS to an
edge box (`config/edge/`). To enable:

1. Copy it to `edge-link.conf`; set the box's **address** in `proxy_pass` (a name
   that does not resolve at start stops the whole gateway from starting; a changed
   address needs a reload) and the name in its certificate in `proxy_ssl_name`.
2. Put here `central-client.crt` / `central-client.key` (ML-DSA-65, `clientAuth`;
   its SHA-256 fingerprint goes into the box's `allowed-clients.txt`) and
   `edge-ca.pem`: **a CA used for edge boxes only**, ML-DSA-65, nothing else in
   the file. If it is a CA that also issues other certificates (the gateway's
   enrollment CA, for instance), any of them carrying the box's name would pass
   as the box.
3. The listener is the plain end: bind it to the address the SCADA side reaches
   and admit only the SCADA hosts (`listen <address>:1502`, `allow`, `deny all`,
   as in the example), and publish the port only towards that side.

The gateway verifies the box (`proxy_ssl_verify on`, name, CA, ML-DSA-65 only);
without that anyone on the path could stand in for the box. Limits are listed in
`config/edge/README.md`.
