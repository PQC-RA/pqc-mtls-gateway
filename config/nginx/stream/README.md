# Stream listeners (off by default)

This directory is mounted into the gateway at `/etc/nginx/stream`. Every `*.conf`
here is included inside `stream { }`; with none present, nothing changes.

`edge-link.conf.example` is the central side of an edge link: a plain TCP
listener for the SCADA or historian, carried over post-quantum mutual TLS to an
edge box (`config/edge/`). To enable:

1. Copy it to `edge-link.conf`; set the box's **address** in `proxy_pass` (a name
   that does not resolve at start stops the whole gateway from starting) and the
   name in its certificate in `proxy_ssl_name`.
2. Put here `central-client.crt` / `central-client.key` (ML-DSA-65, `clientAuth`;
   its SHA-256 fingerprint goes into the box's `allowed-clients.txt`) and
   `edge-ca.pem` (the CA that issued the box's certificate).
3. Publish the listener's port only towards the SCADA side: it is the plain end.

The gateway verifies the box (`proxy_ssl_verify on`, name, CA, ML-DSA-65 only);
without that anyone on the path could stand in for the box. Limits are listed in
`config/edge/README.md`.
