# 2026-11-07, test stand: where the CPU goes, and the header size

`cpusplit.sh` on the test stand; nothing live contacted. The twin PKIs are rebuilt with `../stand/mkpki.sh` (new
keys, the live certificate profile); every private key was deleted at the end. OpenSSL 3.6.5; servers in the
gateway image (OpenResty 1.31.8.1) with the live gateway's TLS settings (`nginx-cpusplit.conf`).

## Files

- `speed.txt`: `openssl speed -seconds 5 ML-DSA-65 ML-KEM-768 ecdsap256 ecdhx25519`, 3 runs.
- `cpu.txt`, `check.txt`: `openssl s_time`, client side, 3 windows of 10 s per arm, alternating. Arms: hybrid
  (X25519MLKEM768 + ML-DSA-65, as live), pure (MLKEM768 + ML-DSA-65), classical (X25519 + ECDSA P-256). Each client
  offers only its arm's group (`client-*.cnf`). `check.txt`: one `s_client` per arm (group, peer signature,
  verification, bytes).
- `header-sizes.tsv`: 200 ML-DSA-65 device certificates with the live profile: DER, PEM and URL-encoded sizes.
- `header-test.tsv`: the smallest and largest URL-encoded certificate sent as a header to an nginx with default
  header buffers, the SHA-256 fingerprint instead, and synthetic values. `hdr-min.txt`, `hdr-max.txt`: those two
  URL-encoded certificates (public data).

## Results

- Single operations (medians of 3 runs): ML-DSA-65 sign 0.827 ms, verify 0.157 ms; ML-KEM-768 key generation
  0.033 ms, encapsulation 0.018 ms, decapsulation 0.029 ms; ECDSA P-256 sign 0.018 ms, verify 0.057 ms.
- Client CPU per handshake (mean of 3 windows): hybrid 2.052 ms, pure 1.921 ms, classical 0.594 ms. The X25519
  part of the hybrid adds about 7 %.
- Header: all 200 certificates are 5,617 B as DER and 7,664 B as PEM; URL-encoded they are 8,276 to 8,426 B
  (the number of `+`, `/` and `=` characters varies with the key and signature). Both the smallest and the
  largest are refused (HTTP 400) by nginx's default 4 x 8 KB header buffers; the 64-character fingerprint passes.
  Synthetic header values pass up to 8,180 B and fail at 8,200 B.
