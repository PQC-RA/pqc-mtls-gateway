# 2026-11-04: server-side files added later

Files from the gateway host for the 4 Nov campaign that were not in the first commit of this folder.

- `cert-sizes.csv`: DER sizes of root, intermediate, server, OCSP and device certificates with ML-DSA-65, ECDSA
  P-256 and RSA-2048 (the 4 Nov matched PKIs), and the ratios.
- `matched-bytes.tsv`: handshake bytes per arm with the matched PKIs (`s_client` totals).
- `throughput3_raw.txt`: `openssl s_time` windows per arm (connections per user second and per real second).
- `staple-vpn.pcap`: the capture behind `../live/staple-vpn.tcpdump.txt` (the stapled handshakes over the VPN).
  Addresses rewritten as described in `../../README.md`.
- `matrix-access.log`: the access log of the throwaway gateway used for the 2x2 enforcement matrix
  (`../stand/matrix/`).
- `ca-public/`: the public files of the throwaway CA of the issuance test (`../stand/issuance-check-removed/`):
  root and intermediate certificates, chains and CRLs. Its private keys were never copied.
