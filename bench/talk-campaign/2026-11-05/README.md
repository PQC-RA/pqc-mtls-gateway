# 2026-11-05: three checks (CPU, a Mac client's chain, Java 25 and 27)

Nothing live was changed. Throwaway private keys were deleted after the runs; none is here.

## `cpu-matched-99/`: CPU per handshake, matched arms

`openssl s_time` 3.6.5, client side, one core, on the gateway host's loopback test ports (not the live ports),
with the 4 Nov matched PKIs: ML-DSA-65 with X25519MLKEM768 against ECDSA P-256 with X25519. Session tickets and
cache off; three 10 s windows per arm, interleaved (`cpu.sh`, `cpu.txt`). Result: 2.018 ms against 0.662 ms of
client CPU per handshake (3.05x).

## `mac-client-chain-27/`: a Mac client's full chain costs a round trip

Client: a Mac (macOS 27.0.1), Homebrew curl 8.20.0 on OpenSSL 3.6.2, over the WireGuard VPN. Server:
`openssl s_server` 3.6.5 on the test stand with a throwaway ML-DSA-65 PKI, X25519MLKEM768, client certificate
required, tickets off (`setup.sh`, `run.sh`). Delay: `tc netem` on the stand for the test port only, giving
round trips of 5, 34 and 70 ms. 20 samples per arm per delay, arms interleaved. Time to the first response byte
(`time_starttransfer`), so the client's own flight is included. Result: sending the full chain instead of the
leaf costs about one round trip once the round trip is long enough (+32 ms at 34 ms, +69 ms at 70 ms); the leaf
alone does not. `cap.pcap` is the stand's capture.

## `java-25-27/`: Java 25 and 27 against the live gateway

`T.java` from the campaign (negotiation only: trusts any server certificate, sends no client certificate) in
`eclipse-temurin:25-jdk` (25.0.5) and `eclipse-temurin:27-jdk` (27), from the test stand to the live gateway's
:8443 and :443. All four handshakes were refused (`handshake_failure`). The gateway logged
`reason=no_pq_sigalg` (`gateway-handshake-log.txt`): both versions offer X25519MLKEM768 but no ML-DSA signature
scheme.
