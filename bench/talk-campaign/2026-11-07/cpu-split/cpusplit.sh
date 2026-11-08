#!/bin/bash
# 2026-11-07, test stand .27, nothing live: slide 8's "where the CPU goes" and slide 10's header size, re-run.
# (1) openssl speed: one ML-DSA-65 signature and verification, ML-KEM-768, ECDSA P-256, X25519; 3 runs.
# (2) CPU per handshake, client side (openssl s_time, as on 31 Oct and 4 Nov), against servers with the live
#     gateway's TLS settings; three arms that differ only in the key exchange or the algorithm:
#       hybrid    X25519MLKEM768 + ML-DSA-65 (what live runs)
#       pure      MLKEM768       + ML-DSA-65 (the same without the X25519 hedge)
#       classical X25519         + ECDSA P-256
#     The client offers only its arm's group (OPENSSL_CONF per arm), so no arm pays for an unused key share.
#     3 windows of 10 s per arm, the arms alternating.
# (3) Header size: 200 device certificates with the live profile, DER and URL-encoded sizes; the smallest and
#     largest sent to an nginx with default header buffers.
set -euo pipefail
O=/opt/openssl-3.6.5/bin/openssl; export OPENSSL_CONF=/etc/ssl/openssl.cnf
W=/root/cpusplit-20261107; mkdir -p $W; cd $W
IMG=clean1-gateway:11a5422
{ echo "# $(date -u +%FT%TZ) $(hostname) $(uname -r) $($O version)"; lscpu | grep "Model name"; nproc; uptime; } > env.txt

# ---- PKI: the re-run's twin PKIs with the live profile, rebuilt here (new keys)
sed "s#^W=/root/rerun-20261107/pki#W=$W/pki#" /root/rerun-20261107/mkpki.sh > mkpki.sh
bash mkpki.sh > mkpki.out 2>&1

# ---- (1) primitives
: > speed.txt
for r in 1 2 3; do echo "=== run $r $(date -u +%FT%TZ)" >> speed.txt
  $O speed -seconds 5 ML-DSA-65 ML-KEM-768 ecdsap256 ecdhx25519 2>/dev/null | grep -E "ML-|ecdsa|ecdh|sign|op " >> speed.txt; done

# ---- (2) servers
cat > nginx-cpusplit.conf <<'X'
# The live gateway's :443 TLS settings, as in the re-run's nginx.conf; one server per arm.
worker_processes 1;
pid /tmp/cpusplit-nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 1024; }
http {
    access_log off;
    ssl_session_tickets on;
    ssl_session_timeout 5m;
    client_body_temp_path /tmp/cs_body; proxy_temp_path /tmp/cs_proxy; fastcgi_temp_path /tmp/cs_fcgi;
    uwsgi_temp_path /tmp/cs_uwsgi; scgi_temp_path /tmp/cs_scgi;
    server {                                   # hybrid: as live
        listen 127.0.0.1:31451 ssl; http2 on; server_name pqc-gw.local;
        ssl_certificate /r/pki/pq/server.crt; ssl_certificate_key /r/pki/pq/server.key;
        ssl_verify_client on; ssl_client_certificate /r/pki/pq/ca-chain.crt; ssl_verify_depth 2;
        ssl_protocols TLSv1.3;
        ssl_conf_command Groups X25519MLKEM768;
        ssl_conf_command ClientSignatureAlgorithms ML-DSA-65;
        location / { return 404; }
    }
    server {                                   # pure: the same without the X25519 hedge
        listen 127.0.0.1:31452 ssl; http2 on; server_name pqc-gw.local;
        ssl_certificate /r/pki/pq/server.crt; ssl_certificate_key /r/pki/pq/server.key;
        ssl_verify_client on; ssl_client_certificate /r/pki/pq/ca-chain.crt; ssl_verify_depth 2;
        ssl_protocols TLSv1.3;
        ssl_conf_command Groups MLKEM768;
        ssl_conf_command ClientSignatureAlgorithms ML-DSA-65;
        location / { return 404; }
    }
    server {                                   # classical twin
        listen 127.0.0.1:31453 ssl; http2 on; server_name pqc-gw.local;
        ssl_certificate /r/pki/cl/server.crt; ssl_certificate_key /r/pki/cl/server.key;
        ssl_verify_client on; ssl_client_certificate /r/pki/cl/ca-chain.crt; ssl_verify_depth 2;
        ssl_protocols TLSv1.3;
        ssl_conf_command Groups X25519;
        ssl_conf_command ClientSignatureAlgorithms ECDSA+SHA256;
        location / { return 404; }
    }
    server {                                   # (3) header test: no large_client_header_buffers, nginx's default 4 8k
        listen 127.0.0.1:31460; location / { return 200 "ok\n"; }
    }
}
X
for g in X25519MLKEM768 MLKEM768 X25519; do
  printf 'openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = sys\n[sys]\nGroups = %s\n' $g > client-$g.cnf
done
docker rm -f cpusplit-nginx >/dev/null 2>&1 || true
docker run -d --name cpusplit-nginx --network host -v $W:/r:ro --entrypoint nginx $IMG -c /r/nginx-cpusplit.conf -g "daemon off;" >/dev/null
sleep 2
echo "# server: $(docker exec cpusplit-nginx nginx -v 2>&1) in $IMG" >> env.txt
arms="hybrid:31451:pq:X25519MLKEM768 pure:31452:pq:MLKEM768 classical:31453:cl:X25519"
: > check.txt
for a in $arms; do IFS=: read n p d g <<<"$a"
  printf "%s\t" $n >> check.txt
  echo | OPENSSL_CONF=$W/client-$g.cnf $O s_client -connect 127.0.0.1:$p -servername pqc-gw.local -cert pki/$d/device.crt \
    -key pki/$d/device.key -verifyCAfile pki/$d/ca-chain.crt -verify_return_error 2>&1 | \
    awk '/^Negotiated TLS1.3 group/{g=$4} /^Peer signature type/{s=$4} /^Verification:/{v=$2} /SSL handshake has read/{r=$5; w=$9} END{print g"\t"s"\t"v"\t"r"\t"w}' >> check.txt
done
echo "--- openssl s_time, client side, no delay, 3 x 10 s per arm, alternating" > cpu.txt
for w in 1 2 3; do for a in $arms; do IFS=: read n p d g <<<"$a"
  echo "=== $n window $w $(date -u +%FT%TZ)" >> cpu.txt
  OPENSSL_CONF=$W/client-$g.cnf $O s_time -connect 127.0.0.1:$p -new -time 10 -cert pki/$d/device.crt \
    -key pki/$d/device.key -CAfile pki/$d/ca-chain.crt >> cpu.txt 2>&1
done; done

# ---- (3) header size
python3 -I - "$O" "$W" <<'P'
import os, subprocess, sys, urllib.parse
O, W = sys.argv[1:3]
env = dict(os.environ, OPENSSL_CONF="/etc/ssl/openssl.cnf")
d = os.path.join(W, "hdr"); os.makedirs(d, exist_ok=True)
rows = []
for i in range(200):
    k, c, x = (os.path.join(d, f"dev{i}.{e}") for e in ("key", "csr", "crt"))
    run = lambda a: subprocess.run([O] + a, env=env, check=True, capture_output=True)
    run(["genpkey", "-algorithm", "ML-DSA-65", "-out", k])
    run(["req", "-new", "-key", k, "-subj", "/CN=rerun-device1", "-out", c])
    run(["x509", "-req", "-in", c, "-CA", f"{W}/pki/pq/int.crt", "-CAkey", f"{W}/pki/pq/int.key", "-days", "30",
         "-set_serial", str(0x108D + i), "-extfile", f"{W}/pki/ext.cnf", "-extensions", "device", "-out", x])
    pem = open(x).read()
    der = len(subprocess.run([O, "x509", "-in", x, "-outform", "DER"], env=env, capture_output=True).stdout)
    rows.append((i, der, len(pem.encode()), len(urllib.parse.quote(pem, safe=""))))
    os.remove(k); os.remove(c)
with open(os.path.join(W, "header-sizes.tsv"), "w") as f:
    f.write("i\tder_bytes\tpem_bytes\turlencoded_bytes\n")
    for r in rows:
        f.write("%d\t%d\t%d\t%d\n" % r)
u = sorted(r[3] for r in rows)
print("urlencoded: min %d median %d max %d; DER %s" % (u[0], u[len(u) // 2], u[-1], sorted({r[1] for r in rows})))
lo = min(rows, key=lambda r: r[3]); hi = max(rows, key=lambda r: r[3])
for tag, r in (("min", lo), ("max", hi)):
    open(os.path.join(W, f"hdr-{tag}.txt"), "w").write(urllib.parse.quote(open(os.path.join(d, f"dev{r[0]}.crt")).read(), safe=""))
P
{ printf "header\tvalue_bytes\thttp\n"
  for t in min max; do H=$(cat hdr-$t.txt)
    printf "X-SSL-Client-Cert (URL-encoded, %s of 200)\t%d\t%s\n" $t ${#H} $(curl -s -o /dev/null -w '%{http_code}' -H "X-SSL-Client-Cert: $H" http://127.0.0.1:31460/); done
  F=$(sha256sum < hdr/dev0.crt | cut -c1-64)
  printf "X-SSL-Client-Fingerprint (SHA-256)\t%d\t%s\n" ${#F} $(curl -s -o /dev/null -w '%{http_code}' -H "X-SSL-Client-Fingerprint: $F" http://127.0.0.1:31460/)
  for n in 8000 8150 8170 8180 8200; do V=$(head -c $n /dev/zero | tr '\0' a)
    printf "synthetic\t%d\t%s\n" $n $(curl -s -o /dev/null -w '%{http_code}' -H "X: $V" http://127.0.0.1:31460/); done; } > header-test.tsv

docker rm -f cpusplit-nginx >/dev/null
find $W -name '*.key' -delete
echo "keys left: $(find $W -name '*.key' | wc -l)" >> env.txt
cat check.txt; grep -E "^===|connections/user" cpu.txt; cat header-test.tsv
