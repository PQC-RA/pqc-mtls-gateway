# real-clients.sh: real classical client stacks against the migration listener.
# Sourced by migration-listener-test.sh when REAL_CLIENTS=1, after its case 9, so
# the throwaway gateway is up and the customer-CA client certificate is under
# pq-required. Uses W, H, P_MIG, NAME, PKI_DIR, O and check from that script.
#
# Images (pulled beforehand; the test does not pull):
#   python:3.9-slim-bullseye   CPython ssl on OpenSSL 1.1.1
#   python:3.11-slim-bookworm  CPython ssl on OpenSSL 3.0
#   eclipse-temurin:21-jdk     Java 21 JSSE (HttpsURLConnection)
#   curlimages/curl            curl on OpenSSL 3.5 (post-quantum capable)
#   pqc-test-chromium:local    Chromium from Alpine (bench/images/build.sh)
#
# Cases:
#   10 OpenSSL 1.1.1 client  -> served, class classical
#   11 OpenSSL 3.0 client    -> served, class classical
#   12 Java 21 client        -> served, class classical
#   13 Java 21 with the customer-CA client certificate (pq-required) -> 403 pq_required
#   14 curl on OpenSSL 3.5   -> served, class pq-kex or pq (what it negotiated is logged)
#   15a Chromium (headless) trusting the gateway CA (NSS) -> served, class pq
#   15b Chromium not trusting it, the classical certificate pinned by SPKI -> NOT
#       served: Chromium offers ML-DSA, gets the ML-DSA-65 certificate, rejects it

RC=$W/rc; mkdir -p "$RC"
cp "$W/cl/ca.crt" "$RC/customer-ca.crt"
cat "$PKI_DIR/ca-chain.crt" "$W/cl/ca.crt" > "$RC/both-ca.pem"
cat > "$RC/probe.py" <<'PY'
import http.client, ssl, sys
host, port, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
c = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
c.request("GET", "/")
r = c.getresponse()
print(ssl.OPENSSL_VERSION, "|", r.status, "|", r.read().decode().strip(), "|", c.sock.version(), c.sock.cipher()[0])
PY
cat > "$RC/Probe.java" <<'JAVA'
import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.security.KeyStore;

public class Probe {
    public static void main(String[] a) throws Exception {
        char[] pw = "changeit".toCharArray();
        KeyStore ts = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(a[1])) { ts.load(in, pw); }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ts);
        KeyManager[] km = null;
        if (a.length > 2) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = new FileInputStream(a[2])) { ks.load(in, pw); }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(ks, pw);
            km = kmf.getKeyManagers();
        }
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(km, tmf.getTrustManagers(), null);
        HttpsURLConnection u = (HttpsURLConnection) new URI(a[0]).toURL().openConnection();
        u.setSSLSocketFactory(ctx.getSocketFactory());
        int code = u.getResponseCode();
        InputStream in = code < 400 ? u.getInputStream() : u.getErrorStream();
        String body = in == null ? "" : new String(in.readAllBytes()).trim();
        System.out.println("java " + System.getProperty("java.version") + " | " + code + " | " + body + " | " + u.getCipherSuite());
    }
}
JAVA
# Java trusts only what it can parse: the customer's classical CA.
docker run --rm -v "$RC:/rc" eclipse-temurin:21-jdk keytool -importcert -noprompt -alias customer -file /rc/customer-ca.crt \
	-keystore /rc/trust.p12 -storetype PKCS12 -storepass changeit >/dev/null 2>&1
O pkcs12 -export -in "$W/cl/client.crt" -inkey "$W/cl/client.key" -out "$RC/client.p12" -passout pass:changeit
chmod -R a+rX "$RC"

URL=https://$H:$P_MIG/
RUN=(docker run --rm --network host --add-host "$H:127.0.0.1" -v "$RC:/rc:ro")
last_sig(){ docker exec $NAME sh -c 'tail -1 /var/log/nginx/pqc-migration-access.log' | grep -oE '"server_sig":"[^"]*"'; }
last_class(){ docker exec $NAME sh -c 'tail -1 /var/log/nginx/pqc-migration-access.log' | grep -oE '"group":"[^"]*"|"class":"[^"]*"' | tr '\n' ' '; }

r=$("${RUN[@]}" python:3.9-slim-bullseye python -I /rc/probe.py $H $P_MIG /rc/customer-ca.crt 2>&1 | tail -1); echo "  10: $r | $(last_class)"
check "10 CPython on OpenSSL 1.1.1: served, class classical" "echo '$r' | grep -q '^OpenSSL 1.1.1.* | 200 | class=classical hdr=classical |'"
r=$("${RUN[@]}" python:3.11-slim-bookworm python -I /rc/probe.py $H $P_MIG /rc/customer-ca.crt 2>&1 | tail -1); echo "  11: $r | $(last_class)"
check "11 CPython on OpenSSL 3.0: served, class classical" "echo '$r' | grep -q '^OpenSSL 3\.0\..* | 200 | class=classical hdr=classical |'"
r=$("${RUN[@]}" eclipse-temurin:21-jdk java /rc/Probe.java "$URL" /rc/trust.p12 2>&1 | tail -1); echo "  12: $r | $(last_class)"
check "12 Java 21 (JSSE): served, class classical" "echo '$r' | grep -q '^java 21\..* | 200 | class=classical hdr=classical |'"
r=$("${RUN[@]}" eclipse-temurin:21-jdk java /rc/Probe.java "$URL" /rc/trust.p12 /rc/client.p12 2>&1 | tail -1); echo "  13: $r | $(last_class)"
check "13 Java 21 with the customer-CA client certificate under pq-required: 403 pq_required" "echo '$r' | grep -q '^java 21\..* | 403 | .*pq_required'"
r=$("${RUN[@]}" curlimages/curl -s --cacert /rc/both-ca.pem -w ' | %{http_code}' "$URL" 2>&1 | tr -d '\n'); echo "  14: $r | $(last_class)"
check "14 curl on OpenSSL 3.5: served, post-quantum key exchange (pq or pq-kex)" "echo '$r' | grep -qE '^class=pq(-kex)? hdr=pq(-kex)? \| 200\$'"

# Chromium offers mldsa44/65/87 first among its signature algorithms, so OpenSSL
# serves it the ML-DSA-65 certificate. With the gateway's CA in its NSS store it is
# served post-quantum (15a); without it, the handshake fails even though a
# classical certificate is available (15b): the hazard in the README.
cp "$PKI_DIR/ca-chain.crt" "$RC/gateway-ca-chain.crt"; chmod a+r "$RC/gateway-ca-chain.crt"
before=$(docker exec $NAME sh -c 'wc -l < /var/log/nginx/pqc-migration-access.log')
r=$(timeout 90 "${RUN[@]}" --name $NAME-chr-a --entrypoint sh pqc-test-chromium:local -c '
	mkdir -p $HOME/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -N --empty-password &&
	awk "/BEGIN/{n++} {print > \"/tmp/ca\" n \".pem\"}" /rc/gateway-ca-chain.crt &&
	for f in /tmp/ca*.pem; do certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "$(basename $f)" -i "$f"; done &&
	chromium-browser --headless --no-sandbox --disable-gpu --disable-background-networking --no-first-run --user-data-dir=/tmp/u --dump-dom "$0"' "$URL" 2>"$RC/chromium-15a.err" | grep -oE 'class=[a-z-]+ hdr=[a-z-]*' | head -1)
echo "  15a: $("${RUN[@]}" pqc-test-chromium:local --version 2>/dev/null) | $r | $(last_class) $(last_sig)"
check "15a Chromium trusting the gateway CA: served, class pq (ML-DSA-65, X25519MLKEM768)" "echo '$r' | grep -q '^class=pq hdr=pq\$'"
SPKI=$(O x509 -in "$W/cl/server.crt" -pubkey -noout | O pkey -pubin -outform DER | O dgst -sha256 -binary | base64)
mid=$(docker exec $NAME sh -c 'wc -l < /var/log/nginx/pqc-migration-access.log')
r=$(timeout 90 "${RUN[@]}" --name $NAME-chr-b pqc-test-chromium:local --headless --no-sandbox --disable-gpu --disable-background-networking --no-first-run --user-data-dir=/tmp/u \
	--ignore-certificate-errors-spki-list="$SPKI" --dump-dom "$URL" 2>"$RC/chromium-15b.err" | grep -oE 'class=[a-z-]+ hdr=[a-z-]*' | head -1)
after=$(docker exec $NAME sh -c 'wc -l < /var/log/nginx/pqc-migration-access.log')
echo "  15b: '${r}' | requests logged: 15a $((mid-before)), 15b $((after-mid))"
check "15b Chromium NOT trusting the gateway CA (classical certificate pinned) is not served: it gets ML-DSA-65" "[ -z '$r' ] && [ $((after-mid)) = 0 ]"

docker rm -f $NAME-chr-a $NAME-chr-b >/dev/null 2>&1
find "$RC" -name '*.p12' -exec shred -u {} +
