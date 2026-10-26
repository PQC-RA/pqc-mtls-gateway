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
#
# Cases:
#   10 OpenSSL 1.1.1 client  -> served, class classical
#   11 OpenSSL 3.0 client    -> served, class classical
#   12 Java 21 client        -> served, class classical
#   13 Java 21 with the customer-CA client certificate (pq-required) -> 403 pq_required
#   14 curl on OpenSSL 3.5   -> served, class pq-kex or pq (what it negotiated is logged)

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

find "$RC" -name '*.p12' -exec shred -u {} +
