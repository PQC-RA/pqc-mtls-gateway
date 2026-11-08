import javax.net.ssl.*; import java.security.cert.X509Certificate;
public class T { public static void main(String[] a) throws Exception {
  // negotiation only: trust-all, so the test isolates group and signature-scheme support
  TrustManager[] tm={new X509TrustManager(){public void checkClientTrusted(X509Certificate[] c,String s){} public void checkServerTrusted(X509Certificate[] c,String s){} public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}}};
  SSLContext c=SSLContext.getInstance("TLSv1.3"); c.init(null,tm,null);
  try (SSLSocket s=(SSLSocket)c.getSocketFactory().createSocket(a[0],Integer.parseInt(a[1]))) {
    s.setSoTimeout(5000); s.startHandshake(); System.out.println("OK handshake "+s.getSession().getProtocol()+" java "+System.getProperty("java.version"));
  } catch (Exception e) { System.out.println("FAIL "+e.getClass().getSimpleName()+": "+String.valueOf(e.getMessage()).replace('\n',' ')+" java "+System.getProperty("java.version")); }
}}
