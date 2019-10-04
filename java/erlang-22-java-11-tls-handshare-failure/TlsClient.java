import javax.net.ssl.*;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TlsClient {


    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl:handshake:verbose");
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        }, null);
        SSLSocketFactory ssf = sslContext.getSocketFactory();
        Socket s = ssf.createSocket("127.0.0.1", 9999);
        ((SSLSocket) s).getSession();
    }

}
