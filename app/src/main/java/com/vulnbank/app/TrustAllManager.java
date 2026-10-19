package com.vulnbank.app;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * VULN (OWASP M5 - Insecure Communication, CWE-295 Improper Certificate Validation):
 *
 * This TrustManager accepts ANY certificate, including self-signed ones.
 * Combined with usesCleartextTraffic and no certificate/public-key pinning,
 * an attacker on the same network (or a malicious Wi-Fi AP) can MITM every
 * request with a tool like Burp Suite / mitmproxy and read or modify
 * all traffic, including login credentials.
 */
public class TrustAllManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // VULN: no validation at all
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // VULN: no validation at all -- accepts self-signed / mismatched-hostname certs
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    // Fix: use the system default TrustManagerFactory, or OkHttp's
    // CertificatePinner with the app's real certificate/public-key hashes.
}
