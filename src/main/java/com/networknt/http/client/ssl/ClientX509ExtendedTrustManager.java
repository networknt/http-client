package com.networknt.http.client.ssl;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Delegates to the first configured trust manager. Certificate failures propagate
 * unchanged so JSSE can inspect their validation causes when selecting TLS alerts.
 * Callers and exception logs can therefore see the delegate's certificate diagnostics.
 */
public class ClientX509ExtendedTrustManager implements X509TrustManager {
    private final X509TrustManager trustManager;

    public ClientX509ExtendedTrustManager(List<TrustManager> trustManagers) {
        if(trustManagers == null || trustManagers.size() == 0) {
            throw new IllegalArgumentException("TrustManagers must not be null or empty");
        }
        this.trustManager = (X509TrustManager)trustManagers.get(0);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> certificates = new ArrayList<>(Arrays.asList(trustManager.getAcceptedIssuers()));
        return certificates.toArray(new X509Certificate[0]);
    }
}
