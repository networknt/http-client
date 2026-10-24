package com.networknt.http.client.ssl;

import org.junit.jupiter.api.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ClientX509ExtendedTrustManagerTest {
    private static final String MESSAGE = "None of the TrustManagers trust this certificate chain";

    @Test
    void serverRejectionRetainsOriginalCauseAndGenericMessage() throws Exception {
        X509TrustManager delegate = mock(X509TrustManager.class);
        X509Certificate[] chain = new X509Certificate[0];
        CertificateException cause = new CertificateException("synthetic path-validation reason");
        doThrow(cause).when(delegate).checkServerTrusted(chain, "RSA");
        var wrapper = new ClientX509ExtendedTrustManager(List.of(delegate));
        CertificateException failure = assertThrows(CertificateException.class,
                () -> wrapper.checkServerTrusted(chain, "RSA"));
        assertSame(cause, failure.getCause());
        assertEquals(MESSAGE, failure.getMessage());
        verify(delegate, times(1)).checkServerTrusted(chain, "RSA");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void clientRejectionRetainsOriginalCauseAndGenericMessage() throws Exception {
        X509TrustManager delegate = mock(X509TrustManager.class);
        X509Certificate[] chain = new X509Certificate[0];
        CertificateException cause = new CertificateException("synthetic client-validation reason");
        doThrow(cause).when(delegate).checkClientTrusted(chain, "RSA");
        var wrapper = new ClientX509ExtendedTrustManager(List.of(delegate));
        CertificateException failure = assertThrows(CertificateException.class,
                () -> wrapper.checkClientTrusted(chain, "RSA"));
        assertSame(cause, failure.getCause());
        assertEquals(MESSAGE, failure.getMessage());
        verify(delegate, times(1)).checkClientTrusted(chain, "RSA");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void successfulChecksDelegateOnceWithoutChangingInputs() throws Exception {
        X509TrustManager delegate = mock(X509TrustManager.class);
        X509Certificate[] chain = new X509Certificate[0];
        var wrapper = new ClientX509ExtendedTrustManager(List.of(delegate));
        wrapper.checkServerTrusted(chain, "UNKNOWN");
        wrapper.checkClientTrusted(chain, "RSA");
        verify(delegate, times(1)).checkServerTrusted(chain, "UNKNOWN");
        verify(delegate, times(1)).checkClientTrusted(chain, "RSA");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void laterManagerCannotTurnFirstManagerRejectionIntoAcceptance() throws Exception {
        X509TrustManager first = mock(X509TrustManager.class);
        X509TrustManager second = mock(X509TrustManager.class);
        X509Certificate[] chain = new X509Certificate[0];
        CertificateException cause = new CertificateException("first manager rejects");
        doThrow(cause).when(first).checkServerTrusted(chain, "RSA");
        var wrapper = new ClientX509ExtendedTrustManager(List.of(first, second));
        assertSame(cause, assertThrows(CertificateException.class,
                () -> wrapper.checkServerTrusted(chain, "RSA")).getCause());
        verify(first, times(1)).checkServerTrusted(chain, "RSA");
        verifyNoInteractions(second);
    }

    @Test
    void acceptedIssuersAreUnchanged() {
        X509TrustManager delegate = mock(X509TrustManager.class);
        X509Certificate cert = mock(X509Certificate.class);
        when(delegate.getAcceptedIssuers()).thenReturn(new X509Certificate[]{cert});
        assertArrayEquals(new X509Certificate[]{cert},
                new ClientX509ExtendedTrustManager(List.of(delegate)).getAcceptedIssuers());
        verify(delegate, times(1)).getAcceptedIssuers();
    }

    @Test
    void missingManagersStillReject() {
        assertThrows(IllegalArgumentException.class, () -> new ClientX509ExtendedTrustManager(null));
        assertThrows(IllegalArgumentException.class,
                () -> new ClientX509ExtendedTrustManager(List.<TrustManager>of()));
    }
}
