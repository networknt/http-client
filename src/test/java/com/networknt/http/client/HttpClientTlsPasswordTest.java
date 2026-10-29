package com.networknt.http.client;

import com.networknt.client.ClientConfig;
import com.networknt.config.TlsUtil;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.api.function.Executable;
import com.networknt.http.client.ssl.CompositeX509TrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static com.networknt.http.client.HttpClientRequest.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@Isolated
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(Resources.SYSTEM_PROPERTIES)
class HttpClientTlsPasswordTest {
    private static final String STORE_PASSWORD = "store-canary";
    private static final String KEY_PASSWORD = "key-canary";
    private static final String[] PROPERTIES = {KEY_STORE_PROPERTY, KEY_STORE_PASSWORD_PROPERTY,
            TRUST_STORE_PROPERTY, TRUST_STORE_PASSWORD_PROPERTY, TRUST_STORE_TYPE_PROPERTY};
    private static Path keyStorePath;
    private static Path trustStorePath;
    private final Map<String, Object> tls = new HashMap<>();
    private final List<char[]> captured = new ArrayList<>();
    private Field configField;
    private Field contextField;
    @AutoClose private StateGuard state;

    @BeforeAll
    static void copySyntheticStores(@TempDir Path directory) throws Exception {
        keyStorePath = directory.resolve("client.jks");
        trustStorePath = directory.resolve("trust.jks");
        for (String name : new String[]{"client.jks", "trust.jks"}) {
            try (InputStream input = HttpClientTlsPasswordTest.class.getResourceAsStream("/tls-password-fixtures/" + name)) {
                assertNotNull(input, "Missing synthetic fixture " + name);
                Files.copy(input, directory.resolve(name));
            }
        }
    }

    @BeforeEach
    void isolateConfigurationCacheAndProperties() throws Exception {
        // Register ownership before any mutation; @AutoClose also runs after setup failures.
        state = new StateGuard();
        configField = state.configField;
        contextField = state.contextField;
        for (String name : PROPERTIES) System.clearProperty(name);
        tls.put(LOAD_KEY_STORE, true);
        tls.put(KEY_STORE, keyStorePath.toString());
        tls.put(KEY_STORE_PASS, STORE_PASSWORD);
        tls.put(KEY_PASS, KEY_PASSWORD);
        tls.put(LOAD_TRUST_STORE, true);
        tls.put(TRUST_STORE, trustStorePath.toString());
        tls.put(TRUST_STORE_PASS, STORE_PASSWORD);
        tls.put(LOAD_DEFAULT_TRUST, false);
        tls.put(TLS_VERSION, "TLSv1.3");
        ClientConfig config = mock(ClientConfig.class);
        when(config.getTlsConfig()).thenReturn(tls);
        configField.set(null, config);
        contextField.set(null, null);
        var configs = tracked(mockStatic(ClientConfig.class));
        configs.when(ClientConfig::get).thenReturn(config);
    }

    private static final class StateGuard implements AutoCloseable {
        final Field configField;
        final Field contextField;
        final Object config;
        final Object context;
        final Map<String, String> properties = new HashMap<>();
        final List<MockedStatic<?>> mocks = new ArrayList<>();
        boolean closed;

        StateGuard() throws Exception {
            configField = HttpClientRequest.class.getDeclaredField("clientConfig");
            contextField = HttpClientRequest.class.getDeclaredField("sslContext");
            configField.setAccessible(true);
            contextField.setAccessible(true);
            config = configField.get(null);
            context = contextField.get(null);
            for (String name : PROPERTIES) properties.put(name, System.getProperty(name));
        }

        @Override public void close() {
            if (closed) return;
            closed = true;
            List<Executable> restore = new ArrayList<>();
            for (int i = mocks.size() - 1; i >= 0; i--) {
                var mock = mocks.get(i);
                restore.add(mock::closeOnDemand);
            }
            restore.add(() -> configField.set(null, config));
            restore.add(() -> contextField.set(null, context));
            for (String name : PROPERTIES) restore.add(() -> {
                String value = properties.get(name);
                if (value == null) System.clearProperty(name);
                else System.setProperty(name, value);
            });
            // Run every restoration even if closing a mock or restoring another value fails.
            assertAll("Restore shared TLS test state", restore);
        }
    }

    private <T> MockedStatic<T> tracked(MockedStatic<T> mock) {
        state.mocks.add(mock);
        return mock;
    }

    @Test
    void contextLoadsAndCachesWhileAllThreeOwnedCopiesAreCleared() throws Exception {
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager()) {
            SSLContext context = createSSLContext();
            assertNotNull(context);
            assertEquals("TLSv1.3", context.getProtocol());
            assertSame(context, createSSLContext());
        }
        assertCleared(3);
        assertEquals(borrowed, tls);
    }

    @Test
    void keyStoreLoadFailureClearsItsPasswordCopy() throws Exception {
        tls.put(KEY_STORE_PASS, "incorrect-store-canary");
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager()) {
            assertThrows(RuntimeException.class, HttpClientRequest::createSSLContext);
        }
        assertCleared(1);
        assertEquals(borrowed, tls);
    }

    @Test
    void keyManagerFailureClearsBothPasswordCopies() throws Exception {
        tls.put(KEY_PASS, "incorrect-key-canary");
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager()) {
            assertThrows(IOException.class, HttpClientRequest::createSSLContext);
        }
        assertCleared(2);
        assertEquals(borrowed, tls);
    }

    @Test
    void configuredTrustStoreFailureClearsItsPasswordCopy() throws Exception {
        tls.put(LOAD_KEY_STORE, false);
        tls.put(TRUST_STORE_PASS, "incorrect-trust-canary");
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads()) {
            assertThrows(IOException.class, HttpClientRequest::createSSLContext);
        }
        assertCleared(1);
        assertEquals(borrowed, tls);
    }

    @Test
    void keyStoreSystemPropertiesRetainPrecedenceAndAreNotModified() throws Exception {
        tls.put(KEY_STORE, "unused-config-store");
        tls.put(KEY_STORE_PASS, "unused-config-password");
        System.setProperty(KEY_STORE_PROPERTY, keyStorePath.toString());
        System.setProperty(KEY_STORE_PASSWORD_PROPERTY, STORE_PASSWORD);
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager()) {
            assertNotNull(createSSLContext());
        }
        assertCleared(3);
        assertEquals(borrowed, tls);
        assertEquals(STORE_PASSWORD, System.getProperty(KEY_STORE_PASSWORD_PROPERTY));
        assertEquals(keyStorePath.toString(), System.getProperty(KEY_STORE_PROPERTY));
    }

    @Test
    void missingPrivateKeyPasswordStillFailsAfterLoadingAndClearingStoreCopy() throws Exception {
        tls.remove(KEY_PASS);
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager()) {
            assertThrows(NullPointerException.class, HttpClientRequest::createSSLContext);
        }
        assertCleared(1);
        assertEquals(borrowed, tls);
    }

    @Test
    void defaultTrustStorePropertyPasswordWinsAndOwnedCopyIsCleared() throws Exception {
        tls.put(DEFAULT_CERT_PASS, "unused-default-password");
        System.setProperty(TRUST_STORE_PASSWORD_PROPERTY, STORE_PASSWORD);
        Map<String, Object> borrowed = new HashMap<>(tls);
        assertDefaultLoad(false);
        assertCleared(1);
        assertEquals(borrowed, tls);
        assertEquals(STORE_PASSWORD, System.getProperty(TRUST_STORE_PASSWORD_PROPERTY));
    }

    @Test
    void defaultTrustStoreConfigurationPasswordAndEmptyPropertyRetainSemantics() throws Exception {
        tls.put(DEFAULT_CERT_PASS, STORE_PASSWORD);
        System.setProperty(TRUST_STORE_PASSWORD_PROPERTY, "");
        Map<String, Object> borrowed = new HashMap<>(tls);
        assertDefaultLoad(false);
        assertCleared(1);
        assertEquals(borrowed, tls);
        assertEquals("", System.getProperty(TRUST_STORE_PASSWORD_PROPERTY));
    }

    @Test
    void defaultTrustStoreFailureClearsItsPasswordCopy() throws Exception {
        tls.put(DEFAULT_CERT_PASS, "incorrect-default-canary");
        Map<String, Object> borrowed = new HashMap<>(tls);
        assertDefaultLoad(true);
        assertCleared(1);
        assertEquals(borrowed, tls);
    }

    @Test
    void defaultTrustStoreMissingPasswordStillPassesNull() throws Exception {
        assertDefaultLoad(false);
        assertEquals(1, captured.size());
        assertNull(captured.getFirst());
        assertFalse(tls.containsKey(DEFAULT_CERT_PASS));
        assertNull(System.getProperty(TRUST_STORE_PASSWORD_PROPERTY));
    }

    @Test
    void fullContextCombinesDefaultAndConfiguredTrustAndClearsAllFourCopies() throws Exception {
        tls.put(LOAD_DEFAULT_TRUST, true);
        tls.put(DEFAULT_CERT_PASS, STORE_PASSWORD);
        SSLContext context = spy(SSLContext.getInstance("TLSv1.3"));
        AtomicReference<TrustManager[]> selected = new AtomicReference<>();
        doAnswer(invocation -> {
            selected.set(invocation.getArgument(1));
            return invocation.callRealMethod();
        }).when(context).init(any(KeyManager[].class), any(TrustManager[].class), isNull());
        Map<String, Object> borrowed = new HashMap<>(tls);
        try (var stores = observeStoreLoads(); var factories = observeKeyManager();
             var defaults = observeDefaultStoreLoads();
             var contexts = tracked(mockStatic(SSLContext.class, CALLS_REAL_METHODS))) {
            contexts.when(() -> SSLContext.getInstance("TLSv1.3")).thenReturn(context);
            assertSame(context, createSSLContext());
        }
        assertCleared(4);
        assertEquals(borrowed, tls);
        assertEquals(1, selected.get().length);
        var composite = assertInstanceOf(CompositeX509TrustManager.class, selected.get()[0]);
        assertEquals(2, composite.getAcceptedIssuers().length, "Both trust stores contribute an issuer");
    }

    @Test
    void defaultStoreFailureInsideFullContextClearsBothTrustCopies() throws Exception {
        tls.put(LOAD_KEY_STORE, false);
        tls.put(LOAD_DEFAULT_TRUST, true);
        tls.put(DEFAULT_CERT_PASS, "incorrect-default-canary");
        try (var stores = observeStoreLoads(); var defaults = observeDefaultStoreLoads()) {
            assertThrows(IOException.class, HttpClientRequest::createSSLContext);
        }
        assertCleared(2);
        assertNull(contextField.get(null));
    }

    @Test
    void stateGuardRestoresGlobalsEvenWhenOneMockCleanupThrows() throws Exception {
        try (var guard = new StateGuard()) {
            guard.mocks.add(mockStatic(TlsUtil.class));
            MockedStatic<?> failing = mock(MockedStatic.class);
            doThrow(new IllegalStateException("synthetic cleanup failure")).when(failing).closeOnDemand();
            guard.mocks.add(failing);
            for (String name : PROPERTIES) System.setProperty(name, "changed-for-cleanup-test");
            configField.set(null, null);
            contextField.set(null, SSLContext.getInstance("TLSv1.3"));
            assertThrows(AssertionError.class, guard::close);
            assertSame(guard.config, configField.get(null));
            assertSame(guard.context, contextField.get(null));
            for (String name : PROPERTIES) assertEquals(guard.properties.get(name), System.getProperty(name));
            // Opening the same static mock again proves the original registration was released.
            try (var released = mockStatic(TlsUtil.class)) { assertNotNull(released); }
        }
    }

    private MockedStatic<TlsUtil> observeStoreLoads() {
        var stores = tracked(mockStatic(TlsUtil.class, CALLS_REAL_METHODS));
        stores.when(() -> TlsUtil.loadKeyStore(anyString(), any(char[].class))).thenAnswer(invocation -> {
            char[] password = invocation.getArgument(1);
            captured.add(password);
            String name = invocation.getArgument(0);
            String expected = name.equals(trustStorePath.toString()) ? (String) tls.get(TRUST_STORE_PASS)
                    : System.getProperty(KEY_STORE_PASSWORD_PROPERTY, (String) tls.get(KEY_STORE_PASS));
            assertArrayEquals(expected.toCharArray(), password, "Observe the actual input before provider use");
            return invocation.callRealMethod();
        });
        return stores;
    }

    private MockedStatic<KeyManagerFactory> observeKeyManager() throws Exception {
        String algorithm = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory factory = spy(KeyManagerFactory.getInstance(algorithm));
        doAnswer(invocation -> {
            char[] password = invocation.getArgument(1);
            captured.add(password);
            assertArrayEquals(((String) tls.get(KEY_PASS)).toCharArray(), password);
            return invocation.callRealMethod();
        }).when(factory).init(any(KeyStore.class), any(char[].class));
        var factories = tracked(mockStatic(KeyManagerFactory.class, CALLS_REAL_METHODS));
        factories.when(() -> KeyManagerFactory.getInstance(algorithm)).thenReturn(factory);
        return factories;
    }

    private MockedStatic<KeyStore> observeDefaultStoreLoads() throws Exception {
        System.setProperty(TRUST_STORE_PROPERTY, trustStorePath.toString());
        System.setProperty(TRUST_STORE_TYPE_PROPERTY, "JKS");
        KeyStore store = spy(KeyStore.getInstance("JKS", Security.getProvider("SUN")));
        doAnswer(invocation -> {
            char[] password = invocation.getArgument(1);
            captured.add(password);
            String expected = System.getProperty(TRUST_STORE_PASSWORD_PROPERTY);
            if (expected == null || expected.isEmpty()) expected = (String) tls.get(DEFAULT_CERT_PASS);
            if (expected == null) assertNull(password);
            else assertArrayEquals(expected.toCharArray(), password);
            return invocation.callRealMethod();
        }).when(store).load(any(InputStream.class), nullable(char[].class));
        var stores = tracked(mockStatic(KeyStore.class, CALLS_REAL_METHODS));
        stores.when(() -> KeyStore.getInstance("JKS", Security.getProvider("SUN"))).thenReturn(store);
        return stores;
    }

    private void assertDefaultLoad(boolean fail) throws Exception {
        try (var stores = observeDefaultStoreLoads()) {
            if (fail) assertThrows(Exception.class, HttpClientRequest::loadDefaultTrustStore);
            else assertTrue(loadDefaultTrustStore().length > 0);
        }
        assertEquals(trustStorePath.toString(), System.getProperty(TRUST_STORE_PROPERTY));
        assertEquals("JKS", System.getProperty(TRUST_STORE_TYPE_PROPERTY));
    }

    private void assertCleared(int count) {
        assertEquals(count, captured.size(), "All expected password handoffs were exercised");
        for (char[] password : captured) {
            assertNotNull(password);
            assertTrue(password.length > 0);
            for (char value : password) assertEquals('\0', value, "Owned password copy was not cleared");
        }
    }
}
