package com.networknt.http.client;

import com.networknt.client.ClientConfig;
import com.networknt.config.TlsUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import javax.net.ssl.KeyManagerFactory;
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
import java.util.concurrent.TimeUnit;

import static com.networknt.http.client.HttpClientRequest.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HttpClientTlsPasswordTest {
    private static final String STORE_PASSWORD = "store-canary";
    private static final String KEY_PASSWORD = "key-canary";
    private static final String[] PROPERTIES = {KEY_STORE_PROPERTY, KEY_STORE_PASSWORD_PROPERTY,
            TRUST_STORE_PROPERTY, TRUST_STORE_PASSWORD_PROPERTY, TRUST_STORE_TYPE_PROPERTY};
    private static Path keyStorePath;
    private static Path trustStorePath;
    private final Map<String, String> previousProperties = new HashMap<>();
    private final Map<String, Object> tls = new HashMap<>();
    private final List<char[]> captured = new ArrayList<>();
    private Field configField;
    private Field contextField;
    private Object previousConfig;
    private Object previousContext;
    private MockedStatic<ClientConfig> configs;

    @BeforeAll
    static void createSyntheticStores(@TempDir Path directory) throws Exception {
        keyStorePath = directory.resolve("client.jks");
        trustStorePath = directory.resolve("trust.jks");
        Path output = directory.resolve("keytool.log");
        Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1",
                "-storetype", "JKS", "-keystore", keyStorePath.toString(), "-storepass", STORE_PASSWORD,
                "-keypass", KEY_PASSWORD, "-dname", "CN=local.test", "-validity", "1", "-noprompt")
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        if (!keytool.waitFor(30, TimeUnit.SECONDS)) {
            keytool.destroyForcibly();
            fail("Synthetic fixture keytool timed out");
        }
        assertEquals(0, keytool.exitValue(), Files.readString(output));
        KeyStore keys = KeyStore.getInstance("JKS");
        try (InputStream input = Files.newInputStream(keyStorePath)) {
            keys.load(input, STORE_PASSWORD.toCharArray());
        }
        KeyStore trust = KeyStore.getInstance("JKS");
        trust.load(null, STORE_PASSWORD.toCharArray());
        trust.setCertificateEntry("fixture", keys.getCertificate("fixture"));
        try (var stream = Files.newOutputStream(trustStorePath)) {
            trust.store(stream, STORE_PASSWORD.toCharArray());
        }
    }

    @BeforeEach
    void isolateConfigurationCacheAndProperties() throws Exception {
        configField = HttpClientRequest.class.getDeclaredField("clientConfig");
        contextField = HttpClientRequest.class.getDeclaredField("sslContext");
        configField.setAccessible(true);
        contextField.setAccessible(true);
        previousConfig = configField.get(null);
        previousContext = contextField.get(null);
        for (String name : PROPERTIES) {
            previousProperties.put(name, System.getProperty(name));
            System.clearProperty(name);
        }
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
        configs = mockStatic(ClientConfig.class);
        configs.when(ClientConfig::get).thenReturn(config);
    }

    @AfterEach
    void restoreSharedState() throws Exception {
        if (configs != null) configs.close();
        configField.set(null, previousConfig);
        contextField.set(null, previousContext);
        for (String name : PROPERTIES) {
            String previous = previousProperties.get(name);
            if (previous == null) System.clearProperty(name);
            else System.setProperty(name, previous);
        }
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

    private MockedStatic<TlsUtil> observeStoreLoads() {
        var stores = mockStatic(TlsUtil.class, CALLS_REAL_METHODS);
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
        var factories = mockStatic(KeyManagerFactory.class, CALLS_REAL_METHODS);
        factories.when(() -> KeyManagerFactory.getInstance(algorithm)).thenReturn(factory);
        return factories;
    }

    private void assertDefaultLoad(boolean fail) throws Exception {
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
        try (var stores = mockStatic(KeyStore.class, CALLS_REAL_METHODS)) {
            stores.when(() -> KeyStore.getInstance("JKS", Security.getProvider("SUN"))).thenReturn(store);
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
