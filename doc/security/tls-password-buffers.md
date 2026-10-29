# TLS password-buffer ownership (A20)

[Issue #64](https://github.com/networknt/http-client/issues/64) covers partner
Checkmarx Heap_Inspection rows 108–111 in HttpClientRequest. On master
`fb95cb472b6ce382679efa344037e2ad2cae9a46` and 2.x
`35d1364ea01fb9ac0779d0bc3b68b56d312ac356`, the four TLS password conversions
still produced temporary char arrays without clearing them. This is scoped
memory-exposure hardening, not evidence of a remote exploit.

## Change

The client keystore password, private-key password, configured truststore
password and default/JDK truststore password now use explicitly owned temporary
arrays, cleared with JDK Arrays.fill in finally blocks. Each copy is cleared after its
keystore load or key-manager initialization, including exceptions. The default
truststore still receives null when no password is supplied. A missing required
private-key password retains its previous failure behavior after the store load.

Public signatures, configuration keys, system-property precedence, TLS versions,
trust-manager composition and SSLContext caching are unchanged. Borrowed
configuration and system-property values are not erased or mutated. Password
Strings supplied by those APIs, configuration state and security-provider copies
may remain in memory. A scanner may still flag the retained String inputs; this
change does not promise complete heap erasure. Protect process memory, dumps,
diagnostics and configuration/secret access, and rotate exposed credentials.

## Dependency and provider compatibility

The cleanup is self-contained and does not depend on PasswordChars or any other
new class in the provided config jar. It adds no new minimum config artifact
requirement; the existing project dependency baseline still applies. A compatibility
probe removes PasswordChars from a copied config jar: the revised TLS loader
compiles on both branches, while the previous PR heads fail on the missing helper.
This checks the introduced helper dependency, not all historical config versions.

The cleanup assumes KeyStore.load and KeyManagerFactory.init consume or copy
the caller's password array before returning. Local tests exercise JDK JKS and
default key/trust-manager providers. A provider retaining the caller's array for
later use would see zeros and is not covered by this qualification. PKCS11, FIPS,
builder-based or other custom providers need provider-specific ownership and
lifecycle qualification before adopting early clearing. No general JCA ownership
guarantee or custom-provider compatibility is claimed.

## Verification

HttpClientTlsPasswordTest copies checked-in synthetic JKS fixtures and
observes arrays handed to real keystore loaders and key-manager initialization.
It covers successful initialization/cache reuse, store/key-manager failures,
system-property precedence, required-password failure and nullable default-store
passwords, and checks borrowed inputs remain unchanged. The full context path
with loadDefaultTrustStore enabled observes all four copies and checks that the
composite trust manager includes issuers from both configured and default stores.
Default-store failure through the full context is covered too.

JUnit isolated, same-thread execution and a system-properties resource lock
prevent these tests from overlapping other tests. An AutoClose state guard is
registered before mutation, closes static mocks on demand, and independently
attempts every cache/property restoration even when another cleanup fails.
A regression injects a cleanup failure and verifies that the remaining globals
and mock registrations are restored. Fixture setup spawns no keytool process.
See the fixture README for intentionally public test-key/password details.

As a negative control, substituting the original TLS loaders produced nine
uncleared-buffer failures in the original ten ownership tests; the null-password
case correctly had no array to erase.

The focused run also includes the existing OAuth logging regressions:

```sh
mvn -o clean test -Dtest=HttpClientTlsPasswordTest,OauthHelperLoggingTest
```

This is local JVM/provider evidence, not a partner rescan, live endpoint test,
production TLS qualification or deployment.
