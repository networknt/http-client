# TLS password-buffer ownership (A20)

[Issue #64](https://github.com/networknt/http-client/issues/64) covers partner
Checkmarx Heap_Inspection rows 108–111 in HttpClientRequest. On master
`fb95cb472b6ce382679efa344037e2ad2cae9a46` and 2.x
`35d1364ea01fb9ac0779d0bc3b68b56d312ac356`, the four TLS password conversions
still produced temporary char arrays without clearing them. This is scoped
memory-exposure hardening, not evidence of a remote exploit.

## Change

The client keystore password, private-key password, configured truststore
password and default/JDK truststore password now use the framework's
`com.networknt.config.PasswordChars` owner. Each owned copy is cleared after its
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

## Matching framework prerequisite

`config` is a provided dependency. Consumers must supply a matching framework
artifact containing PasswordChars; replacing only http-client while retaining an
older config artifact is insufficient. The helper is included in merged light-4j
master `62b06f43d7ae505e68b8cae5ebf60b70946443f8` (3.0.0-SNAPSHOT) and 2.x
`05a86a5d9510f704168d58f3817d9a2514ae178c` (2.4.2-SNAPSHOT). Local validation
built config/client-config prerequisites from those exact merged sources.

From the matching light-4j source, prepare local prerequisites with
`mvn -pl config,client-config -am install -DskipTests`. This installs artifacts
locally and does not publish a release.

## Verification

HttpClientTlsPasswordTest generates synthetic local JKS key/trust stores and
observes arrays handed to real keystore loaders and key-manager initialization.
It covers successful initialization/cache reuse, store/key-manager failures,
system-property precedence, required-password failure and nullable default-store
passwords, and checks borrowed inputs remain unchanged. Replacing the repaired
loaders with their original implementations causes nine of the ten TLS tests to
fail on uncleared arrays; the null-password case correctly has no array to erase.

The focused run also includes the existing OAuth logging regressions:

```sh
mvn -o clean test -Dtest=HttpClientTlsPasswordTest,OauthHelperLoggingTest
```

This is local JVM/provider evidence, not a partner rescan, live endpoint test,
production TLS qualification or deployment.
