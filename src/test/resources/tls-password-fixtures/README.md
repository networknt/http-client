# Synthetic TLS ownership fixtures

These public test fixtures contain an intentionally committed, disposable EC
private key and a self-signed certificate for http-client-unit-test.invalid.
Never use them for deployment, transport identity or production trust.

- client.jks: JKS, alias fixture, store password store-canary, key password key-canary.
- trust.jks: JKS containing only the matching synthetic certificate; password store-canary.

The tests copy these resources and use JCA in-process. Fixture preparation
requires neither keytool nor a subprocess, network service or live certificate authority.
The long certificate lifetime avoids expiration-related fixture maintenance;
the tests load keys/certificates and do not qualify production TLS handshakes.
