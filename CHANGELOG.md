## [1.0.15](https://github.com/networknt/http-client/tree/1.0.14) (2025-07-17)

**Fixed bugs:**

- fixes #43 add token exchange request and update OauthHelper to support the grant type
- added unit test for JWT expiry (#42)
- fixes #40 add repositories and resolve javadoc issues

## [1.0.14](https://github.com/networknt/http-client/tree/1.0.14) (2025-05-26)

**Fixed bugs:**

- adjust JWT renewal logic to use "exp" claim instead of response body
- removing the system time since "exp" is final expire date in Epoch milliseconds
