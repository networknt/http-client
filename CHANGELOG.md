## [1.0.16](https://github.com/networknt/http-client/tree/1.0.14) (2025-10-09)

**Fixed bugs:**

- Passing only the encoded jwt instead of the entire Jwt pojo to make it easier for reused by other classes leveraging oAuthHelper
- typo on info log
- removing the system time since "exp" is final expire date in Epoch millis
- adjust JWT renewal logic to use "exp" claim instead of response body "expire_in"
- fixes #45 DefaultTokenExchangeRequestComposer misses the csrf token
- upgrade maven gpg version

## [1.0.15](https://github.com/networknt/http-client/tree/1.0.14) (2025-07-17)

**Fixed bugs:**

- fixes #43 add token exchange request and update OauthHelper to support the grant type
- added unit test for JWT expiry (#42)
- fixes #40 add repositories and resolve javadoc issues

## [1.0.14](https://github.com/networknt/http-client/tree/1.0.14) (2025-05-26)

**Fixed bugs:**

- adjust JWT renewal logic to use "exp" claim instead of response body
- removing the system time since "exp" is final expire date in Epoch milliseconds
