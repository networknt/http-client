## [2.4.0](https://github.com/networknt/http-client/tree/2.4.0) (2026-10-08)

**Commits:**

- fixes #55 upgrade to 2.4.0 and light-4j 2.4.0 ([6ea0364](https://github.com/networknt/http-client/commit/6ea03642c541bb131ecd7f8b2a3d1850485f2d16)) (by Steve Hu)
- upgrade encoder to 1.5.0 from 1.2.1 ([4b0daa2](https://github.com/networknt/http-client/commit/4b0daa299bf785bad6b6cce188325b2deadf6ea2)) (by Steve Hu)
- upgrade maven-javadoc to 3.12.0 ([3869f33](https://github.com/networknt/http-client/commit/3869f33b8eb762f60d46697fdea2332ab594d147)) (by Steve Hu)
- upgrade maven-version to 2.22.0 from 2.4 ([a3c7fe8](https://github.com/networknt/http-client/commit/a3c7fe810e5b3f8e6272fbe147832c623d29268b)) (by Steve Hu)
- upgrade mockito to 5.24.0 ([30362f1](https://github.com/networknt/http-client/commit/30362f13d3b40778d809eaef8d7468d5187a97c5)) (by Steve Hu)
- upgrade jackson to 2.22.3 from 2.22.1 ([4e80d11](https://github.com/networknt/http-client/commit/4e80d1194e618b4c4e4aec06bb6c096eea4a5ec9)) (by Steve Hu)
- upgrade maven-surefire to 3.6.0 ([c84d78e](https://github.com/networknt/http-client/commit/c84d78e7cae1227aa6cdd4b6d24f4660795a67f3)) (by Steve Hu)
- upgrade logback to 1.6.3 from 1.5.37 ([8f275e2](https://github.com/networknt/http-client/commit/8f275e2b093719ab821b24fd45b56b77d882d621)) (by Steve Hu)
- upgrade logback to 1.5.37 ([9991a46](https://github.com/networknt/http-client/commit/9991a469e42ec6ff4414f75b96c5b15fb3b40ab5)) (by Steve Hu)
- upgrade central-publishing-maven to 0.11.0 from 0.7.0 ([1f7005e](https://github.com/networknt/http-client/commit/1f7005e953169ef46454b491c2a4a63a47464be3)) (by Steve Hu)
- update jackson version to 2.22.1 ([d5d551e](https://github.com/networknt/http-client/commit/d5d551eaa128553fe3771fb3a29d667162630558)) (by Steve Hu)
- build: support Java 25 coverage ([ef7242c](https://github.com/networknt/http-client/commit/ef7242cce3aa3668534b7b9d89c7eeb444c6cb36)) (by Steve Hu)
- build: target Java 25 ([6b2cf83](https://github.com/networknt/http-client/commit/6b2cf834987e4aa0e9158a588a18d23860120f23)) (by Steve Hu)
- fixes #54 remove default cacerts password literal to avoid security scan flag ([683215f](https://github.com/networknt/http-client/commit/683215f809874da05543fb378a583e6604d90ea3)) (by Steve Hu)
- update gitignore ([fe2534b](https://github.com/networknt/http-client/commit/fe2534b06246f6f70ee5a24defa2c99a15256c5a)) (by Steve Hu)
- upgrade to 1.0.18 and update changelog ([31300af](https://github.com/networknt/http-client/commit/31300af5572724322484127045e7658b5b9835fd)) (by Steve Hu)

## [1.0.18](https://github.com/networknt/http-client/tree/1.0.18) (2026-04-27)

**Fixed bugs:**

- fixes #52 fix the client.verifyHostname false timing in Java 25
- fixes #50 log the error for jwk if response code is 400 and up (#51)
- fixes #49 remove unused org.apache package

## [1.0.17](https://github.com/networknt/http-client/tree/1.0.14) (2025-10-09)

**Fixed bugs:**

- upgrade to java 21
- fixes #46 refactor the config class for reload (#47)

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
