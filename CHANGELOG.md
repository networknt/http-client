## [1.0.14](https://github.com/networknt/http-client/tree/1.0.14) (2025-05-26)

**Fixed bugs:**

- adjust JWT renewal logic to use "exp" claim instead of response body
- removing the system time since "exp" is final expire date in Epoch milliseconds
