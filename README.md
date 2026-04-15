# simple-go-token

simple-go-token provides basic JWT functionality.

It wraps around the [github.com/golang-jwt/jwt/v5](github.com/golang-jwt/jwt/v5) package and reduces boilerplate by making various simplifications and assumptions:

- Only registered claims are supported. Custom claims are not.
- Tokens are issued for only 1 audience ("aud").
- The "not before" ("nbf") claim is set to the same value as "issued at" ("iat").
- Only symmetric signing is supported (through HMAC). It defaults to HS256 signing. Asymmetric signing is not supported.
- Only 1 secret key is used (no `keyFunc` needed).
