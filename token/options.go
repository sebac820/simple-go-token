package token

import "github.com/golang-jwt/jwt/v5"

type Option func(*Issuer)

// WithNower creates an Option for the Issuer that makes it use the given Nower.
// This Option is usually used for testing.
// Not specifying it will make the Issuer default to time.Now().
func WithNower(n Nower) Option {
	return func(t *Issuer) {
		t.nower = n
	}
}

// WithSigningMethod creates an Option for the Issuer
// that makes it use the specified HMAC variant for signing.
// Not specifying this Option will make the Issuer default to jwt.SigningMethodHS256.
func WithSigningMethod(m *jwt.SigningMethodHMAC) Option {
	return func(t *Issuer) {
		t.signingMethod = m
	}
}
