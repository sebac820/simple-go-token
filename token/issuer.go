package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer provides basic JWT functionality.
type Issuer struct {
	// Injected:

	audience      jwt.ClaimStrings
	tokenDuration time.Duration
	issuerName    string
	secretKey     []byte

	// Through options:

	nower         Nower
	signingMethod *jwt.SigningMethodHMAC
}

func NewIssuer(
	audience string,
	issuerName string,
	secretKey []byte,
	tokenDuration time.Duration,
	options ...Option,
) *Issuer {
	s := &Issuer{
		audience:      jwt.ClaimStrings([]string{audience}),
		tokenDuration: tokenDuration,
		issuerName:    issuerName,
		secretKey:     secretKey,

		nower:         DefaultNower{},
		signingMethod: jwt.SigningMethodHS256,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Issue issues a JWT for the given subject.
func (t *Issuer) Issue(subject string) string {
	now := t.nower.Now()
	claims := jwt.RegisteredClaims{
		Audience:  t.audience,
		ExpiresAt: jwt.NewNumericDate(now.Add(t.tokenDuration)),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    t.issuerName,
		NotBefore: jwt.NewNumericDate(now),
		Subject:   subject,
	}
	token := jwt.NewWithClaims(t.signingMethod, claims)
	tokenString, _ := token.SignedString(t.secretKey)
	return tokenString
}

// ParseAndValidate parses and validates the given token string.
// A non-nil error indicates that the token is invalid and will be returned as nil.
// A nil error indicates that the token is valid
// and will be returned as a *Token struct.
func (t *Issuer) ParseAndValidate(tokenString string) (*Token, error) {
	token, err := jwt.Parse(
		tokenString,
		t.getKey,
		t.withValidMethods(),
		t.withTimeFunc(),
	)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", ErrInvalidToken)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	audiences, err := token.Claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("could not get audience: %w", ErrInvalidToken)
	}
	if len(audiences) == 0 {
		return nil, fmt.Errorf("audience not specified: %w", ErrInvalidToken)
	}
	if len(audiences) > 1 {
		return nil, fmt.Errorf("more than 1 audience specified: %w", ErrInvalidToken)
	}
	audience := audiences[0]
	subject, err := token.Claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("could not get subject: %w", ErrInvalidToken)
	}
	tokenStruct := &Token{
		Audience: audience,
		Subject:  subject,
	}
	return tokenStruct, nil
}

func (t *Issuer) getKey(*jwt.Token) (any, error) {
	return t.secretKey, nil
}

func (t *Issuer) withValidMethods() jwt.ParserOption {
	return jwt.WithValidMethods([]string{t.signingMethod.Alg()})
}

func (t *Issuer) withTimeFunc() jwt.ParserOption {
	return jwt.WithTimeFunc(t.nower.Now)
}
