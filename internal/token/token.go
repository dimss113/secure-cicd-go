// Package token issues and verifies short-lived HS256 JWTs.
package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuerName = "secure-cicd-go"

// ErrInvalid wraps every reason a token is rejected.
var ErrInvalid = errors.New("invalid token")

// Issuer signs and checks tokens with one shared secret.
type Issuer struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewIssuer returns an Issuer whose tokens live for ttl.
func NewIssuer(secret []byte, ttl time.Duration, now func() time.Time) *Issuer {
	return &Issuer{secret: secret, ttl: ttl, now: now}
}

// Issue signs a token for subject and returns it with its expiry.
func (i *Issuer) Issue(subject string) (string, time.Time, error) {
	if subject == "" {
		return "", time.Time{}, errors.New("token: subject is empty")
	}
	now := i.now()
	exp := now.Add(i.ttl)
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    issuerName,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token: sign: %w", err)
	}
	return tok, exp, nil
}

// Verify checks signature, algorithm, issuer and expiry, and returns the subject.
func (i *Issuer) Verify(tok string) (string, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(tok, &claims,
		func(*jwt.Token) (any, error) { return i.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuerName),
		jwt.WithTimeFunc(i.now),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: missing subject", ErrInvalid)
	}
	return claims.Subject, nil
}
