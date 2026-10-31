package token

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	secretA = []byte("secret-a-0123456789abcdef0123456789")
	secretB = []byte("secret-b-0123456789abcdef0123456789")
	t0      = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
)

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestIssueVerify_RoundTrip(t *testing.T) {
	iss := NewIssuer(secretA, 15*time.Minute, clock(t0))
	tok, exp, err := iss.Issue("alice")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !exp.Equal(t0.Add(15 * time.Minute)) {
		t.Errorf("expiresAt = %v, want %v", exp, t0.Add(15*time.Minute))
	}
	sub, err := iss.Verify(tok)
	if err != nil || sub != "alice" {
		t.Fatalf("Verify = %q, %v; want alice, nil", sub, err)
	}
}

func TestVerify_Expired(t *testing.T) {
	tok, _, _ := NewIssuer(secretA, 15*time.Minute, clock(t0)).Issue("alice")
	_, err := NewIssuer(secretA, 15*time.Minute, clock(t0.Add(16*time.Minute))).Verify(tok)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	tok, _, _ := NewIssuer(secretA, 15*time.Minute, clock(t0)).Issue("alice")
	_, err := NewIssuer(secretB, 15*time.Minute, clock(t0)).Verify(tok)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestVerify_AlgNone(t *testing.T) {
	claims := jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    issuerName,
		IssuedAt:  jwt.NewNumericDate(t0),
		ExpiresAt: jwt.NewNumericDate(t0.Add(time.Minute)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewIssuer(secretA, 15*time.Minute, clock(t0)).Verify(tok)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	claims := jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    "other",
		IssuedAt:  jwt.NewNumericDate(t0),
		ExpiresAt: jwt.NewNumericDate(t0.Add(time.Minute)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secretA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewIssuer(secretA, 15*time.Minute, clock(t0)).Verify(tok)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestVerify_Garbage(t *testing.T) {
	_, err := NewIssuer(secretA, 15*time.Minute, clock(t0)).Verify("abc.def")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestIssue_EmptySubject(t *testing.T) {
	if _, _, err := NewIssuer(secretA, 15*time.Minute, clock(t0)).Issue(""); err == nil {
		t.Fatal("Issue(\"\") returned nil error")
	}
}
