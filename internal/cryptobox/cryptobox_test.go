package cryptobox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

var keyA = bytes.Repeat([]byte{0x11}, 32)

func newBox(t *testing.T, key []byte) *Box {
	t.Helper()
	b, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	b := newBox(t, keyA)
	enc, err := b.Encrypt([]byte("halo"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := b.Decrypt(enc)
	if err != nil || string(got) != "halo" {
		t.Fatalf("Decrypt = %q, %v; want halo, nil", got, err)
	}
}

func TestEncrypt_NonceUnique(t *testing.T) {
	b := newBox(t, keyA)
	first, _ := b.Encrypt([]byte("same"))
	second, _ := b.Encrypt([]byte("same"))
	if first == second {
		t.Fatal("two encryptions of the same text are identical; nonce is reused")
	}
}

func TestNew_BadKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("New accepted a 16-byte key")
	}
}

func TestDecrypt_Invalid(t *testing.T) {
	b := newBox(t, keyA)
	valid, _ := b.Encrypt([]byte("halo"))
	raw, _ := base64.StdEncoding.DecodeString(valid)
	raw[len(raw)-1] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)
	otherKey, _ := newBox(t, bytes.Repeat([]byte{0x22}, 32)).Encrypt([]byte("halo"))

	cases := map[string]string{
		"not base64": "!!!",
		"too short":  base64.StdEncoding.EncodeToString([]byte("12345")),
		"tampered":   tampered,
		"other key":  otherKey,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := b.Decrypt(in); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("err = %v, want ErrDecrypt", err)
			}
		})
	}
}
