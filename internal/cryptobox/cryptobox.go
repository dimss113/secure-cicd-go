// Package cryptobox encrypts short texts with AES-256-GCM.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrDecrypt is returned for any ciphertext that cannot be opened.
var ErrDecrypt = errors.New("cannot decrypt")

// Box seals and opens data with one AES-256 key.
type Box struct {
	aead cipher.AEAD
}

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cryptobox: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Encrypt returns base64(nonce || ciphertext || tag).
func (b *Box) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("cryptobox: nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, plaintext, nil)), nil
}

// Decrypt reverses Encrypt; every failure is ErrDecrypt.
func (b *Box) Decrypt(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrDecrypt
	}
	n := b.aead.NonceSize()
	if len(raw) < n+b.aead.Overhead() {
		return nil, ErrDecrypt
	}
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
