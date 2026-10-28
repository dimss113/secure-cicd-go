// Package config loads the secrets file rendered by Vault Agent and refuses anything incomplete.
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const minJWTSecretLen = 32

// Config holds the decoded secrets the API needs at start.
type Config struct {
	Env       string
	JWTSecret []byte
	AESKey    []byte
}

type fileConfig struct {
	Env       *string `json:"env"`
	JWTSecret *string `json:"jwtSecret"`
	AESKey    *string `json:"aesKey"`
}

// Load reads and validates the config file; errors name the field but never its value.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var raw fileConfig
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		if _, ok := errors.AsType[*json.SyntaxError](err); ok {
			return Config{}, errors.New("parse config: invalid JSON")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if raw.Env == nil || *raw.Env == "" {
		return Config{}, errors.New("config: env is missing or empty")
	}
	if raw.JWTSecret == nil || len(*raw.JWTSecret) < minJWTSecretLen {
		return Config{}, fmt.Errorf("config: jwtSecret is missing or shorter than %d characters", minJWTSecretLen)
	}
	if raw.AESKey == nil {
		return Config{}, errors.New("config: aesKey is missing")
	}
	key, err := hex.DecodeString(*raw.AESKey)
	if err != nil || len(key) != 32 {
		return Config{}, errors.New("config: aesKey must be 64 hex characters (32 bytes)")
	}

	return Config{Env: *raw.Env, JWTSecret: []byte(*raw.JWTSecret), AESKey: key}, nil
}
