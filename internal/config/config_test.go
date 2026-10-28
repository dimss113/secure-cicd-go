package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load("../../testdata/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "test" {
		t.Errorf("Env = %q, want test", cfg.Env)
	}
	if len(cfg.AESKey) != 32 {
		t.Errorf("len(AESKey) = %d, want 32", len(cfg.AESKey))
	}
	if string(cfg.JWTSecret) != "dev-only-not-a-secret-0123456789abcdef" {
		t.Errorf("JWTSecret = %q", cfg.JWTSecret)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("err = %v, want it to mention open config", err)
	}
}

func TestLoad_Invalid(t *testing.T) {
	longSecret := `"dev-only-not-a-secret-0123456789abcdef"`
	cases := []struct {
		name      string
		body      string
		wantIn    string
		mustNotIn string
	}{
		{"broken json", `{`, "parse config", ""},
		{"unknown field", `{"env":"x","jwtSecret":` + longSecret + `,"aesKey":"` + validKey + `","extra":1}`, "extra", ""},
		{"null secret", `{"env":"x","jwtSecret":null,"aesKey":"` + validKey + `"}`, "jwtSecret", ""},
		{"short secret", `{"env":"x","jwtSecret":"tiny","aesKey":"` + validKey + `"}`, "jwtSecret", "tiny"},
		{"non hex key", `{"env":"x","jwtSecret":` + longSecret + `,"aesKey":"` + strings.Repeat("z", 64) + `"}`, "aesKey", "zzzz"},
		{"31 byte key", `{"env":"x","jwtSecret":` + longSecret + `,"aesKey":"` + validKey[:62] + `"}`, "aesKey", validKey[:62]},
		{"empty env", `{"env":"","jwtSecret":` + longSecret + `,"aesKey":"` + validKey + `"}`, "env", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("Load returned nil error")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("err = %q, want it to contain %q", err, tc.wantIn)
			}
			if tc.mustNotIn != "" && strings.Contains(err.Error(), tc.mustNotIn) {
				t.Errorf("err = %q leaks the value %q", err, tc.mustNotIn)
			}
		})
	}
}
