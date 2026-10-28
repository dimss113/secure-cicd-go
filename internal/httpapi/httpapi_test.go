package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dimss113/secure-cicd-go/internal/cryptobox"
	"github.com/dimss113/secure-cicd-go/internal/token"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func newTestHandler(t *testing.T, logs *bytes.Buffer) http.Handler {
	t.Helper()
	iss := token.NewIssuer([]byte("test-secret-0123456789abcdef012345"), 15*time.Minute, func() time.Time { return t0 })
	box, err := cryptobox.New(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if logs == nil {
		logs = &bytes.Buffer{}
	}
	return NewHandler(iss, box, slog.New(slog.NewJSONHandler(logs, nil)))
}

func do(t *testing.T, h http.Handler, method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q is not a JSON object of strings: %v", rec.Body.String(), err)
	}
	return m
}

func issue(t *testing.T, h http.Handler, subject string) string {
	t.Helper()
	rec := do(t, h, "POST", "/v1/tokens", `{"subject":"`+subject+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/tokens = %d %s", rec.Code, rec.Body)
	}
	return decode(t, rec)["token"]
}

func TestHealth(t *testing.T) {
	rec := do(t, newTestHandler(t, nil), "GET", "/health", "", nil)
	if rec.Code != 200 || decode(t, rec)["status"] != "ok" {
		t.Fatalf("GET /health = %d %s", rec.Code, rec.Body)
	}
}

func TestVersion(t *testing.T) {
	rec := do(t, newTestHandler(t, nil), "GET", "/version", "", nil)
	m := decode(t, rec)
	if rec.Code != 200 || m["commit"] != "dev" || m["buildTime"] != "unknown" {
		t.Fatalf("GET /version = %d %v", rec.Code, m)
	}
}

func TestTokens_Then_Me(t *testing.T) {
	h := newTestHandler(t, nil)
	rec := do(t, h, "POST", "/v1/tokens", `{"subject":"alice"}`, nil)
	m := decode(t, rec)
	if rec.Code != http.StatusCreated || m["token"] == "" || m["expiresAt"] != "2026-10-28T12:15:00Z" {
		t.Fatalf("POST /v1/tokens = %d %v", rec.Code, m)
	}
	rec = do(t, h, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + m["token"]})
	if rec.Code != 200 || decode(t, rec)["subject"] != "alice" {
		t.Fatalf("GET /v1/me = %d %s", rec.Code, rec.Body)
	}
}

func TestMe_MissingOrBadToken(t *testing.T) {
	h := newTestHandler(t, nil)
	for _, auth := range []string{"", "Bearer x", "Basic abc"} {
		rec := do(t, h, "GET", "/v1/me", "", map[string]string{"Authorization": auth})
		if rec.Code != http.StatusUnauthorized || decode(t, rec)["error"] != "invalid token" {
			t.Errorf("Authorization %q: got %d %s, want 401 invalid token", auth, rec.Code, rec.Body)
		}
	}
}

func TestTokens_BadSubject(t *testing.T) {
	h := newTestHandler(t, nil)
	bodies := []string{
		`{"subject":""}`,
		`{"subject":"` + strings.Repeat("a", 65) + `"}`,
		`{"subject":"alice","role":"admin"}`,
		`{"subject":`,
	}
	for _, body := range bodies {
		rec := do(t, h, "POST", "/v1/tokens", body, nil)
		if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] == "" {
			t.Errorf("body %q: got %d %s, want 400 with error", body, rec.Code, rec.Body)
		}
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	h := newTestHandler(t, nil)
	rec := do(t, h, "POST", "/v1/encrypt", `{"plaintext":"rahasia kecil"}`, nil)
	ct := decode(t, rec)["ciphertext"]
	if rec.Code != 200 || ct == "" {
		t.Fatalf("POST /v1/encrypt = %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "POST", "/v1/decrypt", `{"ciphertext":"`+ct+`"}`, nil)
	if rec.Code != 200 || decode(t, rec)["plaintext"] != "rahasia kecil" {
		t.Fatalf("POST /v1/decrypt = %d %s", rec.Code, rec.Body)
	}
}

func TestDecrypt_Garbage(t *testing.T) {
	rec := do(t, newTestHandler(t, nil), "POST", "/v1/decrypt", `{"ciphertext":"!!!"}`, nil)
	if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "cannot decrypt" {
		t.Fatalf("got %d %s, want 400 cannot decrypt", rec.Code, rec.Body)
	}
}

func TestBodyTooLarge(t *testing.T) {
	body := `{"plaintext":"` + strings.Repeat("a", 1<<20) + `"}`
	rec := do(t, newTestHandler(t, nil), "POST", "/v1/encrypt", body, nil)
	if rec.Code != http.StatusRequestEntityTooLarge || decode(t, rec)["error"] == "" {
		t.Fatalf("got %d, want 413 with error", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := do(t, newTestHandler(t, nil), "GET", "/v1/tokens", "", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/tokens = %d, want 405", rec.Code)
	}
}

func TestLogs_NoSecrets(t *testing.T) {
	var logs bytes.Buffer
	h := newTestHandler(t, &logs)
	tok := issue(t, h, "alice")
	do(t, h, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + tok})
	do(t, h, "POST", "/v1/encrypt", `{"plaintext":"jangan-dicatat"}`, nil)
	if strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), "jangan-dicatat") {
		t.Fatalf("logs leak a token or request body:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), `"path":"/v1/me"`) || !strings.Contains(logs.String(), `"status":200`) {
		t.Fatalf("logs miss the request line:\n%s", logs.String())
	}
}
