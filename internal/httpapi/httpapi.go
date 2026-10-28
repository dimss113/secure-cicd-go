// Package httpapi exposes the health, version, token and crypto endpoints.
package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dimss113/secure-cicd-go/internal/buildinfo"
	"github.com/dimss113/secure-cicd-go/internal/cryptobox"
	"github.com/dimss113/secure-cicd-go/internal/token"
)

const (
	maxBodyBytes  = 1 << 20
	maxSubjectLen = 64
)

type api struct {
	iss *token.Issuer
	box *cryptobox.Box
}

// NewHandler wires the routes and the request log.
func NewHandler(iss *token.Issuer, box *cryptobox.Box, logger *slog.Logger) http.Handler {
	a := &api{iss: iss, box: box}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"commit": buildinfo.Commit, "buildTime": buildinfo.BuildTime})
	})
	mux.HandleFunc("POST /v1/tokens", a.createToken)
	mux.HandleFunc("GET /v1/me", a.me)
	mux.HandleFunc("POST /v1/encrypt", a.encrypt)
	mux.HandleFunc("POST /v1/decrypt", a.decrypt)
	return logRequests(logger, mux)
}

func (a *api) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Subject string `json:"subject"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Subject == "" || len(in.Subject) > maxSubjectLen {
		writeError(w, http.StatusBadRequest, "subject must be 1-64 characters")
		return
	}
	tok, exp, err := a.iss.Issue(in.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot issue token")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": tok, "expiresAt": exp.UTC().Format(time.RFC3339)})
}

func (a *api) me(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	sub, err := a.iss.Verify(raw)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"subject": sub})
}

func (a *api) encrypt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Plaintext string `json:"plaintext"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ct, err := a.box.Encrypt([]byte(in.Plaintext))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot encrypt")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

func (a *api) decrypt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ciphertext string `json:"ciphertext"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	plain, err := a.box.Decrypt(in.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot decrypt")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": string(plain)})
}

// readJSON decodes a size-limited body with no unknown fields and writes the 4xx itself on failure.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if _, tooBig := errors.AsType[*http.MaxBytesError](err); tooBig {
			writeError(w, http.StatusRequestEntityTooLarge, "request body larger than 1 MiB")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, path, status and duration; never headers or bodies.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"durationMs", time.Since(start).Milliseconds(),
		)
	})
}
