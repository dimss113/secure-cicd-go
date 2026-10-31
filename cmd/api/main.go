// Command api serves the secure-cicd-go HTTP API; "api healthcheck" probes it for Docker.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimss113/secure-cicd-go/internal/config"
	"github.com/dimss113/secure-cicd-go/internal/cryptobox"
	"github.com/dimss113/secure-cicd-go/internal/httpapi"
	"github.com/dimss113/secure-cicd-go/internal/token"
)

const (
	defaultConfigFile = "/run/config/config.json"
	defaultPort       = "8080"
	tokenTTL          = 15 * time.Minute
	shutdownTimeout   = 10 * time.Second
)

func main() {
	port := envOr("PORT", defaultPort)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(port))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger, port); err != nil {
		logger.Error("api stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger, port string) error {
	cfg, err := config.Load(envOr("CONFIG_FILE", defaultConfigFile))
	if err != nil {
		logger.Error("config invalid", "error", err.Error())
		os.Exit(1)
	}
	box, err := cryptobox.New(cfg.AESKey)
	if err != nil {
		return err
	}
	iss := token.NewIssuer(cfg.JWTSecret, tokenTTL, time.Now)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           httpapi.NewHandler(iss, box, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", srv.Addr, "env", cfg.Env)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func healthcheck(port string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
