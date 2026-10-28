COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X github.com/dimss113/secure-cicd-go/internal/buildinfo.Commit=$(COMMIT) -X github.com/dimss113/secure-cicd-go/internal/buildinfo.BuildTime=$(BUILD_TIME)

.PHONY: test lint run build

test:
	go test -race ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

# Dummy secrets from testdata; never a real config.
run:
	CONFIG_FILE=./testdata/config.json go run ./cmd/api

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/api ./cmd/api
