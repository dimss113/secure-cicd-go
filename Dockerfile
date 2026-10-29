# syntax=docker/dockerfile:1

# Both bases are pinned by digest so a rebuild never pulls an unscanned image.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG COMMIT=dev
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/dimss113/secure-cicd-go/internal/buildinfo.Commit=${COMMIT} -X github.com/dimss113/secure-cicd-go/internal/buildinfo.BuildTime=${BUILD_TIME}" \
    -o /out/app ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/app /app
USER root
EXPOSE 8080
# Distroless has no shell or curl, so the binary probes itself.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
