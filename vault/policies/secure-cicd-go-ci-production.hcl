# CI deploy job (production): read the Dokploy API key, nothing else.
path "static-secret/data/secure-cicd-go/ci/production/dokploy" {
  capabilities = ["read"]
}
