# CI deploy job (development): read the Dokploy API key, nothing else.
path "static-secret/data/secure-cicd-go/ci/development/dokploy" {
  capabilities = ["read"]
}
