# Config and template are baked in: a template change changes the image, so compose recreates
# the container instead of serving a stale render.
FROM hashicorp/vault:2.2.1@sha256:962a92876e168d68eaaa24b0b8b49bbce1cb63024060a67bba95cd158a366fc2
COPY --chmod=0444 agent.hcl config.json.ctmpl /vault/config/
COPY --chmod=0555 entrypoint.sh /usr/local/bin/agent-entrypoint.sh
# Same UID as the app, so the 0400 config.json is readable by the app and nobody else.
USER 65532:65532
HEALTHCHECK --interval=3s --timeout=3s --start-period=5s --retries=30 CMD ["test", "-s", "/vault/out/config.json"]
ENTRYPOINT ["/usr/local/bin/agent-entrypoint.sh"]
