# Security

Read tools are always available. Response tools are opt-in via `ABNORMAL_ALLOW_RESPONSE` or `--allow-response`. Evidence download tools are opt-in via `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD` or `--allow-evidence-download`. Enabling response does not enable evidence download.

High-impact response actions require `confirm: true`. Omitting it returns a preview and does not mutate.

A call succeeds only if:

```text
the MCP tool is enabled by server configuration (for response/evidence)
        AND
the Abnormal token is valid and permitted for that tenant
        AND
Abnormal authorization allows the operation
```

Use least-privilege API tokens with only the endpoint groups your workflow needs.

## Token handling

- Tokens are read from `ABNORMAL_API_TOKEN`.
- Bearer tokens and `Authorization` headers are redacted from error strings and logs.
- Tokens are not used as slog attributes.
- Do not put real tokens in git, issue reports, or example files.

## HTTP transport

The Streamable HTTP transport (`ABNORMAL_MCP_TRANSPORT=http`) is intended for **local development and trusted networks only**.

- **Default bind:** `127.0.0.1:8090` (loopback). The server does not default to `0.0.0.0` or bare `:port` addresses.
- **No built-in authentication:** HTTP mode does not validate MCP client identity. Anyone who can reach the endpoint can invoke tools using the server's configured Abnormal token.
- **Do not expose directly to the public internet.**
- **Remote or network deployment** requires a trusted external layer (reverse proxy, VPN, or private network) that performs authentication and access control before traffic reaches `abnormal-mcp`.
- **Non-loopback binds** log a startup warning.
- Request body size is capped (`ABNORMAL_MCP_HTTP_MAX_BODY_BYTES`, default 32 MiB). Server read/write/idle timeouts apply.
- No debug or pprof endpoints are registered.

## Request bounds

- HTTP timeout: 30 seconds
- Default page size: 20
- Maximum page size: 50
- No automatic retries in Phase 1

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md). Enable GitHub private vulnerability reporting and secret scanning on the repository.
