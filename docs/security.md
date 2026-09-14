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

## Intended deployment: local use

This MCP server is designed for **local analyst workflows** (Cursor, Claude Desktop, or a local agent on the same machine). It does **not** implement authentication, authorization, or network access controls beyond basic HTTP hardening.

- **Default transport:** stdio (recommended). The Abnormal token stays in the local process environment.
- **HTTP transport:** loopback bind only by default (`127.0.0.1:8090`). No built-in MCP client authentication.
- **Do not expose** the HTTP endpoint on a LAN or the public internet and assume it is safe. There is no RBAC, API gateway, or session layer in this project.
- If you need shared or remote access, you must supply your own external controls (VPN, firewall, authenticated proxy). That is **out of scope** for this server.

## Token handling

- Tokens are read from `ABNORMAL_API_TOKEN`.
- Bearer tokens and `Authorization` headers are redacted from error strings and logs.
- Tokens are not used as slog attributes.
- Do not put real tokens in git, issue reports, or example files.

## HTTP transport

The Streamable HTTP transport (`ABNORMAL_MCP_TRANSPORT=http`) is for **local development on the same machine**.

- **Default bind:** `127.0.0.1:8090` (loopback). The server does not default to `0.0.0.0` or bare `:port` addresses.
- **No built-in authentication:** HTTP mode does not validate MCP client identity. Anyone who can reach the endpoint can invoke tools using the server's configured Abnormal token.
- **Non-loopback binds** log a startup warning.
- Request body size is capped (`ABNORMAL_MCP_HTTP_MAX_BODY_BYTES`, default 32 MiB). Server read/write/idle timeouts apply.
- No debug or pprof endpoints are registered.

## Request bounds

- Outbound Abnormal API timeout: 30 seconds per attempt
- Automatic retries: `ABNORMAL_HTTP_MAX_RETRIES` (default 2) on HTTP 429, 502, 503, and 504 with exponential backoff and `Retry-After` support
- Default page size: 20; maximum page size: 50
- Outbound JSON responses capped at 16 MiB; text/CSV at 4 MiB
- Tool outputs bound large slices (contacts, timelines, genome entries, link lists)

## Response action audit log

Confirmed response tool executions (`confirm: true`) — including remediation, case updates, and Detection 360 report submission — emit structured `slog` info lines with tool name, resource type/id, and action. Tokens and message bodies are never logged.

## Evidence access audit log

Evidence download tool calls emit structured `slog` info lines with tool name, resource identifier, and payload size. Raw file contents and `content_base64` values are never logged (`content_base64` fields in log text are redacted).

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md). Enable GitHub private vulnerability reporting and secret scanning on the repository.
