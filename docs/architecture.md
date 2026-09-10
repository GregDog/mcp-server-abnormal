# Architecture

```text
MCP Client (stdio or HTTP)
    → Abnormal MCP Server
        → Handwritten Abnormal REST client
            → Abnormal Security Client API (REST v1)
```

`abnormal-mcp serve` speaks MCP over **stdio by default** using the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). Set `ABNORMAL_MCP_TRANSPORT=http` (or `--transport http`) for **Streamable HTTP** instead. Logs go to stderr so they do not corrupt the stdio protocol on stdout.

The server constructs an Abnormal REST client at startup. It does not call Abnormal until a tool runs.

```text
cmd/abnormal-mcp        CLI: serve, version; stdio or HTTP transport
internal/config         Environment configuration
internal/abnormal       REST client, pagination, redaction
internal/tools          MCP tool handlers (read / response / evidence)
```

There is no built-in MCP authentication in HTTP mode. The Abnormal API token is process-wide configuration. This server is intended for **local use** (stdio or loopback HTTP). Network exposure without your own access controls is unsupported.

## Security model

```text
read tools are always available
        AND
response/evidence tools only when explicitly enabled
        AND
Abnormal token permissions
        AND
Abnormal authorization
```

## API limitations

Documented in [tools.md](tools.md):

- `GET /threats` pagination only works when a `filter` query parameter is set; without it the API returns only the top 100 threat IDs.
- `GET /threats/{id}` message paging is currently limited (about 10 messages per threat).
- Message search (`POST /search`) is synchronous; activity status endpoints track remediation operations.
- There is no `GET /messages/{id}` for full message bodies; use search/threat payloads or Phase 5 evidence download.
- `sender_domain` in `abnormal_search_messages` is implemented via `sender_email` regex because the API has no native domain filter.
- ATO case endpoints require an Account Takeover license on the tenant.
- `GET /employee/{email}/logins` returns CSV from the API; this server parses and bounds rows (max 50).
- Vendor and case list pagination follows the same `filter` + `pageSize` / `pageNumber` pattern as threats.

Official API reference: [Abnormal Security Client API v1.4.3](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3).

## Distribution

- **GitHub Releases** — binaries, checksums, SBOMs
- **GHCR** — `ghcr.io/gregdog/mcp-server-abnormal` Docker images
- **MCP Registry** — `io.github.GregDog/mcp-server-abnormal` (see [publishing.md](publishing.md))
