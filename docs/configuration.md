# Configuration

Configuration is environment-based.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ABNORMAL_API_TOKEN` | yes | | Abnormal REST API bearer token |
| `ABNORMAL_BASE_URL` | no | `https://api.abnormalplatform.com/v1` | API base URL (US default). EU: `https://eu.rest.abnormalsecurity.com/v1`. FedRAMP: `https://rest.abnormalsecurity.us/v1` |
| `ABNORMAL_MOCK_DATA` | no | `false` | Send `Mock-Data: True` header for official test data |
| `ABNORMAL_MCP_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, or `error` |
| `ABNORMAL_ALLOW_RESPONSE` | no | `false` | Enable response MCP tools when `true`, `1`, `yes`, or `on` |
| `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD` | no | `false` | Enable evidence download MCP tools when `true`, `1`, `yes`, or `on` |
| `ABNORMAL_MCP_TRANSPORT` | no | `stdio` | `stdio` or `http` |
| `ABNORMAL_MCP_HTTP_ADDR` | no | `127.0.0.1:8090` | Loopback listen address when `ABNORMAL_MCP_TRANSPORT=http` |
| `ABNORMAL_MCP_HTTP_JSON` | no | `false` | Use `application/json` responses for HTTP transport |
| `ABNORMAL_MCP_HTTP_MAX_BODY_BYTES` | no | `33554432` | Max HTTP request body size (32 MiB) |

You can also pass `--allow-response`, `--allow-evidence-download`, `--transport`, `--http-addr`, or `--http-json` to `abnormal-mcp serve`. Response and evidence download are independent.

Create tokens in the Abnormal portal under Integrations → Abnormal REST API. The token value is shown once.

The API token is never written to logs.
