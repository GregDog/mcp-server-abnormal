# Abnormal MCP Server

[![CI](https://github.com/GregDog/mcp-server-abnormal/actions/workflows/ci.yml/badge.svg)](https://github.com/GregDog/mcp-server-abnormal/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A secure, open-source [Model Context Protocol](https://modelcontextprotocol.io/) server for [Abnormal Security](https://abnormalsecurity.com/).

This project is **not** an official Abnormal product and is not endorsed by Abnormal AI.

## Overview

`abnormal-mcp` lets MCP clients such as Cursor and Claude Desktop query Abnormal Security over **stdio** (default) or **Streamable HTTP**. It uses a lightweight handwritten client against the [Abnormal Security Client API](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3).

```text
MCP Client
    → Abnormal MCP Server (stdio or HTTP)
        → Abnormal REST API
```

The server is read-only by default. Response and evidence download tools are opt-in and independent. Abnormal authorization still applies to every request.

## Features

**Read (always on)**

- Threat list and get from the Threat Log
- Threat links and attachment metadata
- Threat action status poll (`abnormal_threat_action_get`)
- Message search with ergonomic filters (`since`, `sender`, `sender_domain`, `recipient`, `subject`, `url`, `attachment`, `sender_ip`, `judgement`)
- Search activity list and status
- Message remediation history
- AI Security Mailbox (formerly Abuse Mailbox) campaigns and unanalyzed reports
- Employee profile, identity (Genome), and recent logins
- ATO case list, detail, and analysis
- Vendor list, detail, activity, and vendor compromise cases
- US, EU, and FedRAMP base URLs (configurable)

**Response (opt-in: `ABNORMAL_ALLOW_RESPONSE=true`)**

- Search remediation (`delete`, `move_to_inbox`) with `confirm: true` preview gate
- Threat remediate / unremediate with `confirm: true` preview gate
- ATO case status update with `confirm: true` preview gate

**Evidence download (opt-in: `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true`)**

- Message EML download (by ABX message ID or search `cloud_message_id`)
- Attachment analysis signals and attachment download
- Metadata + bounded preview by default; optional base64 embed (max 1 MiB in tool output)

- stdio transport (default) and opt-in Streamable HTTP
- Native Go binary and Docker image
- MCP Registry listing on tagged releases (`io.github.GregDog/mcp-server-abnormal`)

## Quick Start

Create an Abnormal REST API token in the Abnormal portal under Integrations → Abnormal REST API.

```bash
export ABNORMAL_API_TOKEN="your-token"
abnormal-mcp serve
```

## Installation

### From source

```bash
git clone https://github.com/GregDog/mcp-server-abnormal.git
cd mcp-server-abnormal
make build
```

### Docker

```bash
docker run --rm -i \
  -e ABNORMAL_API_TOKEN \
  ghcr.io/gregdog/mcp-server-abnormal serve
```

## Client configuration

### Cursor (stdio)

See [examples/cursor.mcp.json](examples/cursor.mcp.json).

### Claude Desktop

See [examples/claude-desktop.json](examples/claude-desktop.json).

## Tools

**24 read tools** are always registered. With `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true`, five evidence tools are added (29 total). With `ABNORMAL_ALLOW_RESPONSE=true`, three response tools are added (27 total, or 32 with both gates enabled).

| Area | Tools |
| --- | --- |
| Threats | `abnormal_threats_list`, `abnormal_threat_get`, `abnormal_threat_action_get`, `abnormal_threat_links_list`, `abnormal_threat_attachments_list` |
| Search | `abnormal_search_messages`, `abnormal_search_activities_list`, `abnormal_search_activity_get` |
| Messages | `abnormal_message_remediation_history` |
| Mailbox | `abnormal_mailbox_campaigns_list`, `abnormal_mailbox_campaign_get`, `abnormal_mailbox_unanalyzed_list` |
| Employees | `abnormal_employee_get`, `abnormal_employee_identity_get`, `abnormal_employee_logins_list` |
| ATO cases | `abnormal_cases_list`, `abnormal_case_get`, `abnormal_case_analysis_get`, `abnormal_case_action_get` |
| Vendors | `abnormal_vendors_list`, `abnormal_vendor_get`, `abnormal_vendor_activity_list`, `abnormal_vendor_cases_list`, `abnormal_vendor_case_get` |
| Evidence (opt-in) | `abnormal_message_eml_get`, `abnormal_search_message_eml_get`, `abnormal_message_attachment_get`, `abnormal_message_attachment_download`, `abnormal_search_attachment_download` |
| Response (opt-in) | `abnormal_search_remediate`, `abnormal_threat_remediate`, `abnormal_case_update` |

See [docs/tools.md](docs/tools.md) for parameters.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ABNORMAL_API_TOKEN` | (required) | Bearer token |
| `ABNORMAL_BASE_URL` | `https://api.abnormalplatform.com/v1` | API base URL |
| `ABNORMAL_ALLOW_RESPONSE` | `false` | Enable response tools (Phase 2+) |
| `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD` | `false` | Enable evidence download (Phase 5+) |
| `ABNORMAL_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |

Full list: [docs/configuration.md](docs/configuration.md).

## Security

Read tools are always on. Response and evidence tools require explicit opt-in.

**Local use only:** this server has no built-in authentication or RBAC. Use stdio (default) or loopback HTTP on the same machine. Do not expose the HTTP endpoint on a network without your own access controls.

See [docs/security.md](docs/security.md) and [SECURITY.md](SECURITY.md).

## Development

```bash
make check
make test-access   # optional live API smoke test
```

See [docs/development.md](docs/development.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
