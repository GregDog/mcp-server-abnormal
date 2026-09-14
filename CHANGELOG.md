# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Detection 360 tools: `abnormal_detection360_reports_list` (read) and `abnormal_detection360_report_submit` (gated by `ABNORMAL_ALLOW_RESPONSE` with `confirm: true`) for false positives and missed email reports
- URL rewrite click events: `abnormal_url_rewrite_clicks_list` (`GET /url-rewrite/clicked-events`)
- Portal audit logs: `abnormal_audit_logs_list` (`GET /auditlogs`)

## [1.0.1] - 2026-09-10

### Fixed

- Shorten MCP Registry `server.json` description to satisfy the 100-character validation limit

## [1.0.0] - 2026-09-10

First release with all six planned phases: core investigation, response, enrichment, vendor/BEC, evidence download, and hardening.

### Added

- Phase 1: threat list/get, message search, search activities, remediation history, AI Security Mailbox campaigns and unanalyzed reports
- Phase 2: `abnormal_search_remediate`, `abnormal_threat_remediate` (gated by `ABNORMAL_ALLOW_RESPONSE`), and `abnormal_threat_action_get`
- Phase 3: threat links/attachments, employee profile/identity/logins, ATO case list/detail/analysis/action status, and gated `abnormal_case_update`
- Phase 4: vendor list/detail/activity and vendor case list/detail
- Phase 5: evidence download tools (gated by `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD`) for EML and attachments with metadata, bounded preview, and optional base64 embed
- Phase 6: HTTP retry/backoff on 429 and 5xx, bounded tool outputs, structured HTTP errors, response/evidence audit logging, and local-only security documentation
- stdio and Streamable HTTP transports
- Docker image, GoReleaser, CI/CodeQL, and MCP Registry metadata

### Fixed

- Time-window filters on threat and mailbox list tools no longer prefix a duplicate `filter=` in the query value
- `abnormal_message_remediation_history` decodes `folder_locations` as `{name, display_name}` objects per the live API response

[1.0.1]: https://github.com/GregDog/mcp-server-abnormal/releases/tag/v1.0.1
[1.0.0]: https://github.com/GregDog/mcp-server-abnormal/releases/tag/v1.0.0
