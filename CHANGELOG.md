# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Phase 5 evidence download tools (gated by `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD`): EML and attachment download with metadata, bounded preview, and optional base64 embed; attachment analysis signals; evidence access audit logging
- Phase 6 hardening: HTTP retry/backoff on 429 and 5xx, bounded tool outputs, structured HTTP errors, response action audit logging, and local-only deployment documentation (no RBAC/gateway in scope)

### Fixed

- Time-window filters on threat and mailbox list tools no longer prefix a duplicate `filter=` in the query value, so `receivedTime` / `lastReportedTime` ranges are applied.
- `abnormal_message_remediation_history` decodes `folder_locations` as `{name, display_name}` objects per the live API response.

### Added

- Phase 3: threat links/attachments, employee profile/identity/logins, ATO case list/detail/analysis/action status, and gated `abnormal_case_update`
- Phase 4: vendor list/detail/activity and vendor case list/detail
- Phase 2: `abnormal_search_remediate`, `abnormal_threat_remediate` (gated by `ABNORMAL_ALLOW_RESPONSE`), and `abnormal_threat_action_get` (read-only status poll)
- Phase 1: threat list/get, message search, search activities, remediation history, AI Security Mailbox campaigns and unanalyzed reports
- stdio and Streamable HTTP transports
- Docker image and MCP Registry metadata
