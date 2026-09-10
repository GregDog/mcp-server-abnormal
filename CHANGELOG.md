# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Fixed

- Time-window filters on threat and mailbox list tools no longer prefix a duplicate `filter=` in the query value, so `receivedTime` / `lastReportedTime` ranges are applied.
- `abnormal_message_remediation_history` decodes `folder_locations` as `{name, display_name}` objects per the live API response.

### Added

- Phase 2: `abnormal_search_remediate`, `abnormal_threat_remediate` (gated by `ABNORMAL_ALLOW_RESPONSE`), and `abnormal_threat_action_get` (read-only status poll)
- Phase 1: threat list/get, message search, search activities, remediation history, AI Security Mailbox campaigns and unanalyzed reports
- stdio and Streamable HTTP transports
- Docker image and MCP Registry metadata
