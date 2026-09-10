# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Fixed

- Time-window filters on threat and mailbox list tools no longer prefix a duplicate `filter=` in the query value, so `receivedTime` / `lastReportedTime` ranges are applied.

### Added

- Phase 1: threat list/get, message search, search activities, remediation history, AI Security Mailbox campaigns and unanalyzed reports
- stdio and Streamable HTTP transports
- Docker image and MCP Registry metadata
