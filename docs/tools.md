# Tools

All tools are read-only in Phase 1. Tool names are prefixed with `abnormal_`.

## Threats

### `abnormal_threats_list`

List threat campaigns from the Abnormal Threat Log.

| Parameter | Description |
| --- | --- |
| `since` | Start of `receivedTime` filter (RFC3339). Default last 24 hours. |
| `until` | End of `receivedTime` filter (RFC3339). Default now. |
| `source` | `all`, `attacks`, `borderline`, or `spam` |
| `sender`, `recipient`, `subject` | Optional filters |
| `attack_type` | Optional attack type filter |
| `limit` | Page size (default 20, max 50) |
| `cursor` | Page number from a previous response |

Always applies a `receivedTime` filter so pagination works.

### `abnormal_threat_get`

Get threat campaign details by UUID.

| Parameter | Description |
| --- | --- |
| `id` | Threat ID (UUID) |

Returns bounded message metadata. The API currently returns at most about 10 messages per threat.

## Search

### `abnormal_search_messages`

Search email messages across Abnormal and quarantine sources.

| Parameter | Maps to |
| --- | --- |
| `since` / `until` | Required time window (defaults: last 24h → now) |
| `sender` | `sender_email` |
| `sender_domain` | `sender_email` regex `.*@domain$` |
| `recipient` | `recipient_email` |
| `subject` | `subject` |
| `url` | `body_link` |
| `attachment` | `attachment_name` |
| `sender_ip` | `sender_ip` |
| `judgement` | `attack`, `borderline`, `spam`, `graymail`, or `safe` |
| `judgement_source` | `ABNORMAL_SYSTEM` or `CUSTOMER_AI_MODEL` |
| `internet_message_id` | `internet_message_id` |
| `source` | `abnormal` (default) or `quarantine` |
| `limit`, `cursor` | Pagination |

Do not set both `sender` and `sender_domain`.

### `abnormal_search_activities_list`

List activity logs for search and remediation operations.

### `abnormal_search_activity_get`

| Parameter | Description |
| --- | --- |
| `activity_log_id` | Activity ID from a remediation response |

## Messages

### `abnormal_message_remediation_history`

| Parameter | Description |
| --- | --- |
| `message_id` | ABX message ID (numeric) |

## AI Security Mailbox

### `abnormal_mailbox_campaigns_list`

List user-reported phishing campaigns. Uses `lastReportedTime` filter (default last 24h).

### `abnormal_mailbox_campaign_get`

| Parameter | Description |
| --- | --- |
| `id` | Campaign UUID |

### `abnormal_mailbox_unanalyzed_list`

List mailbox submissions that were not analyzed. Optional `since` / `until` (RFC3339).
