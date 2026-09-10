# Tools

Tool names are prefixed with `abnormal_`. Read tools are always available. Response tools require `ABNORMAL_ALLOW_RESPONSE=true` and `confirm: true` on each call.

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

### `abnormal_threat_action_get`

Poll the status of a threat remediate or unremediate action.

| Parameter | Description |
| --- | --- |
| `threat_id` | Threat ID (UUID) |
| `action_id` | Action ID from `abnormal_threat_remediate` |

Always available (read-only).

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

## Response (opt-in)

Enable with `ABNORMAL_ALLOW_RESPONSE=true` or `--allow-response`. All response tools require `confirm: true`; omitting it returns a preview only.

### `abnormal_search_remediate`

Delete or move messages from search results. Returns `activity_log_id` — poll with `abnormal_search_activity_get`.

| Parameter | Description |
| --- | --- |
| `confirm` | Must be `true` to execute |
| `action` | `delete` or `move_to_inbox` |
| `remediation_reason` | `false_negative`, `unsolicited`, `other`, `groups_remediation`, or `quarantine_release` |
| `source` | `abnormal` (default) or `quarantine` |
| `target_folder` | Required when `action` is `move_to_inbox` |
| `remediate_all` | When `true`, remediate all messages matching search filters |
| `messages` | Specific messages when `remediate_all` is `false` |
| `since` / `until`, `sender`, `recipient`, etc. | Search filters when `remediate_all` is `true` (same mapping as `abnormal_search_messages`) |

### `abnormal_threat_remediate`

Remediate or restore (unremediate) all messages in a threat campaign. Returns `action_id` — poll with `abnormal_threat_action_get`.

| Parameter | Description |
| --- | --- |
| `confirm` | Must be `true` to execute |
| `id` | Threat ID (UUID) |
| `action` | `remediate` or `unremediate` |
