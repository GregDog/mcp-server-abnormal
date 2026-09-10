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

## Threat enrichment

### `abnormal_threat_links_list`

| Parameter | Description |
| --- | --- |
| `threat_id` | Threat ID (UUID) |

### `abnormal_threat_attachments_list`

| Parameter | Description |
| --- | --- |
| `threat_id` | Threat ID (UUID) |

## Employees

### `abnormal_employee_get`

| Parameter | Description |
| --- | --- |
| `email` | Employee email address |

### `abnormal_employee_identity_get`

Employee identity analysis (Genome) by email.

### `abnormal_employee_logins_list`

Recent login events (last 30 days). Returns bounded parsed rows, not raw CSV.

| Parameter | Description |
| --- | --- |
| `email` | Employee email address |
| `limit` | Max rows (default 50, max 50) |

## ATO cases

Requires Account Takeover license on the tenant.

### `abnormal_cases_list`

List ATO cases. Always applies `lastModifiedTime` filter (default last 24h).

### `abnormal_case_get` / `abnormal_case_analysis_get`

| Parameter | Description |
| --- | --- |
| `id` | Case ID |

### `abnormal_case_action_get`

| Parameter | Description |
| --- | --- |
| `case_id` | Case ID |
| `action_id` | Action ID from `abnormal_case_update` |

## Vendors (BEC)

### `abnormal_vendors_list`

List vendors your organization has interacted with.

### `abnormal_vendor_get` / `abnormal_vendor_activity_list`

| Parameter | Description |
| --- | --- |
| `vendor_domain` | Vendor email domain |

### `abnormal_vendor_cases_list`

List vendor compromise cases. Always applies `lastModifiedTime` filter (default last 24h).

### `abnormal_vendor_case_get`

| Parameter | Description |
| --- | --- |
| `id` | Vendor case ID |

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

### `abnormal_case_update`

Update ATO case status. Returns `action_id` — poll with `abnormal_case_action_get`.

| Parameter | Description |
| --- | --- |
| `confirm` | Must be `true` to execute |
| `id` | Case ID |
| `action` | `action_required`, `acknowledge_resolved`, `acknowledge_in_progress`, or `acknowledge_not_an_attack` |

## Evidence download (opt-in)

Enable with `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true` or `--allow-evidence-download`. These tools return metadata (content type, size, SHA256) and optional bounded preview or base64 — not raw binary by default.

| Tool | Description |
| --- | --- |
| `abnormal_message_eml_get` | Download EML by ABX `message_id` |
| `abnormal_search_message_eml_get` | Download EML by `cloud_message_id` from search |
| `abnormal_message_attachment_get` | Attachment analysis signals (JSON) |
| `abnormal_message_attachment_download` | Download attachment by ABX `message_id` and `attachment_name` |
| `abnormal_search_attachment_download` | Download attachment using search result identifiers |

Shared optional parameters on download tools:

| Parameter | Default | Description |
| --- | --- | --- |
| `include_preview` | `true` | Bounded text preview (4 KiB) for text-like content types |
| `include_content_base64` | `false` | Embed base64 when payload is under 1 MiB |

### `abnormal_message_eml_get`

| Parameter | Description |
| --- | --- |
| `message_id` | ABX message ID from threat or search results (`abnormal_message_id`) |

### `abnormal_search_message_eml_get`

| Parameter | Description |
| --- | --- |
| `cloud_message_id` | From `abnormal_search_messages` results |
| `quarantine_identity` | Required for quarantine source messages |
| `recipient_mailbox` | Required for quarantine source messages |

### `abnormal_message_attachment_get`

| Parameter | Description |
| --- | --- |
| `message_id` | ABX message ID |
| `attachment_name` | Attachment file name |

### `abnormal_message_attachment_download`

Same parameters as `abnormal_message_attachment_get`, plus optional `include_preview` and `include_content_base64`.

### `abnormal_search_attachment_download`

| Parameter | Description |
| --- | --- |
| `message_id` | Numeric message ID (parse from `abnormal_message_id` in search results) |
| `attachment_name` | Attachment file name |
| `tenant_id` | From search results |
| `raw_message_id` | From search results |
| `native_user_id` | From search results |
| `recipient_mailbox` | Recipient mailbox email (`mailbox_name` in search results) |

Outbound download size is capped by `ABNORMAL_MAX_EVIDENCE_BYTES` (default 10 MiB).
