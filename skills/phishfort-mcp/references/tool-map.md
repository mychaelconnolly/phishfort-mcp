# PhishFort MCP Tool Map

Use exact names when available. If the MCP host prefixes or namespaces tools, match by the final semantic name.

## Read Tools

| Tool | Purpose | Key params |
| --- | --- | --- |
| `phishfort_list_capabilities` | Show supported operations and approval policy. | none |
| `phishfort_get_limits` | Show documented API limits and MCP-enforced limit choices. | none |
| `phishfort_whoami` | Check auth/client identity and client scope. | none |
| `phishfort_list_incidents` | List incidents with filters and pagination. | `client_id`, `from_date`, `to_date`, `status`, `limit`, `cursor` |
| `phishfort_get_incident` | Fetch one incident by id. | `incident_id` |
| `phishfort_find_incident_by_subject` | Fetch one incident by URL, domain, email, phone, IPv4, or subject. | `subject` |
| `phishfort_list_webhooks` | List webhook subscriptions. | none |
| `phishfort_verify_webhook_signature` | Verify a received webhook HMAC signature. | `signature`, `timestamp`, `raw_body`, `secret_file` or `secret` |

## Approval Tool

Use `phishfort_plan_change` before every mutating tool.

Required planning params:

- `operation`: one of the operation names below.
- `params`: exact params that will be passed to the mutating tool, excluding approval fields.
- `expires_in_seconds`: optional; defaults to 900.

Returned approval fields to reuse unchanged:

- `approval_id`
- `approval_phrase`
- `expires_at`
- `request_digest`
- `destructive_confirmed_required`

If any operation param changes, discard the plan and call `phishfort_plan_change` again.

## Mutating Tools

| Operation for `phishfort_plan_change` | Write tool | Required params before approval fields | Notes |
| --- | --- | --- | --- |
| `report_incident` | `phishfort_report_incident` | `action` plus either `url`, or `incident_type` and `subject` | `action` is `tkd` or `monitor`; optional `reported_by`, `client_id`, `comment`, `attachment_paths`. |
| `request_incident_action` | `phishfort_request_incident_action` | `incident_id`, `action` | `action` is `tkd`, `monitor`, or `safe`. Treat `safe` as high-impact user intent. |
| `add_attachments` | `phishfort_add_attachments` | `incident_id`, `attachment_paths` | Supported extensions only; max 12 files; total request under 10 MiB. |
| `add_comment` | `phishfort_add_comment` | `incident_id`, `comment` | Comment must be nonblank. |
| `create_webhook` | `phishfort_create_webhook` | `url`, `events` | Optional `description`, `secret_output_name`; secret is saved locally, not returned. Server preflights max 5 subscriptions. |
| `update_webhook` | `phishfort_update_webhook` | `webhook_id` plus at least one update field | Optional `url`, `events`, `active`, `description`. |
| `delete_webhook` | `phishfort_delete_webhook` | `webhook_id` | Destructive; requires `destructive_confirmed=true`. |
| `test_webhook` | `phishfort_test_webhook` | `webhook_id` | Sends a test delivery. |
| `rotate_webhook_secret` | `phishfort_rotate_webhook_secret` | `webhook_id` | Destructive; invalidates previous secret immediately and requires `destructive_confirmed=true`. |

Every write tool also needs:

- `approval_id`
- `approval_phrase`
- `expires_at`
- `request_digest`
- `destructive_confirmed`, default false

## MCP Resources

| Resource | Use |
| --- | --- |
| `phishfort://reference/summary` | Distilled API behavior, endpoints, limits, structures, and webhook signature details. |
| `phishfort://reference/limits` | JSON summary of pagination, attachment, retry, and webhook limits. |
| `phishfort://reference/source-manifest` | Official docs URL set used for the local reference. |
| `phishfort://reference/security-review` | Security choices behind the MCP server and skill workflows. |

## Valid Values

Incident list `status` values:

- `pending_review`
- `case_building`
- `approval_required`
- `takedown_ready`
- `takedown_in_progress`
- `takedown_success`
- `takedown_attempt_failed`
- `blocklisted`
- `pre_weaponised`
- `action_required`
- `closed`

Report `incident_type` values:

- `email`
- `phone`
- `ipv4`

Webhook event values:

- `incident.created`
- `incident.status_changed`
- `incident.history_created`
- `incident.takedown_updated`
- `incident.action_required`
