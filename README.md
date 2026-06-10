```text
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███████╗ ██████╗ ██████╗ ████████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║██║███████╗███████║█████╗  ██║   ██║██████╔╝   ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══╝  ██║   ██║██╔══██╗   ██║
██║     ██║  ██║██║███████║██║  ██║██║     ╚██████╔╝██║  ██║   ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝

                         ███╗   ███╗ ██████╗██████╗
                         ████╗ ████║██╔════╝██╔══██╗
                         ██╔████╔██║██║     ██████╔╝
                         ██║╚██╔╝██║██║     ██╔═══╝
                         ██║ ╚═╝ ██║╚██████╗██║
                         ╚═╝     ╚═╝ ╚═════╝╚═╝

        MCP server + paired agent skill for PhishFort workflows
        approval-gated writes | secret-safe defaults | no URL fetching
```

# phishfort-mcp

**A security-first MCP server and paired agent skill for the PhishFort Unified Client API.**

Bring PhishFort incident review, reporting, attachments, comments, and webhook management into your MCP client, then give your agent the workflow playbook for using those tools safely.

[Paired skill](skills/phishfort-mcp/SKILL.md) | [Official PhishFort API docs](https://phishfort.github.io/unified-client-api-docs/) | [Security review](docs/reference/mcp-security-review.md) | [Local reference](docs/reference/phishfort-unified-client-api.md)

> Unofficial project. Not affiliated with, endorsed by, or maintained by PhishFort.

## Standards-Backed Security Posture

This server was designed against the [Official Model Context Protocol security guidance](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), [Anthropic connector guidance](https://claude.com/docs/connectors/building/mcp), [OpenAI MCP guidance](https://developers.openai.com/api/docs/mcp), [OpenAI agent safety guidance](https://developers.openai.com/api/docs/guides/agent-builder-safety), and [PhishFort's official API docs](https://phishfort.github.io/unified-client-api-docs/). The table below lists only security features that are implemented in code, with local evidence.

Local evidence:

- [MCP security review](docs/reference/mcp-security-review.md)
- [PhishFort API reference](docs/reference/phishfort-unified-client-api.md)
- [Source manifest](docs/reference/source-manifest.json)

| Security feature | What it prevents | Confirmed implementation |
| --- | --- | --- |
| Local `stdio` transport only | Avoids exposing a public HTTP MCP surface in v1 | `server.main()` rejects non-`stdio` transport |
| Two-step approval gate for writes | Forces an explicit plan→confirm step with a tamper-evident digest before any mutation. This is in-process integrity/confirmation, **not** independent human authorization — the host UI provides the human prompt via the destructive hints below | Write tools require `approval_id`, `approval_phrase`, `expires_at`, `request_digest`; `_validate_approval()` recomputes the digest from the actual params |
| Tamper-resistant approval digest | Blocks changing params after approval planning | `approval.py` canonicalizes params and verifies `request_digest`; covered by `test_approval_rejects_tampered_params` |
| Destructive confirmation | Adds explicit friction for delete/rotate operations | Destructive specs require `destructive_confirmed=true`; covered by `test_destructive_operation_requires_confirmed` |
| Read/write MCP annotations | Gives MCP hosts correct safety hints | `_read_annotations()` and `_write_annotations()` set read-only/destructive/idempotent hints |
| API keys never passed as tool args | Reduces credential leakage through prompts/tool logs | `Settings` reads `PHISHFORT_API_KEY` or `PHISHFORT_API_KEY_FILE`; tool signatures do not accept API keys |
| Default API host pinning | Avoids accidental credential use against arbitrary hosts | `Settings.validate_base_url()` requires `https://capi.phishfort.com/v1` unless explicit override is enabled |
| Redirects disabled | Avoids following API responses to unexpected locations | `httpx.AsyncClient(..., follow_redirects=False)` |
| Error redaction | Prevents API keys and secret-named fields from leaking through raised API errors | `PhishFortClient._error()` applies `redact()` (key value plus recursive `secret`/`token`/`apiKey` key masking); covered by `test_error_redacts_api_key` and `test_error_redacts_secret_keys` |
| Untrusted data warnings | Reminds agents not to treat incident content as instructions | `response_envelope()` adds `untrusted_data_warning` to PhishFort data outputs |
| No generic URL fetching | Avoids browsing hostile URLs returned in incident data | Server exposes PhishFort API tools only; no tool fetches incident URLs |
| Attachment file restrictions | Reduces local file exfiltration risk | `validate_attachment_paths()` enforces roots, extensions, max 12 files, and 10 MiB cap; `open_attachments()` holds `O_NOFOLLOW` fds to close the validate→open race; covered by attachment tests |
| Webhook URL preflight (defense-in-depth) | Rejects localhost/private/reserved targets — including legacy decimal/octal/hex IP forms — before a webhook is registered. The server never fetches the URL itself (PhishFort delivers webhooks), so backend egress controls remain the real boundary | `validate_webhook_url()` and `is_private_host()`; covered by webhook URL tests |
| Webhook secret containment | Keeps one-time secrets out of tool output | `_handle_secret_response()` recursively strips `secret`/`token`/`apiKey` keys at any depth; `write_secret_file()` writes `0600` with `O_NOFOLLOW`; covered by secret tests |
| Webhook signature verification | Enables receiver-side HMAC verification | `verify_signature()` uses HMAC-SHA256 and `hmac.compare_digest()`; covered by `test_verify_signature` |
| Limit-aware behavior | Avoids known API limit failures where possible | `phishfort_get_limits`, `reference_limits`, incident limit clamp, webhook 5-subscription preflight; covered by `tests/test_limits.py` |
| Bounded retry behavior | Avoids unsafe retry storms or unbounded sleeps | Retries only `429`/`5xx` and transport errors, caps the retry count at 5, treats terminal statuses as terminal, caps `Retry-After`; covered by retry tests |

## About

`phishfort-mcp` is a public, unofficial MCP integration for teams and operators who want PhishFort incident workflows available inside agentic tools without giving up basic operational control. The MCP server provides live API access; the paired skill gives compatible agents the workflow memory needed to use that access consistently.

It is built for local-first use, explicit approvals, and careful handling of phishing data. The goal is not to make incident response fully autonomous. The goal is to make the repetitive parts faster while keeping sensitive actions, secrets, and untrusted content under control.

## Why This Exists

PhishFort has a focused REST API for phishing incident workflows. MCP makes that API usable from agentic tools, and the paired skill teaches those agents the operating procedure: what to read first, how to plan writes, what data is untrusted, and when to stop for explicit approval.

That pairing matters because security workflows are not just API calls. Incident data can contain hostile text, URLs should not be fetched casually, and takedown or webhook operations should not happen from a loose prompt.

`phishfort-mcp` ships two pieces that work together:

- a local `stdio` MCP server for live PhishFort API access
- an agent-agnostic skill that turns raw tool access into repeatable, safer workflows
- approval-gated writes for reporting, actions, evidence, comments, and webhooks
- secret-safe handling for API keys and one-time webhook secrets
- untrusted-data guardrails for incident text, URLs, and webhook payloads

## What You Can Do

| Workflow | Tools |
| --- | --- |
| Give agents the PhishFort operating playbook | `skills/phishfort-mcp/SKILL.md` |
| Check documented API limits | `phishfort_get_limits` |
| Check identity and client scope | `phishfort_whoami` |
| Search and inspect incidents | `phishfort_list_incidents`, `phishfort_get_incident`, `phishfort_find_incident_by_subject` |
| Report URLs, domains, emails, phones, and IPv4 subjects | `phishfort_report_incident` |
| Request takedown, monitoring, or safe review | `phishfort_request_incident_action` |
| Add evidence and analyst context | `phishfort_add_attachments`, `phishfort_add_comment` |
| Manage webhook subscriptions | `phishfort_list_webhooks`, `phishfort_create_webhook`, `phishfort_update_webhook`, `phishfort_delete_webhook`, `phishfort_test_webhook`, `phishfort_rotate_webhook_secret` |
| Verify incoming webhook deliveries | `phishfort_verify_webhook_signature` |

The server also exposes MCP resources for the distilled API reference, source manifest, and security review:

- `phishfort://reference/summary`
- `phishfort://reference/limits`
- `phishfort://reference/source-manifest`
- `phishfort://reference/security-review`

## Paired Skill

This repo ships an agent-agnostic skill in [skills/phishfort-mcp/SKILL.md](skills/phishfort-mcp/SKILL.md). Use it with any skill-capable MCP host to teach the agent the safe operating pattern for this server: read before write, treat incident data as untrusted, never fetch returned URLs by default, and use `phishfort_plan_change` before mutating calls.

The skill keeps detailed workflows in [references/workflows.md](skills/phishfort-mcp/references/workflows.md), exact tool parameters in [references/tool-map.md](skills/phishfort-mcp/references/tool-map.md), and points agents to `phishfort_get_limits` before workflows where limits change the right next step.

## Safety Built In

The standards-backed table above is the detailed proof. Operationally, the server stays local-first, keeps credentials out of tool arguments, treats PhishFort data as untrusted, gates writes through `phishfort_plan_change`, stores webhook secrets outside tool output, and constrains attachments, webhook URLs, limits, and retries.

See [MCP security review](docs/reference/mcp-security-review.md) for the reasoning behind these choices.

## Quick Start

```bash
git clone https://github.com/mychaelconnolly/phishfort-mcp.git
cd phishfort-mcp
uv sync --extra dev
```

Create a local key file:

```bash
mkdir -p ~/.config/phishfort-mcp
chmod 700 ~/.config/phishfort-mcp
$EDITOR ~/.config/phishfort-mcp/phishfort-api-key.txt
chmod 600 ~/.config/phishfort-mcp/phishfort-api-key.txt
```

Run a local CLI smoke:

```bash
uv run phishfort-mcp --help
```

## Codex MCP Registration

```bash
codex mcp add phishfort \
  --env PHISHFORT_API_KEY_FILE=$HOME/.config/phishfort-mcp/phishfort-api-key.txt \
  -- uv --directory <path-to-phishfort-mcp> run phishfort-mcp
```

Then verify:

```bash
codex mcp list
```

A fresh Codex session may be required before new MCP tools are discoverable.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISHFORT_API_BASE_URL` | `https://capi.phishfort.com/v1` | Pinned to official API host unless override is enabled. |
| `PHISHFORT_API_KEY` | unset | Useful for short-lived local shells. |
| `PHISHFORT_API_KEY_FILE` | unset | Preferred for MCP registration. |
| `PHISHFORT_SECRET_DIR` | `~/.config/phishfort-mcp/secrets` | Webhook secrets are written here with `0600` permissions. |
| `PHISHFORT_ATTACHMENT_ROOTS` | `.` | Comma-separated roots allowed for attachment uploads. |
| `PHISHFORT_TIMEOUT_SECONDS` | `30` | HTTP request timeout. |
| `PHISHFORT_MAX_RETRIES` | `3` | Retries apply to `429`, `5xx`, and transport errors; capped at 5; `Retry-After` on `429` is capped locally. |
| `PHISHFORT_ALLOW_CUSTOM_BASE_URL` | `false` | Test-only escape hatch for non-production API hosts. |
| `PHISHFORT_ALLOW_UNSAFE_WEBHOOK_URL` | `false` | Test-only escape hatch for localhost/private webhook targets. |

## Approval-Gated Writes

Read tools can be called directly. Writes are two-step on purpose:

1. Call `phishfort_plan_change` with `operation` and exact params.
2. Review `warnings`, `risk`, `request_digest`, and `approval_phrase`.
3. Call the intended mutating tool with the same params plus `approval_id`, `approval_phrase`, `expires_at`, and `request_digest`.

If anything changes, rerun `phishfort_plan_change`.

This gate is in-process integrity and confirmation: it proves the executed params
match the planned params (tamper-evident digest), enforces expiry, and requires
`destructive_confirmed=true` for destructive operations. It is **not** an independent
authorization boundary — the same agent can plan and confirm. The human-in-the-loop
checkpoint is the MCP host's own tool-confirmation UI, driven by the destructive
annotations the server sets.

## Verification

```bash
uv run ruff check .
uv run pytest
```

Optional live smoke when a valid key exists:

- `phishfort_whoami`
- `phishfort_list_incidents(limit=1)`

Do not run live mutating smoke unless you intend to change PhishFort state.

## API Reference

Official PhishFort docs:

- [Introduction](https://phishfort.github.io/unified-client-api-docs/)
- [Authentication](https://phishfort.github.io/unified-client-api-docs/auth/)
- [Limits](https://phishfort.github.io/unified-client-api-docs/limits/)
- [Incident Lifecycle](https://phishfort.github.io/unified-client-api-docs/incident-lifecycle/)
- [List Incidents](https://phishfort.github.io/unified-client-api-docs/incidents/)
- [Single Incident](https://phishfort.github.io/unified-client-api-docs/single-incident/)
- [Report Incident](https://phishfort.github.io/unified-client-api-docs/report-incident/)
- [Request Incident Action](https://phishfort.github.io/unified-client-api-docs/request-incident-review/)
- [Add Attachments](https://phishfort.github.io/unified-client-api-docs/add-attachments/)
- [Add Comment](https://phishfort.github.io/unified-client-api-docs/add-comment/)
- [Webhooks](https://phishfort.github.io/unified-client-api-docs/webhooks/)
- [Data Structures](https://phishfort.github.io/unified-client-api-docs/structures/)

This repo includes a distilled reference in [docs/reference/phishfort-unified-client-api.md](docs/reference/phishfort-unified-client-api.md) and a source URL manifest in [docs/reference/source-manifest.json](docs/reference/source-manifest.json). Fetched raw PhishFort docs are intentionally not tracked.

## License

MIT. See [LICENSE](LICENSE).
