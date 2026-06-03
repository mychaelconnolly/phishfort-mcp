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

        PhishFort Unified Client API -> local stdio MCP tools
        approval-gated writes | secret-safe by default | no URL fetching
```

# phishfort-mcp

**A security-first local MCP bridge for the PhishFort Unified Client API.**

Bring PhishFort incident review, reporting, attachments, comments, and webhook management into your MCP client without handing API keys to tool calls or letting automation mutate state without an approval gate.

[Official PhishFort API docs](https://phishfort.github.io/unified-client-api-docs/) | [Security review](docs/reference/mcp-security-review.md) | [Local reference](docs/reference/phishfort-unified-client-api.md)

> Unofficial project. Not affiliated with, endorsed by, or maintained by PhishFort.

## Why This Exists

PhishFort has a focused REST API for phishing incident workflows. MCP makes that API usable from agentic tools, but security matters: incident data can contain hostile text, URLs should not be fetched casually, and takedown or webhook operations should not happen from a loose prompt.

`phishfort-mcp` wraps the API as local `stdio` MCP tools with conservative defaults:

- read incident and webhook state quickly
- report takedown or monitoring requests when you mean to
- attach evidence without exposing arbitrary local files
- manage webhooks without leaking one-time secrets
- require explicit approval fields before any mutating API call

## What You Can Do

| Workflow | Tools |
| --- | --- |
| Check identity and client scope | `phishfort_whoami` |
| Search and inspect incidents | `phishfort_list_incidents`, `phishfort_get_incident`, `phishfort_find_incident_by_subject` |
| Report URLs, domains, emails, phones, and IPv4 subjects | `phishfort_report_incident` |
| Request takedown, monitoring, or safe review | `phishfort_request_incident_action` |
| Add evidence and analyst context | `phishfort_add_attachments`, `phishfort_add_comment` |
| Manage webhook subscriptions | `phishfort_list_webhooks`, `phishfort_create_webhook`, `phishfort_update_webhook`, `phishfort_delete_webhook`, `phishfort_test_webhook`, `phishfort_rotate_webhook_secret` |
| Verify incoming webhook deliveries | `phishfort_verify_webhook_signature` |

The server also exposes MCP resources for the distilled API reference, source manifest, and security review:

- `phishfort://reference/summary`
- `phishfort://reference/source-manifest`
- `phishfort://reference/security-review`

## Paired Skill

This repo ships an agent-agnostic skill in [skills/phishfort-mcp/SKILL.md](skills/phishfort-mcp/SKILL.md). Use it with any skill-capable MCP host to teach the agent the safe operating pattern for this server: read before write, treat incident data as untrusted, never fetch returned URLs by default, and use `phishfort_plan_change` before mutating calls.

The skill keeps detailed workflows in [references/workflows.md](skills/phishfort-mcp/references/workflows.md) and exact tool parameters in [references/tool-map.md](skills/phishfort-mcp/references/tool-map.md).

## Safety Built In

- `stdio` transport only for v1.
- Credentials come from `PHISHFORT_API_KEY` or `PHISHFORT_API_KEY_FILE`; never from tool arguments.
- Incident data, comments, history, URLs, attachment metadata, and webhook payloads are treated as untrusted.
- URLs returned by PhishFort are never fetched by the server.
- Mutating tools require an expiring approval envelope from `phishfort_plan_change`.
- Destructive writes require `destructive_confirmed=true`.
- Webhook create/rotate secrets are saved to `0600` files and removed from tool output.
- Attachment uploads are restricted to configured local roots, safe extensions, max 12 files, and 10 MiB total request size.
- Default API base is pinned to `https://capi.phishfort.com/v1`.

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
| `PHISHFORT_MAX_RETRIES` | `3` | Retries apply to `429` and `5xx` only. |
| `PHISHFORT_ALLOW_CUSTOM_BASE_URL` | `false` | Test-only escape hatch for non-production API hosts. |
| `PHISHFORT_ALLOW_UNSAFE_WEBHOOK_URL` | `false` | Test-only escape hatch for localhost/private webhook targets. |

## Approval-Gated Writes

Read tools can be called directly. Writes are two-step on purpose:

1. Call `phishfort_plan_change` with `operation` and exact params.
2. Review `warnings`, `risk`, `request_digest`, and `approval_phrase`.
3. Call the intended mutating tool with the same params plus `approval_id`, `approval_phrase`, `expires_at`, and `request_digest`.

If anything changes, rerun `phishfort_plan_change`.

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
