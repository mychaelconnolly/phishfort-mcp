```text
+------------------------------------------------------------------------------+
|                                                                              |
|  PPPP  H   H III  SSS  H   H FFFFF  OOO  RRRR  TTTTT    M   M  CCCC PPPP    |
|  P   P H   H  I  S     H   H F     O   O R   R   T      MM MM C     P   P   |
|  PPPP  HHHHH  I   SSS  HHHHH FFFF  O   O RRRR    T      M M M C     PPPP    |
|  P     H   H  I      S H   H F     O   O R  R    T      M   M C     P       |
|  P     H   H III  SSS  H   H F      OOO  R   R   T      M   M  CCCC P       |
|                                                                              |
|        PhishFort Unified Client API -> local stdio MCP tools                  |
|        approval-gated writes | secret-safe by default | no URL fetching       |
|                                                                              |
+------------------------------------------------------------------------------+
```

# phishfort-mcp

Unofficial local MCP server for the [PhishFort Unified Client API](https://phishfort.github.io/unified-client-api-docs/). It exposes PhishFort incident and webhook operations through Model Context Protocol tools with approval gates for mutating calls.

This project is not affiliated with, endorsed by, or maintained by PhishFort.

## Features

Read tools:

- `phishfort_whoami`
- `phishfort_list_incidents`
- `phishfort_get_incident`
- `phishfort_find_incident_by_subject`
- `phishfort_list_webhooks`

Mutating tools require a prior `phishfort_plan_change` approval envelope:

- `phishfort_report_incident`
- `phishfort_request_incident_action`
- `phishfort_add_attachments`
- `phishfort_add_comment`
- `phishfort_create_webhook`
- `phishfort_update_webhook`
- `phishfort_delete_webhook`
- `phishfort_test_webhook`
- `phishfort_rotate_webhook_secret`

MCP resources:

- `phishfort://reference/summary`
- `phishfort://reference/source-manifest`
- `phishfort://reference/security-review`

## Security Model

- `stdio` transport only for v1.
- Credentials come from `PHISHFORT_API_KEY` or `PHISHFORT_API_KEY_FILE`; never from tool arguments.
- All incident data, comments, history, URLs, attachment metadata, and webhook payloads are treated as untrusted data.
- The server does not fetch URLs returned by PhishFort.
- Writes require signed, expiring approval fields from `phishfort_plan_change`.
- Destructive writes require `destructive_confirmed=true`.
- Webhook secrets are written to `0600` files and not returned in tool output.
- Attachment uploads are restricted to configured local roots, safe extensions, max 12 files, and 10 MiB total request size.
- Default API base is pinned to `https://capi.phishfort.com/v1`.

See [MCP security review](docs/reference/mcp-security-review.md) for rationale and source links.

## Install

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

Run local CLI smoke:

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

Environment variables:

- `PHISHFORT_API_BASE_URL`, default `https://capi.phishfort.com/v1`
- `PHISHFORT_API_KEY`
- `PHISHFORT_API_KEY_FILE`
- `PHISHFORT_SECRET_DIR`, default `~/.config/phishfort-mcp/secrets`
- `PHISHFORT_ATTACHMENT_ROOTS`, default `.`
- `PHISHFORT_TIMEOUT_SECONDS`, default `30`
- `PHISHFORT_MAX_RETRIES`, default `3`
- `PHISHFORT_ALLOW_CUSTOM_BASE_URL`, default `false`
- `PHISHFORT_ALLOW_UNSAFE_WEBHOOK_URL`, default `false`

Prefer `PHISHFORT_API_KEY_FILE` for local MCP use.

## Use Pattern

Read tools can be called directly. Mutating tools require:

1. Call `phishfort_plan_change` with `operation` and exact params.
2. Review returned `warnings`, `risk`, `request_digest`, and `approval_phrase`.
3. Call the intended mutating tool with the same params plus `approval_id`, `approval_phrase`, `expires_at`, and `request_digest`.

If params change, rerun `phishfort_plan_change`.

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
