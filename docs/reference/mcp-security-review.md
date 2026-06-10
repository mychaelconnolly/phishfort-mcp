# MCP Security Review

Reviewed before implementation:

- https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://modelcontextprotocol.io/specification/2025-11-25/schema
- https://modelcontextprotocol.io/docs/develop/build-server
- https://developers.openai.com/api/docs/mcp
- https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- https://developers.openai.com/api/docs/guides/agent-builder-safety
- https://claude.com/docs/connectors/building/mcp
- https://claude.com/docs/connectors/building/testing
- https://claude.com/docs/connectors/building/submission

## Security Decisions

- Use local `stdio` transport only for v1. No public HTTP listener, no OAuth surface, no remote connector submission.
- Do not accept API keys or bearer tokens as tool arguments. Credentials come only from environment or file.
- Keep tool descriptions static. Do not put remote API output in tool descriptions.
- Treat all PhishFort API output as untrusted data. Incident text can contain adversarial instructions.
- Add tool annotations and structured output, but enforce safety in server code because annotations are hints.
- Use read tools directly and require approval envelopes for mutating tools.
- Disable redirects and restrict default API host to `https://capi.phishfort.com/v1`.
- Do not fetch URLs found in incident data.
- Bound list output by default and expose pagination.
- Expose documented limits through a read-only tool/resource so agents can plan within known caps.
- Honor `Retry-After` on `429`, but cap it locally to avoid unbounded sleeps.
- Restrict webhook target URLs to HTTPS public hosts unless unsafe local test flag is set.
- Preflight webhook creation against the documented 5-subscription client limit when the list response shape is recognizable.
- Restrict attachment file reads to configured local roots and validate symlink-resolved paths.
- Store webhook secrets to `0600` files and return only path plus checksum prefix.

## Approval Model

`phishfort_plan_change` produces:

- `approval_id`
- exact `approval_phrase`
- `expires_at`
- `request_digest`
- risk and warnings

Each mutating tool recomputes the digest from its actual parameters before calling PhishFort. Tampered params, expired plans, or wrong phrases fail before network I/O. Destructive operations require `destructive_confirmed=true`.

This is in-process integrity and confirmation, not independent authorization: the same agent that plans a change can also confirm it, so the gate proves *what* runs matches the plan, not that a separate authority approved it. The human-in-the-loop checkpoint is the MCP host's tool-confirmation UI, driven by the destructive annotations the server sets. The default approval salt is a process-stable random value (not derived from the API key), consistent within a server process without coupling to key rotation.

## Threat Model Notes

- Incident data may contain prompt injection. The server returns data with an explicit untrusted-data warning.
- Webhook URLs could be used for SSRF. The server rejects localhost/private/reserved hosts — including legacy decimal/octal/hex IP encodings — by default. Note this is a pre-submit sanity check: the server never fetches the webhook URL (PhishFort delivers webhooks), so backend egress controls are the real boundary.
- Attachment paths could exfiltrate local files. The server requires configured roots, allowed extensions, and resolved-path checks, and uploads from `O_NOFOLLOW` file handles held since validation to close the validate→open race.
- One-time webhook secrets could leak through tool output. The server recursively strips `secret`/`token`/`apiKey` keys from API responses before returning output and writes saved secrets through `O_NOFOLLOW` `0600` files.
- API errors could contain credentials. Errors are sanitized (API key value plus sensitive key names) before raising.
