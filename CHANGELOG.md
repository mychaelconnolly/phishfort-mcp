# Changelog

## Unreleased

- Added an agent-agnostic paired skill for safe PhishFort MCP workflows.
- Added limit-aware MCP tool/resource, `Retry-After` handling, and webhook cap preflight.
- Security hardening: enforce `destructive_confirmed` for `request_incident_action`;
  recursively scrub secret-named keys from responses; write webhook secrets through
  `O_NOFOLLOW` `0600` files; retry transport errors and redact secret-named fields in
  errors; random process-stable default approval salt; cap `PHISHFORT_MAX_RETRIES` at 5;
  reject legacy numeric IP forms in the webhook URL preflight; hold `O_NOFOLLOW`
  attachment fds across the validate→upload window; url-quote the report action segment.
- Clarified README/security-review claims: the approval gate is in-process
  integrity/confirmation (not independent authorization) and the webhook URL check is a
  pre-submit sanity check (the server never fetches the URL).

## 0.1.0 - 2026-06-02

- Initial local MCP server for PhishFort Unified Client API.
- Added read tools for identity, incidents, subject lookup, and webhooks.
- Added approval-gated mutating tools for incident reporting, actions, attachments, comments, and webhook management.
- Added local reference resources and MCP security review.
- Added secret redaction, attachment constraints, webhook URL validation, and webhook signature verification.
