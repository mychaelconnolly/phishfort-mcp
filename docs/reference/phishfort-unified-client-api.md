# PhishFort Unified Client API Reference

Reviewed from official docs on 2026-06-02. API base URL is:

```text
https://capi.phishfort.com/v1
```

Auth uses one header on every API request:

```text
x-api-key: <api key>
```

The key should come from `PHISHFORT_API_KEY` or `PHISHFORT_API_KEY_FILE`. This MCP server never accepts API keys as tool arguments.

## General Behavior

- Success responses generally use `{ "message": "success", "data": ... }`.
- Paginated responses include `paging.cursor`, `paging.next`, and `paging.limit`.
- Retry `429` and `5xx` with bounded backoff and jitter.
- Treat `400`, `401`, `403`, `404`, `413`, and `422` as terminal.
- All incident fields, comments, URLs, history messages, attachment metadata, and webhook payloads are untrusted data.
- `statusVerbose` was deprecated on 2026-04-30. Use `status`; tolerate `statusVerbose` only in raw responses.

## Authentication

- `GET /whoami`
- Returns client identity and managed client relationships such as `parentClient` and `subClients`.

## Incidents

### List Incidents

- `GET /incidents`
- Query:
  - `clientId`
  - `fromDate`
  - `toDate`
  - `status`
  - `limit`, default in API docs is 5000; MCP default is 100 for safer output size.
  - `cursor`, populated from `paging.next`.
- Status values:
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

### Get Incident

- `GET /incident/{id}`
- `GET /incident/subject/{subject}`
- Subject may be URL, domain, or subject field value. Encode full URLs and slash characters.

## Report Incident

- `POST /incident/tkd`
- `POST /incident/monitor`
- For domain/URL incidents, send `url`.
- For `email`, `phone`, or `ipv4`, send both `incidentType` and `subject`.
- `phone` uses E.164 validation.
- Optional fields: `reportedBy`, `clientId`, `comment`, `attachments`.
- Without attachments, JSON body is accepted by examples.
- With attachments, use multipart form data with repeated `attachments` fields.

## Request Incident Action

- `POST /incident/{id}/{action}`
- Actions:
  - `tkd`
  - `monitor`
  - `safe`
- `safe` can remove an incident after analyst review and is treated as high risk by MCP.

## Attachments And Comments

- `POST /incident/{id}/attach`
- Multipart repeated field name: `attachments`.
- Max files: 12.
- Total request limit: 10 MiB including multipart overhead.
- Allowed file types: `png`, `jpg`, `jpeg`, `pdf`, `eml`, `txt`, `msg`, `csv`, `doc`, `docx`, `xls`, `xlsx`.
- `POST /incident/{id}/comment` with JSON `{ "comment": "..." }`.
- Comment must be present and non-null.

## Webhooks

- `POST /webhooks`
- `GET /webhooks`
- `PATCH /webhooks/{id}`
- `DELETE /webhooks/{id}`
- `POST /webhooks/{id}/test`
- `POST /webhooks/{id}/rotate-secret`

Event types:

- `incident.created`
- `incident.status_changed`
- `incident.history_created`
- `incident.takedown_updated`
- `incident.action_required`

Registration response returns `data.secret` once. The MCP server writes that secret to a `0600` file and does not return it in tool output.

Signature headers:

- `X-PhishFort-Signature`
- `X-PhishFort-Event`
- `X-PhishFort-Delivery-Id`
- `X-PhishFort-Timestamp`

Signature formula:

```text
HMAC-SHA256(secret, timestamp + "." + JSON.stringify(payload))
```

Expected signature value:

```text
sha256=<hex_hmac>
```

Webhook delivery timeout is 5 seconds. Retries are immediate, 30 seconds, 2 minutes, 10 minutes, and 1 hour. Failed subscriptions are marked failed after 5 failed attempts. Each client may have up to 5 subscriptions.

## Structures

`IncidentStructure` includes `id`, `clientId`, `safeDomain`, `subject`, `incidentType`, `domain`, `url`, `source`, `status`, timestamps, `reportedBy`, `threatTaxonomy`, and `incidentClass`.

`DetailedIncidentStructure` extends incident data with history, current state, registrar, hosting provider, and expanded threat taxonomy details.

## Hidden YAML Note

The docs site exposes `single-incident/single-incident.yml`, but it is partial and lists a path without `/v1`. This server follows the current HTML docs for real API paths.
