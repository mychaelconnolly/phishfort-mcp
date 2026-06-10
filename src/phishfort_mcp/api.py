from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote

import httpx

from phishfort_mcp.config import Settings
from phishfort_mcp.limits import (
    MAX_RETRY_AFTER_SECONDS,
    RETRYABLE_STATUS_CODES,
    TERMINAL_STATUS_CODES,
)
from phishfort_mcp.security import (
    close_file_tuples,
    file_tuple,
    redact,
    rewind_file_tuples,
    validate_attachment_paths,
)


class PhishFortApiError(RuntimeError):
    def __init__(self, method: str, path: str, status_code: int, body: Any) -> None:
        super().__init__(f"{method} {path} returned HTTP {status_code}: {body}")
        self.method = method
        self.path = path
        self.status_code = status_code
        self.body = body


class PhishFortClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.api_key = settings.require_api_key()

    async def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        form_data: dict[str, Any] | None = None,
        attachment_paths: list[str] | None = None,
    ) -> Any:
        clean_path = "/" + path.lstrip("/")
        headers = {
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "User-Agent": "phishfort-mcp/0.1.0",
        }
        files = []
        if attachment_paths:
            paths = validate_attachment_paths(attachment_paths, settings=self.settings)
            files = [file_tuple(path) for path in paths]
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.timeout_seconds,
                follow_redirects=False,
            ) as client:
                for attempt in range(self.settings.max_retries + 1):
                    if attempt:
                        rewind_file_tuples(files)
                    try:
                        response = await client.request(
                            method,
                            f"{self.settings.base_url}{clean_path}",
                            params=self._clean_query(query),
                            headers=headers,
                            json=json_body if not files and not form_data else None,
                            data=form_data if form_data or files else None,
                            files=files or None,
                        )
                    except httpx.TransportError:
                        if attempt < self.settings.max_retries:
                            await asyncio.sleep(self._backoff_seconds(attempt))
                            continue
                        raise
                    parsed = self._parse_response(response)
                    if response.status_code < 300:
                        return parsed
                    if response.status_code in TERMINAL_STATUS_CODES:
                        raise self._error(method, clean_path, response.status_code, parsed)
                    if response.status_code in RETRYABLE_STATUS_CODES or response.status_code >= 500:
                        if attempt < self.settings.max_retries:
                            delay = (
                                self._retry_after_seconds(response)
                                if response.status_code == 429
                                else None
                            )
                            await asyncio.sleep(
                                delay if delay is not None else self._backoff_seconds(attempt)
                            )
                            continue
                    raise self._error(method, clean_path, response.status_code, parsed)
        finally:
            close_file_tuples(files)

    async def whoami(self) -> Any:
        return await self.request("GET", "/whoami")

    async def list_incidents(
        self,
        *,
        client_id: str | None,
        from_date: str | None,
        to_date: str | None,
        status: str | None,
        limit: int,
        cursor: str | None,
    ) -> Any:
        return await self.request(
            "GET",
            "/incidents",
            query={
                "clientId": client_id,
                "fromDate": from_date,
                "toDate": to_date,
                "status": status,
                "limit": limit,
                "cursor": cursor,
            },
        )

    async def get_incident(self, incident_id: str) -> Any:
        return await self.request("GET", f"/incident/{quote(incident_id, safe='')}")

    async def find_incident_by_subject(self, subject: str) -> Any:
        return await self.request("GET", f"/incident/subject/{quote(subject, safe='')}")

    async def report_incident(
        self,
        *,
        action: str,
        url: str | None,
        incident_type: str | None,
        subject: str | None,
        reported_by: str | None,
        client_id: str | None,
        comment: str | None,
        attachment_paths: list[str] | None,
    ) -> Any:
        body = self._report_payload(url, incident_type, subject, reported_by, client_id, comment)
        if attachment_paths:
            return await self.request(
                "POST",
                f"/incident/{action}",
                form_data=body,
                attachment_paths=attachment_paths,
            )
        return await self.request("POST", f"/incident/{action}", json_body=body)

    async def request_incident_action(self, *, incident_id: str, action: str) -> Any:
        return await self.request(
            "POST",
            f"/incident/{quote(incident_id, safe='')}/{quote(action, safe='')}",
        )

    async def add_attachments(self, *, incident_id: str, attachment_paths: list[str]) -> Any:
        return await self.request(
            "POST",
            f"/incident/{quote(incident_id, safe='')}/attach",
            attachment_paths=attachment_paths,
        )

    async def add_comment(self, *, incident_id: str, comment: str) -> Any:
        return await self.request(
            "POST",
            f"/incident/{quote(incident_id, safe='')}/comment",
            json_body={"comment": comment},
        )

    async def list_webhooks(self) -> Any:
        return await self.request("GET", "/webhooks")

    async def create_webhook(
        self, *, url: str, events: list[str], description: str | None
    ) -> Any:
        body: dict[str, Any] = {"url": url, "events": events}
        if description:
            body["description"] = description
        return await self.request("POST", "/webhooks", json_body=body)

    async def update_webhook(
        self,
        *,
        webhook_id: str,
        url: str | None,
        events: list[str] | None,
        active: bool | None,
        description: str | None,
    ) -> Any:
        body = {
            key: value
            for key, value in {
                "url": url,
                "events": events,
                "active": active,
                "description": description,
            }.items()
            if value is not None
        }
        return await self.request("PATCH", f"/webhooks/{quote(webhook_id, safe='')}", json_body=body)

    async def delete_webhook(self, *, webhook_id: str) -> Any:
        return await self.request("DELETE", f"/webhooks/{quote(webhook_id, safe='')}")

    async def test_webhook(self, *, webhook_id: str) -> Any:
        return await self.request("POST", f"/webhooks/{quote(webhook_id, safe='')}/test")

    async def rotate_webhook_secret(self, *, webhook_id: str) -> Any:
        return await self.request(
            "POST", f"/webhooks/{quote(webhook_id, safe='')}/rotate-secret"
        )

    def _error(self, method: str, path: str, status_code: int, body: Any) -> PhishFortApiError:
        return PhishFortApiError(method, path, status_code, redact(body, self.api_key))

    @staticmethod
    def _clean_query(query: dict[str, Any] | None) -> dict[str, Any] | None:
        if not query:
            return None
        return {key: value for key, value in query.items() if value not in (None, "")}

    @staticmethod
    def _parse_response(response: httpx.Response) -> Any:
        if not response.content:
            return None
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text[:2000]

    @staticmethod
    def _backoff_seconds(attempt: int) -> float:
        return min(8.0, (2**attempt) * 0.5) + random.uniform(0, 0.25)

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float | None:
        raw_value = response.headers.get("Retry-After")
        if not raw_value:
            return None
        try:
            seconds = float(raw_value)
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(raw_value)
            except (TypeError, ValueError):
                return None
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, min(seconds, MAX_RETRY_AFTER_SECONDS))

    @staticmethod
    def _report_payload(
        url: str | None,
        incident_type: str | None,
        subject: str | None,
        reported_by: str | None,
        client_id: str | None,
        comment: str | None,
    ) -> dict[str, str]:
        payload: dict[str, str] = {}
        if url:
            payload["url"] = url
        if incident_type:
            payload["incidentType"] = incident_type
        if subject:
            payload["subject"] = subject
        if reported_by:
            payload["reportedBy"] = reported_by
        if client_id:
            payload["clientId"] = client_id
        if comment is not None:
            payload["comment"] = comment
        return payload
