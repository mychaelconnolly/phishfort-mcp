from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from phishfort_mcp.api import PhishFortApiError, PhishFortClient
from phishfort_mcp.config import Settings


def _settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Settings:
    monkeypatch.setenv("PHISHFORT_API_KEY", "test-key")
    monkeypatch.setenv("PHISHFORT_API_BASE_URL", "https://api.test/v1")
    monkeypatch.setenv("PHISHFORT_ALLOW_CUSTOM_BASE_URL", "true")
    monkeypatch.setenv("PHISHFORT_ATTACHMENT_ROOTS", str(tmp_path))
    return Settings.from_env()


@respx.mock
@pytest.mark.asyncio
async def test_whoami_request_headers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    route = respx.get("https://api.test/v1/whoami").mock(
        return_value=httpx.Response(200, json={"message": "success", "data": {"id": "client"}})
    )
    data = await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert data["data"]["id"] == "client"
    assert route.calls.last.request.headers["x-api-key"] == "test-key"


@respx.mock
@pytest.mark.asyncio
async def test_find_incident_by_subject_encodes_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    route = respx.get("https://api.test/v1/incident/subject/https%3A%2F%2Fevil.example%2Fa").mock(
        return_value=httpx.Response(200, json={"message": "success"})
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).find_incident_by_subject(
        "https://evil.example/a"
    )
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_list_incidents_query(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    route = respx.get("https://api.test/v1/incidents").mock(
        return_value=httpx.Response(200, json={"message": "success", "data": []})
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).list_incidents(
        client_id="client",
        from_date="2026-01-01T00:00:00Z",
        to_date=None,
        status="pending_review",
        limit=1,
        cursor="next",
    )
    params = route.calls.last.request.url.params
    assert params["clientId"] == "client"
    assert params["fromDate"] == "2026-01-01T00:00:00Z"
    assert params["status"] == "pending_review"
    assert params["limit"] == "1"
    assert params["cursor"] == "next"


@respx.mock
@pytest.mark.asyncio
async def test_report_incident_json_without_attachments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    route = respx.post("https://api.test/v1/incident/tkd").mock(
        return_value=httpx.Response(200, json={"message": "success", "id": "inc"})
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).report_incident(
        action="tkd",
        url="https://evil.example",
        incident_type=None,
        subject=None,
        reported_by="a@example.com",
        client_id=None,
        comment="bad",
        attachment_paths=None,
    )
    assert route.calls.last.request.headers["content-type"].startswith("application/json")
    assert b"https://evil.example" in route.calls.last.request.content


@respx.mock
@pytest.mark.asyncio
async def test_add_attachments_uses_multipart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    proof = tmp_path / "proof.pdf"
    proof.write_bytes(b"%PDF")
    route = respx.post("https://api.test/v1/incident/inc/attach").mock(
        return_value=httpx.Response(200, json={"message": "success"})
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).add_attachments(
        incident_id="inc", attachment_paths=[str(proof)]
    )
    request = route.calls.last.request
    assert request.headers["content-type"].startswith("multipart/form-data")
    assert b"attachments" in request.content
    assert b"proof.pdf" in request.content


@respx.mock
@pytest.mark.asyncio
async def test_error_redacts_api_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    respx.get("https://api.test/v1/whoami").mock(
        return_value=httpx.Response(401, json={"error": "bad test-key"})
    )
    with pytest.raises(PhishFortApiError) as exc:
        await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert "test-key" not in str(exc.value)
    assert "[REDACTED]" in str(exc.value)


@respx.mock
@pytest.mark.asyncio
async def test_error_redacts_secret_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    respx.get("https://api.test/v1/whoami").mock(
        return_value=httpx.Response(401, json={"error": "nope", "secret": "hook-secret"})
    )
    with pytest.raises(PhishFortApiError) as exc:
        await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert "hook-secret" not in str(exc.value)
    assert "[REDACTED]" in str(exc.value)


@respx.mock
@pytest.mark.asyncio
async def test_transport_error_retries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def fake_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("phishfort_mcp.api.asyncio.sleep", fake_sleep)
    route = respx.get("https://api.test/v1/whoami").mock(
        side_effect=[
            httpx.ConnectError("boom"),
            httpx.Response(200, json={"message": "success"}),
        ]
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_read_timeout_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Read-phase errors are ambiguous (the server may have processed the request),
    # so they must not be retried — re-sending could duplicate a non-idempotent write.
    route = respx.get("https://api.test/v1/whoami").mock(side_effect=httpx.ReadTimeout("boom"))
    with pytest.raises(httpx.ReadTimeout):
        await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_429_retries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def fake_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("phishfort_mcp.api.asyncio.sleep", fake_sleep)
    route = respx.get("https://api.test/v1/whoami").mock(
        side_effect=[
            httpx.Response(429, json={"error": "slow"}),
            httpx.Response(200, json={"message": "success"}),
        ]
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_429_honors_retry_after_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("phishfort_mcp.api.asyncio.sleep", fake_sleep)
    respx.get("https://api.test/v1/whoami").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}, json={"error": "slow"}),
            httpx.Response(200, json={"message": "success"}),
        ]
    )
    await PhishFortClient(_settings(monkeypatch, tmp_path)).whoami()
    assert sleeps == [7.0]


@respx.mock
@pytest.mark.asyncio
async def test_terminal_status_does_not_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    route = respx.post("https://api.test/v1/incident/inc/attach").mock(
        return_value=httpx.Response(413, json={"error": "too large"})
    )
    with pytest.raises(PhishFortApiError):
        await PhishFortClient(_settings(monkeypatch, tmp_path)).add_attachments(
            incident_id="inc", attachment_paths=[]
        )
    assert route.call_count == 1
