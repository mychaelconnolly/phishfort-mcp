from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from phishfort_mcp.approval import build_plan
from phishfort_mcp.limits import (
    MAX_ATTACHMENT_FILES,
    MAX_MULTIPART_BYTES,
    MAX_WEBHOOK_SUBSCRIPTIONS,
    limits_summary,
)
from phishfort_mcp.server import (
    phishfort_create_webhook,
    phishfort_get_limits,
    reference_limits,
)


APPROVAL_SALT = "server-test-salt"


def _server_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PHISHFORT_API_KEY", "test-key")
    monkeypatch.setenv("PHISHFORT_API_BASE_URL", "https://api.test/v1")
    monkeypatch.setenv("PHISHFORT_ALLOW_CUSTOM_BASE_URL", "true")
    monkeypatch.setenv("PHISHFORT_MCP_APPROVAL_SALT", APPROVAL_SALT)
    monkeypatch.setenv("PHISHFORT_SECRET_DIR", str(tmp_path))


def _approval_fields(params: dict[str, object]) -> dict[str, object]:
    plan = build_plan(
        operation="create_webhook",
        params=params,
        expires_in_seconds=900,
        salt=APPROVAL_SALT,
    )
    return {
        "approval_id": plan["approval_id"],
        "approval_phrase": plan["approval_phrase"],
        "expires_at": plan["expires_at"],
        "request_digest": plan["request_digest"],
    }


def test_limits_summary_matches_documented_caps() -> None:
    summary = limits_summary()
    assert summary["attachments"]["max_files_per_request"] == MAX_ATTACHMENT_FILES
    assert summary["attachments"]["max_multipart_bytes"] == MAX_MULTIPART_BYTES
    assert summary["webhooks"]["max_subscriptions_per_client"] == MAX_WEBHOOK_SUBSCRIPTIONS
    assert summary["rate_limits"]["published_sustained_rps_limit"] is None
    assert summary["http_retry"]["retry_after_header"] == "honored on 429 when present"


def test_limit_tool_and_resource_expose_same_webhook_cap() -> None:
    tool_result = phishfort_get_limits()
    resource_result = json.loads(reference_limits())
    assert tool_result["data"]["webhooks"]["max_subscriptions_per_client"] == 5
    assert resource_result["webhooks"]["max_subscriptions_per_client"] == 5
    assert "untrusted_data_warning" not in tool_result


@respx.mock
@pytest.mark.asyncio
async def test_create_webhook_blocks_when_limit_reached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _server_env(monkeypatch, tmp_path)
    params: dict[str, object] = {
        "url": "https://hooks.example.com/phishfort",
        "events": ["incident.created"],
    }
    fields = _approval_fields(params)
    list_route = respx.get("https://api.test/v1/webhooks").mock(
        return_value=httpx.Response(
            200,
            json={"message": "success", "data": [{"id": f"wh_{index}"} for index in range(5)]},
        )
    )

    with pytest.raises(ValueError, match="5 subscriptions"):
        await phishfort_create_webhook(
            url="https://hooks.example.com/phishfort",
            events=["incident.created"],
            destructive_confirmed=False,
            **fields,
        )

    assert list_route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_create_webhook_allows_under_limit_and_saves_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _server_env(monkeypatch, tmp_path)
    params: dict[str, object] = {
        "url": "https://hooks.example.com/phishfort",
        "events": ["incident.created"],
    }
    fields = _approval_fields(params)
    respx.get("https://api.test/v1/webhooks").mock(
        return_value=httpx.Response(
            200,
            json={"message": "success", "data": [{"id": f"wh_{index}"} for index in range(4)]},
        )
    )
    create_route = respx.post("https://api.test/v1/webhooks").mock(
        return_value=httpx.Response(
            200,
            json={"message": "success", "data": {"id": "wh_new", "secret": "hook-secret"}},
        )
    )

    result = await phishfort_create_webhook(
        url="https://hooks.example.com/phishfort",
        events=["incident.created"],
        destructive_confirmed=False,
        **fields,
    )

    assert create_route.call_count == 1
    assert result["data"]["data"]["id"] == "wh_new"
    assert "secret" not in result["data"]["data"]
    assert Path(result["saved_secret"]["secret_file"]).exists()
    assert result["secret_returned"] is False
