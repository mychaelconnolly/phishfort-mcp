from __future__ import annotations

import time

import pytest

from phishfort_mcp.approval import build_plan, validate_approval


def test_approval_round_trip() -> None:
    params = {"incident_id": "abc", "comment": "reviewed"}
    plan = build_plan(
        operation="add_comment", params=params, expires_in_seconds=900, salt="salt"
    )
    validate_approval(
        operation="add_comment",
        params=params,
        expires_at=plan["expires_at"],
        approval_id=plan["approval_id"],
        approval_phrase=plan["approval_phrase"],
        request_digest=plan["request_digest"],
        destructive_confirmed=False,
        salt="salt",
    )


def test_approval_rejects_tampered_params() -> None:
    plan = build_plan(
        operation="add_comment",
        params={"incident_id": "abc", "comment": "one"},
        expires_in_seconds=900,
        salt="salt",
    )
    with pytest.raises(ValueError, match="request_digest"):
        validate_approval(
            operation="add_comment",
            params={"incident_id": "abc", "comment": "two"},
            expires_at=plan["expires_at"],
            approval_id=plan["approval_id"],
            approval_phrase=plan["approval_phrase"],
            request_digest=plan["request_digest"],
            destructive_confirmed=False,
            salt="salt",
        )


def test_destructive_operation_requires_confirmed() -> None:
    params = {"webhook_id": "wh_1"}
    plan = build_plan(
        operation="delete_webhook", params=params, expires_in_seconds=900, salt="salt"
    )
    with pytest.raises(ValueError, match="destructive_confirmed"):
        validate_approval(
            operation="delete_webhook",
            params=params,
            expires_at=plan["expires_at"],
            approval_id=plan["approval_id"],
            approval_phrase=plan["approval_phrase"],
            request_digest=plan["request_digest"],
            destructive_confirmed=False,
            salt="salt",
        )


def test_expired_plan_rejected() -> None:
    params = {"webhook_id": "wh_1"}
    plan = build_plan(
        operation="test_webhook", params=params, expires_in_seconds=60, salt="salt"
    )
    with pytest.raises(ValueError, match="expired"):
        validate_approval(
            operation="test_webhook",
            params=params,
            expires_at=int(time.time()) - 1,
            approval_id=plan["approval_id"],
            approval_phrase=plan["approval_phrase"],
            request_digest=plan["request_digest"],
            destructive_confirmed=False,
            salt="salt",
        )
