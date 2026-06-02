from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import pytest

from phishfort_mcp.config import Settings
from phishfort_mcp.security import (
    validate_attachment_paths,
    validate_webhook_url,
    verify_signature,
    write_secret_file,
)


def test_settings_loads_api_key_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_file = tmp_path / "key.txt"
    key_file.write_text("secret-key\n", encoding="utf-8")
    monkeypatch.setenv("PHISHFORT_API_KEY_FILE", str(key_file))
    settings = Settings.from_env()
    assert settings.require_api_key() == "secret-key"


def test_default_base_url_blocks_custom_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHISHFORT_API_BASE_URL", "https://example.com/v1")
    monkeypatch.delenv("PHISHFORT_ALLOW_CUSTOM_BASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="capi.phishfort.com"):
        Settings.from_env()


def test_webhook_url_blocks_private_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.from_env()
    with pytest.raises(ValueError, match="private"):
        validate_webhook_url("https://127.0.0.1/hook", settings=settings)
    with pytest.raises(ValueError, match="https"):
        validate_webhook_url("http://hooks.example.com/hook", settings=settings)


def test_attachment_paths_restrict_roots_and_extensions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    good = allowed_root / "proof.pdf"
    good.write_bytes(b"%PDF")
    bad = allowed_root / "proof.sh"
    bad.write_text("no", encoding="utf-8")
    monkeypatch.setenv("PHISHFORT_ATTACHMENT_ROOTS", str(allowed_root))
    settings = Settings.from_env()
    assert validate_attachment_paths([str(good)], settings=settings) == [good]
    with pytest.raises(ValueError, match="extension"):
        validate_attachment_paths([str(bad)], settings=settings)


def test_attachment_paths_block_root_escape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF")
    monkeypatch.setenv("PHISHFORT_ATTACHMENT_ROOTS", str(allowed_root))
    settings = Settings.from_env()
    with pytest.raises(ValueError, match="PHISHFORT_ATTACHMENT_ROOTS"):
        validate_attachment_paths([str(outside)], settings=settings)


def test_write_secret_file_uses_0600(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PHISHFORT_SECRET_DIR", str(tmp_path))
    settings = Settings.from_env()
    saved = write_secret_file("webhook-secret", settings=settings, name="hook-secret")
    path = Path(saved["secret_file"])
    assert path.read_text(encoding="utf-8").strip() == "webhook-secret"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_verify_signature() -> None:
    secret = "webhook-secret"
    timestamp = "1710000000"
    raw_body = '{"incidentId":"abc"}'
    mac = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.{raw_body}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert verify_signature(
        secret=secret,
        signature=f"sha256={mac}",
        timestamp=timestamp,
        raw_body=raw_body,
    )
