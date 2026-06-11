from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


DEFAULT_BASE_URL = "https://capi.phishfort.com/v1"
DEFAULT_ATTACHMENT_ROOT = "."
DEFAULT_SECRET_DIR = "~/.config/phishfort-mcp/secrets"
MAX_RETRIES_CEILING = 5

# Process-stable random salt used when PHISHFORT_MCP_APPROVAL_SALT is unset.
# It only needs to be consistent within one server process (plan and validate
# run in the same stdio process); it is not a cross-trust-boundary secret.
_DEFAULT_APPROVAL_SALT = secrets.token_hex(32)


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _csv_paths(raw: str | None, default: str) -> tuple[Path, ...]:
    values = [part.strip() for part in (raw or default).split(",") if part.strip()]
    return tuple(Path(value).expanduser() for value in values)


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: str | None
    api_key_file: Path | None
    timeout_seconds: float
    max_retries: int
    approval_salt: str
    secret_dir: Path
    attachment_roots: tuple[Path, ...]
    allow_custom_base_url: bool
    allow_unsafe_webhook_url: bool
    transport: str

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        api_key = os.environ.get("PHISHFORT_API_KEY", "").strip() or None
        api_key_file_raw = os.environ.get("PHISHFORT_API_KEY_FILE", "").strip()
        api_key_file = Path(api_key_file_raw).expanduser() if api_key_file_raw else None
        if not api_key and api_key_file and api_key_file.exists():
            api_key = api_key_file.read_text(encoding="utf-8").strip()
        base_url = os.environ.get("PHISHFORT_API_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")
        allow_custom_base_url = _bool_env("PHISHFORT_ALLOW_CUSTOM_BASE_URL", False)
        settings = cls(
            base_url=base_url,
            api_key=api_key,
            api_key_file=api_key_file,
            timeout_seconds=float(os.environ.get("PHISHFORT_TIMEOUT_SECONDS", "30")),
            max_retries=min(
                MAX_RETRIES_CEILING, max(0, int(os.environ.get("PHISHFORT_MAX_RETRIES", "3")))
            ),
            approval_salt=(
                os.environ.get("PHISHFORT_MCP_APPROVAL_SALT", "").strip()
                or _DEFAULT_APPROVAL_SALT
            ),
            secret_dir=Path(
                os.environ.get("PHISHFORT_SECRET_DIR", DEFAULT_SECRET_DIR).strip()
            ).expanduser(),
            attachment_roots=_csv_paths(
                os.environ.get("PHISHFORT_ATTACHMENT_ROOTS"), DEFAULT_ATTACHMENT_ROOT
            ),
            allow_custom_base_url=allow_custom_base_url,
            allow_unsafe_webhook_url=_bool_env("PHISHFORT_ALLOW_UNSAFE_WEBHOOK_URL", False),
            transport=os.environ.get("PHISHFORT_MCP_TRANSPORT", "stdio").strip().lower(),
        )
        settings.validate_base_url()
        return settings

    def validate_base_url(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            if not self.allow_custom_base_url:
                raise RuntimeError("PHISHFORT_API_BASE_URL must use https")
        if parsed.hostname != "capi.phishfort.com" and not self.allow_custom_base_url:
            raise RuntimeError("PHISHFORT_API_BASE_URL host must be capi.phishfort.com")
        if not parsed.path.rstrip("/").endswith("/v1"):
            if not self.allow_custom_base_url:
                raise RuntimeError("PHISHFORT_API_BASE_URL must point to the /v1 API base")

    def require_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        source = "PHISHFORT_API_KEY"
        if self.api_key_file:
            source = f"PHISHFORT_API_KEY_FILE ({self.api_key_file})"
        raise RuntimeError(f"PhishFort API key missing; set {source}.")
