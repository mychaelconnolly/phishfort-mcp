from __future__ import annotations

import hashlib
import hmac
import ipaddress
import mimetypes
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from phishfort_mcp.config import Settings
from phishfort_mcp.limits import (
    ALLOWED_ATTACHMENT_EXTENSIONS,
    MAX_ATTACHMENT_FILES,
    MAX_MULTIPART_BYTES,
)
PRIVATE_HOSTNAMES = {"localhost", "localhost.localdomain"}
SENSITIVE_RESPONSE_KEYS = {"secret", "webhooksecret", "token", "apikey", "api_key"}


def redact(value: Any, *secrets: str | None) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if isinstance(key, str) and key.lower() in SENSITIVE_RESPONSE_KEYS
                else redact(item, *secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, *secrets) for item in value]
    if not isinstance(value, str):
        return value
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def scrub_secrets(value: Any) -> tuple[Any, dict[str, str]]:
    """Recursively strip sensitive keys from an API response.

    Returns the scrubbed value plus a mapping of removed key (lowercased) to the
    first string value seen, so callers can persist a one-time webhook secret
    without it ever reaching tool output. Removal is by key name regardless of
    nesting depth or response shape.
    """
    found: dict[str, str] = {}

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            cleaned: dict[str, Any] = {}
            for key, item in node.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_RESPONSE_KEYS:
                    if isinstance(item, str):
                        found.setdefault(key.lower(), item)
                    continue
                cleaned[key] = _walk(item)
            return cleaned
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    return _walk(value), found


def is_private_host(hostname: str) -> bool:
    lowered = hostname.strip().lower().rstrip(".")
    if lowered in PRIVATE_HOSTNAMES or lowered.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def validate_webhook_url(url: str, *, settings: Settings) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" and not settings.allow_unsafe_webhook_url:
        raise ValueError("webhook URL must use https")
    if not parsed.hostname:
        raise ValueError("webhook URL must include a hostname")
    if is_private_host(parsed.hostname) and not settings.allow_unsafe_webhook_url:
        raise ValueError("webhook URL must not target localhost, private, or reserved hosts")


def _resolve_root(root: Path) -> Path:
    return root.expanduser().resolve(strict=True)


def validate_attachment_paths(paths: list[str] | None, *, settings: Settings) -> list[Path]:
    if not paths:
        return []
    if len(paths) > MAX_ATTACHMENT_FILES:
        raise ValueError(f"at most {MAX_ATTACHMENT_FILES} attachment files are allowed")
    roots = [_resolve_root(root) for root in settings.attachment_roots]
    resolved: list[Path] = []
    total = 0
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError(f"attachment path is not a file: {raw_path}")
        if path.suffix.lower() not in ALLOWED_ATTACHMENT_EXTENSIONS:
            raise ValueError(f"attachment extension not allowed: {path.suffix.lower()}")
        if not any(path.is_relative_to(root) for root in roots):
            raise ValueError("attachment path must be inside PHISHFORT_ATTACHMENT_ROOTS")
        total += path.stat().st_size + 1024
        resolved.append(path)
    if total > MAX_MULTIPART_BYTES:
        raise ValueError(f"attachments exceed {MAX_MULTIPART_BYTES} byte request limit")
    return resolved


def file_tuple(path: Path) -> tuple[str, tuple[str, Any, str]]:
    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return ("attachments", (path.name, path.open("rb"), mime_type))


def close_file_tuples(files: list[tuple[str, tuple[str, Any, str]]]) -> None:
    for _, (_, handle, _) in files:
        try:
            handle.close()
        except Exception:
            pass


def rewind_file_tuples(files: list[tuple[str, tuple[str, Any, str]]]) -> None:
    """Reset upload handles to the start so a retried request re-sends the body."""
    for _, (_, handle, _) in files:
        try:
            handle.seek(0)
        except Exception:
            pass


def write_secret_file(secret: str, *, settings: Settings, name: str | None = None) -> dict[str, str]:
    settings.secret_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(settings.secret_dir, 0o700)
    resolved_dir = settings.secret_dir.resolve(strict=True)
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    safe_name = (name or f"phishfort-webhook-{digest[:12]}.txt").replace("/", "_")
    if not safe_name.endswith(".txt"):
        safe_name = f"{safe_name}.txt"
    path = resolved_dir / safe_name
    if path.parent != resolved_dir:
        raise ValueError("secret file name must not escape the secret directory")
    # O_NOFOLLOW: refuse to write through an attacker-planted symlink in the
    # secret dir. O_TRUNC (not O_EXCL) so rotation can overwrite a reused name.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(secret)
        handle.write("\n")
    return {"secret_file": str(path), "secret_sha256_prefix": digest[:16]}


def verify_signature(
    *,
    secret: str,
    signature: str,
    timestamp: str,
    raw_body: str,
) -> bool:
    payload = f"{timestamp}.{raw_body}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    expected = f"sha256={mac}"
    return hmac.compare_digest(signature, expected)


def read_secret_file(path: str, *, settings: Settings) -> str:
    resolved = Path(path).expanduser().resolve(strict=True)
    secret_dir = settings.secret_dir.expanduser().resolve(strict=True)
    if not resolved.is_relative_to(secret_dir):
        raise ValueError("secret_file must be inside PHISHFORT_SECRET_DIR")
    return resolved.read_text(encoding="utf-8").strip()
