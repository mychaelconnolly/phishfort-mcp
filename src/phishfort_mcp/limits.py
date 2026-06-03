from __future__ import annotations

from typing import Any


INCIDENT_LIST_DEFAULT_LIMIT = 100
INCIDENT_LIST_MAX_LIMIT = 5000

ALLOWED_ATTACHMENT_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".eml",
    ".txt",
    ".msg",
    ".csv",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}
MAX_ATTACHMENT_FILES = 12
MAX_MULTIPART_BYTES = 10 * 1024 * 1024

TERMINAL_STATUS_CODES = {400, 401, 403, 404, 413, 422}
RETRYABLE_STATUS_CODES = {429}
MAX_RETRY_AFTER_SECONDS = 30.0

MAX_WEBHOOK_SUBSCRIPTIONS = 5
WEBHOOK_DELIVERY_TIMEOUT_SECONDS = 5
WEBHOOK_RETRY_SCHEDULE = ["immediate", "30 seconds", "2 minutes", "10 minutes", "1 hour"]
WEBHOOK_MAX_FAILED_ATTEMPTS = 5


def limits_summary() -> dict[str, Any]:
    return {
        "incidents": {
            "list_default_limit": INCIDENT_LIST_DEFAULT_LIMIT,
            "list_max_limit": INCIDENT_LIST_MAX_LIMIT,
            "pagination": "cursor-based; use paging.next as cursor",
        },
        "attachments": {
            "max_files_per_request": MAX_ATTACHMENT_FILES,
            "max_multipart_bytes": MAX_MULTIPART_BYTES,
            "max_multipart_mib": 10,
            "allowed_extensions": sorted(ALLOWED_ATTACHMENT_EXTENSIONS),
            "oversize_status_code": 413,
        },
        "http_retry": {
            "retryable_status_codes": sorted(RETRYABLE_STATUS_CODES),
            "retryable_status_family": "5xx",
            "terminal_status_codes": sorted(TERMINAL_STATUS_CODES),
            "retry_after_header": "honored on 429 when present",
            "retry_after_cap_seconds": MAX_RETRY_AFTER_SECONDS,
        },
        "webhooks": {
            "max_subscriptions_per_client": MAX_WEBHOOK_SUBSCRIPTIONS,
            "delivery_timeout_seconds": WEBHOOK_DELIVERY_TIMEOUT_SECONDS,
            "retry_schedule": WEBHOOK_RETRY_SCHEDULE,
            "failed_after_attempts": WEBHOOK_MAX_FAILED_ATTEMPTS,
        },
        "rate_limits": {
            "published_sustained_rps_limit": None,
            "published_daily_quota": None,
            "note": "Official docs publish retry behavior, but do not publish fixed request-per-second or daily quotas.",
        },
    }
