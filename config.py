from __future__ import annotations

import os
from dataclasses import dataclass, field
from models import SeverityLevel


def _parse_timeout() -> int:
    raw = os.environ.get("TIMEOUT_SECONDS", "20")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"TIMEOUT_SECONDS must be an integer, got {raw!r}")
    if value <= 0:
        raise ValueError(f"TIMEOUT_SECONDS must be a positive integer, got {value}")
    return value


def _parse_recipient_emails() -> list[str]:
    raw = os.environ.get("RECIPIENT_EMAILS", "")
    return [e.strip() for e in raw.split(",") if e.strip()]


@dataclass(frozen=True)
class Settings:
    kev_url: str = os.environ.get(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    timeout_seconds: int = field(default_factory=_parse_timeout)
    db_path: str = os.environ.get("DB_PATH", "vulnerabilities.db")
    smtp_host: str = os.environ.get("SMTP_HOST", "localhost")
    smtp_port: int = int(os.environ.get("SMTP_PORT", "25"))
    smtp_user: str = os.environ.get("SMTP_USER", "")
    smtp_password: str = os.environ.get("SMTP_PASSWORD", "")
    sender_email: str = os.environ.get("SENDER_EMAIL", "alerts@example.com")
    recipient_emails: list[str] = field(default_factory=_parse_recipient_emails)
    min_severity: str = os.environ.get("MIN_SEVERITY", "HIGH")
    poll_interval_seconds: int = int(os.environ.get("POLL_INTERVAL_SECONDS", "3600"))


SETTINGS = Settings()
