from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from datetime import datetime
from config import SETTINGS
from persistence import Database
from feeds import CisaKevFeed
from services import AlertService
from models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def build_alert_service(db: Database) -> AlertService:
    feeds = [CisaKevFeed(SETTINGS.kev_url, SETTINGS.timeout_seconds)]

    smtp_host = getattr(SETTINGS, "smtp_host", "localhost")
    smtp_port = getattr(SETTINGS, "smtp_port", 25)
    smtp_user = getattr(SETTINGS, "smtp_user", "")
    smtp_password = getattr(SETTINGS, "smtp_password", "")
    sender_email = getattr(SETTINGS, "sender_email", "alerts@example.com")
    recipient_emails = getattr(SETTINGS, "recipient_emails", ["admin@example.com"])
    min_severity = getattr(SETTINGS, "min_severity", SeverityLevel.HIGH)

    return AlertService(
        db=db,
        feeds=feeds,
        recipient_emails=recipient_emails,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_password=smtp_password,
        sender_email=sender_email,
        min_severity=min_severity,
    )


def run_once(alert_service: AlertService) -> int:
    logger.info("Starting single alert cycle...")
    try:
        notified, failed = alert_service.run_alert_cycle(dry_run=False)
        logger.info(f"Alert cycle completed: {notified} notified, {failed} failed")
        return 0 if failed == 0 else 1
    except Exception as e:
        logger.error(f"Alert cycle failed: {e}", exc_info=True)
        return 1


def run_daemon(alert_service: AlertService, poll_interval: int = 3600) -> None:
    logger.info(f"Starting daemon loop (polling every {poll_interval} seconds)...")
    while True:
        try:
            notified, failed = alert_service.run_alert_cycle(dry_run=False)
            logger.info(f"Alert cycle completed: {notified} notified, {failed} failed")
        except Exception as e:
            logger.error(f"Alert cycle failed: {e}", exc_info=True)

        logger.info(f"Next poll in {poll_interval} seconds...")
        time.sleep(poll_interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-Day Alerts Service")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single alert cycle and exit (for cron jobs)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        default=True,
        help="Run continuous polling loop (default)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=3600,
        help="Polling interval in seconds (default: 3600)",
    )
    parser.add_argument(
        "--db-path",
        default="vulnerabilities.db",
        help="Path to SQLite database",
    )
    args = parser.parse_args()

    db = Database(args.db_path)
    alert_service = build_alert_service(db)

    if args.once:
        return run_once(alert_service)
    else:
        run_daemon(alert_service, args.poll_interval)


if __name__ == "__main__":
    raise SystemExit(main())
