from __future__ import annotations

from models import SeverityLevel
from persistence import Database
from feeds import FeedSource
from .vulnerability_service import VulnerabilityService
from .notification_service import NotificationService


class AlertService:
    def __init__(
        self,
        db: Database,
        feeds: list[FeedSource],
        recipient_emails: list[str],
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        sender_email: str,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
    ) -> None:
        self.vuln_service = VulnerabilityService(db)
        self.notif_service = NotificationService(
            db, smtp_host, smtp_port, smtp_user, smtp_password, sender_email
        )
        self.feeds = feeds
        self.recipient_emails = recipient_emails
        self.min_severity = min_severity

    def run_alert_cycle(self, dry_run: bool = False) -> tuple[int, int]:
        vulns = self.vuln_service.fetch_and_persist_from_feeds(
            self.feeds, self.min_severity
        )

        notified_count = 0
        failed_count = 0

        for vuln in vulns:
            for email in self.recipient_emails:
                success = self.notif_service.send_notification(vuln, email, dry_run=dry_run)
                if success:
                    notified_count += 1
                else:
                    failed_count += 1

        return notified_count, failed_count
