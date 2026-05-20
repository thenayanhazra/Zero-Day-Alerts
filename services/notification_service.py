from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from models import Vulnerability, SeverityLevel
from persistence import Database
from persistence.repository import NotificationRepository


class NotificationService:
    def __init__(
        self,
        db: Database,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        sender_email: str,
    ) -> None:
        self.db = db
        self.notif_repo = NotificationRepository(db)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.sender_email = sender_email

    def should_notify(self, vuln: Vulnerability, recipient_email: str, days: int = 7) -> bool:
        return not self.notif_repo.was_notified(vuln.cve_id, recipient_email, days)

    def send_notification(
        self, vuln: Vulnerability, recipient_email: str, dry_run: bool = False
    ) -> bool:
        if not self.should_notify(vuln, recipient_email):
            return True

        subject = f"[{vuln.severity_level.value}] {vuln.cve_id}: {vuln.title}"
        body = self._render_notification_email(vuln)

        try:
            if not dry_run:
                self._send_email(recipient_email, subject, body)
            self.notif_repo.log_sent(vuln.cve_id, recipient_email, status="SENT")
            return True
        except Exception as e:
            self.notif_repo.log_sent(
                vuln.cve_id, recipient_email, status="FAILED", error=str(e)
            )
            return False

    def send_digest(
        self, vulns: list[Vulnerability], recipient_email: str, dry_run: bool = False
    ) -> bool:
        if not vulns:
            return True

        subject = f"[DIGEST] {len(vulns)} new high-risk vulnerabilities"
        body = self._render_digest_email(vulns)

        try:
            if not dry_run:
                self._send_email(recipient_email, subject, body)
            for vuln in vulns:
                self.notif_repo.log_sent(vuln.cve_id, recipient_email, status="SENT")
            return True
        except Exception as e:
            for vuln in vulns:
                self.notif_repo.log_sent(
                    vuln.cve_id, recipient_email, status="FAILED", error=str(e)
                )
            return False

    def _send_email(self, recipient: str, subject: str, body: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = recipient

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

    def _render_notification_email(self, vuln: Vulnerability) -> str:
        lines = [
            f"CVE: {vuln.cve_id}",
            f"Severity: {vuln.severity_level.value}",
            "",
            f"Title: {vuln.title}",
            "",
            f"Description:\n{vuln.description}",
        ]

        if vuln.cvss_v3_score is not None:
            lines.append(f"CVSS v3.1 Score: {vuln.cvss_v3_score}")

        if vuln.epss_percentile is not None:
            lines.append(f"EPSS Percentile: {vuln.epss_percentile}%")

        if vuln.affected_products:
            lines.append(f"\nAffected Products:\n" + "\n".join(f"  - {p}" for p in vuln.affected_products))

        if vuln.remediation:
            lines.append(f"\nRemediation:\n{vuln.remediation}")

        if vuln.references:
            lines.append(f"\nReferences:\n" + "\n".join(f"  - {ref}" for ref in vuln.references))

        lines.append(f"\nSource: {vuln.source_url or 'Unknown'}")
        lines.append(f"Timestamp: {datetime.utcnow().isoformat()}")

        return "\n".join(lines)

    def _render_digest_email(self, vulns: list[Vulnerability]) -> str:
        by_severity = {
            SeverityLevel.CRITICAL: [],
            SeverityLevel.HIGH: [],
            SeverityLevel.MEDIUM: [],
            SeverityLevel.LOW: [],
        }

        for vuln in vulns:
            by_severity[vuln.severity_level].append(vuln)

        lines = [f"Vulnerability Digest - {datetime.utcnow().isoformat()}", "=" * 60, ""]

        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            if by_severity[severity]:
                lines.append(f"\n{severity.value} ({len(by_severity[severity])}):")
                for vuln in by_severity[severity]:
                    lines.append(f"  {vuln.cve_id}: {vuln.title}")

        lines.append("\n" + "=" * 60)
        lines.append(f"Total: {len(vulns)} vulnerabilities")

        return "\n".join(lines)
