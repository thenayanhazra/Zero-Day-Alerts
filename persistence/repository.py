from __future__ import annotations

from datetime import datetime, timedelta
from models import Vulnerability, SeverityLevel
from .db import Database


class VulnerabilityRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def insert_or_update(self, vuln: Vulnerability) -> None:
        data = vuln.to_dict()
        existing = self.db.query_one(
            "SELECT id FROM vulnerabilities WHERE cve_id = ?", (vuln.cve_id,)
        )

        if existing:
            self.db.execute(
                """
                UPDATE vulnerabilities SET
                    title = ?, description = ?, cvss_v3_score = ?,
                    epss_percentile = ?, severity_level = ?, exploit_status = ?,
                    affected_products = ?, published_date = ?, discovered_date = ?,
                    feed_sources = ?, reference_urls = ?, remediation = ?,
                    source_url = ?, last_updated = CURRENT_TIMESTAMP
                WHERE cve_id = ?
                """,
                (
                    data["title"],
                    data["description"],
                    data["cvss_v3_score"],
                    data["epss_percentile"],
                    data["severity_level"],
                    data["exploit_status"],
                    self.db.insert_json_field(data["affected_products"]),
                    data["published_date"],
                    data["discovered_date"],
                    self.db.insert_json_field(data["feed_sources"]),
                    self.db.insert_json_field(data["references"]),
                    data["remediation"],
                    data["source_url"],
                    vuln.cve_id,
                ),
            )
        else:
            self.db.execute(
                """
                INSERT INTO vulnerabilities
                (cve_id, title, description, cvss_v3_score, epss_percentile,
                 severity_level, exploit_status, affected_products, published_date,
                 discovered_date, feed_sources, reference_urls, remediation, source_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.cve_id,
                    data["title"],
                    data["description"],
                    data["cvss_v3_score"],
                    data["epss_percentile"],
                    data["severity_level"],
                    data["exploit_status"],
                    self.db.insert_json_field(data["affected_products"]),
                    data["published_date"],
                    data["discovered_date"],
                    self.db.insert_json_field(data["feed_sources"]),
                    self.db.insert_json_field(data["references"]),
                    data["remediation"],
                    data["source_url"],
                ),
            )

    def find_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        row = self.db.query_one(
            "SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
        )
        return self._row_to_vuln(row) if row else None

    def find_recent(
        self, days: int = 7, severity: SeverityLevel | None = None
    ) -> list[Vulnerability]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        if severity:
            rows = self.db.query(
                "SELECT * FROM vulnerabilities WHERE first_seen >= ? AND severity_level = ? ORDER BY first_seen DESC",
                (cutoff.isoformat(), severity.value),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM vulnerabilities WHERE first_seen >= ? ORDER BY first_seen DESC",
                (cutoff.isoformat(),),
            )
        return [self._row_to_vuln(row) for row in rows if row]

    def find_new_since(self, timestamp: datetime) -> list[Vulnerability]:
        rows = self.db.query(
            "SELECT * FROM vulnerabilities WHERE first_seen >= ? ORDER BY first_seen DESC",
            (timestamp.isoformat(),),
        )
        return [self._row_to_vuln(row) for row in rows if row]

    def find_by_severity(self, severity: SeverityLevel) -> list[Vulnerability]:
        rows = self.db.query(
            "SELECT * FROM vulnerabilities WHERE severity_level = ? ORDER BY first_seen DESC",
            (severity.value,),
        )
        return [self._row_to_vuln(row) for row in rows if row]

    def _row_to_vuln(self, row: any) -> Vulnerability | None:
        if not row:
            return None
        return Vulnerability(
            cve_id=row["cve_id"],
            title=row["title"],
            description=row["description"] or "",
            severity_level=SeverityLevel(row["severity_level"]),
            cvss_v3_score=row["cvss_v3_score"],
            epss_percentile=row["epss_percentile"],
            exploit_status=row["exploit_status"],
            affected_products=self.db.parse_json_field(row["affected_products"]),
            published_date=(
                datetime.fromisoformat(row["published_date"])
                if row["published_date"]
                else None
            ),
            discovered_date=(
                datetime.fromisoformat(row["discovered_date"])
                if row["discovered_date"]
                else None
            ),
            feed_sources=self.db.parse_json_field(row["feed_sources"]),
            references=self.db.parse_json_field(row["reference_urls"]),
            remediation=row["remediation"],
            source_url=row["source_url"],
        )


class NotificationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def log_sent(
        self, cve_id: str, recipient_email: str, status: str = "SENT", error: str | None = None
    ) -> None:
        self.db.execute(
            "INSERT INTO notification_log (cve_id, recipient_email, status, error_message) VALUES (?, ?, ?, ?)",
            (cve_id, recipient_email, status, error),
        )

    def was_notified(self, cve_id: str, recipient_email: str, days: int = 7) -> bool:
        cutoff = datetime.utcnow() - timedelta(days=days)
        row = self.db.query_one(
            "SELECT id FROM notification_log WHERE cve_id = ? AND recipient_email = ? AND sent_at >= ? AND status = 'SENT'",
            (cve_id, recipient_email, cutoff.isoformat()),
        )
        return row is not None

    def get_failed_notifications(self) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM notification_log WHERE status = 'FAILED' ORDER BY sent_at ASC LIMIT 100"
        )
        return [dict(row) for row in rows]


class FeedMetadataRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def update_feed_metadata(
        self, feed_name: str, item_count: int, etag: str | None = None, status: str = "SUCCESS"
    ) -> None:
        existing = self.db.query_one(
            "SELECT feed_name FROM feed_metadata WHERE feed_name = ?", (feed_name,)
        )
        if existing:
            self.db.execute(
                "UPDATE feed_metadata SET last_fetch = CURRENT_TIMESTAMP, last_etag = ?, item_count = ?, status = ? WHERE feed_name = ?",
                (etag, item_count, status, feed_name),
            )
        else:
            self.db.execute(
                "INSERT INTO feed_metadata (feed_name, last_fetch, last_etag, item_count, status) VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?)",
                (feed_name, etag, item_count, status),
            )

    def get_feed_metadata(self, feed_name: str) -> dict | None:
        row = self.db.query_one(
            "SELECT * FROM feed_metadata WHERE feed_name = ?", (feed_name,)
        )
        return dict(row) if row else None
