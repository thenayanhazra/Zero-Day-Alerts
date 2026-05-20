from __future__ import annotations

import sqlite3
import json
from datetime import datetime
from pathlib import Path


class Database:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                cve_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                cvss_v3_score REAL,
                epss_percentile REAL,
                severity_level TEXT NOT NULL,
                exploit_status TEXT DEFAULT 'UNKNOWN',
                affected_products TEXT,
                published_date DATETIME,
                discovered_date DATETIME,
                feed_sources TEXT,
                reference_urls TEXT,
                remediation TEXT,
                source_url TEXT,
                first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notification_log (
                id INTEGER PRIMARY KEY,
                cve_id TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'SENT',
                error_message TEXT,
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_metadata (
                feed_name TEXT PRIMARY KEY,
                last_fetch DATETIME,
                last_etag TEXT,
                item_count INTEGER,
                status TEXT DEFAULT 'SUCCESS'
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
            ON vulnerabilities(severity_level)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notification_log_cve_email
            ON notification_log(cve_id, recipient_email)
        """)

        conn.commit()
        conn.close()

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        return cursor

    def query(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def query_one(self, query: str, params: tuple = ()) -> sqlite3.Row | None:
        rows = self.query(query, params)
        return rows[0] if rows else None

    def insert_json_field(self, value: list | dict) -> str:
        return json.dumps(value) if value else None

    def parse_json_field(self, value: str) -> list | dict | None:
        return json.loads(value) if value else None
