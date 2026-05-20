import tempfile
from datetime import datetime
from pathlib import Path
import pytest
from models import Vulnerability, SeverityLevel, ExploitStatus
from persistence import Database
from persistence.repository import VulnerabilityRepository, NotificationRepository


@pytest.fixture
def temp_db() -> Database:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = Database(db_path)
    yield db
    Path(db_path).unlink(missing_ok=True)


def test_database_initialization(temp_db: Database) -> None:
    assert temp_db.db_path.exists()
    conn = temp_db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    assert "vulnerabilities" in tables
    assert "notification_log" in tables
    conn.close()


def test_vulnerability_insert_and_retrieve(temp_db: Database) -> None:
    repo = VulnerabilityRepository(temp_db)
    vuln = Vulnerability(
        cve_id="CVE-2025-9999",
        title="Test Vulnerability",
        description="Test description",
        severity_level=SeverityLevel.HIGH,
        affected_products=["Product1", "Product2"],
        feed_sources=["CISA_KEV"],
    )

    repo.insert_or_update(vuln)
    retrieved = repo.find_by_cve_id("CVE-2025-9999")

    assert retrieved is not None
    assert retrieved.cve_id == "CVE-2025-9999"
    assert retrieved.title == "Test Vulnerability"
    assert retrieved.severity_level == SeverityLevel.HIGH


def test_vulnerability_update(temp_db: Database) -> None:
    repo = VulnerabilityRepository(temp_db)
    vuln1 = Vulnerability(
        cve_id="CVE-2025-8888",
        title="Original Title",
        description="Original description",
        severity_level=SeverityLevel.MEDIUM,
    )
    repo.insert_or_update(vuln1)

    vuln2 = Vulnerability(
        cve_id="CVE-2025-8888",
        title="Updated Title",
        description="Updated description",
        severity_level=SeverityLevel.HIGH,
    )
    repo.insert_or_update(vuln2)

    retrieved = repo.find_by_cve_id("CVE-2025-8888")
    assert retrieved.title == "Updated Title"
    assert retrieved.severity_level == SeverityLevel.HIGH


def test_notification_log(temp_db: Database) -> None:
    repo = NotificationRepository(temp_db)
    repo.log_sent("CVE-2025-1234", "test@example.com")

    assert repo.was_notified("CVE-2025-1234", "test@example.com")
    assert not repo.was_notified("CVE-2025-5678", "test@example.com")


def test_notification_not_sent_different_email(temp_db: Database) -> None:
    repo = NotificationRepository(temp_db)
    repo.log_sent("CVE-2025-1234", "test1@example.com")

    assert repo.was_notified("CVE-2025-1234", "test1@example.com")
    assert not repo.was_notified("CVE-2025-1234", "test2@example.com")
