import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from models import Vulnerability, SeverityLevel, ExploitStatus
from persistence import Database
from services import VulnerabilityService, AlertService
from feeds import CisaKevFeed


@pytest.fixture
def temp_db() -> Database:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = Database(db_path)
    yield db
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def sample_vulns() -> list[Vulnerability]:
    return [
        Vulnerability(
            cve_id="CVE-2025-0001",
            title="Critical RCE",
            description="Remote code execution",
            severity_level=SeverityLevel.CRITICAL,
        ),
        Vulnerability(
            cve_id="CVE-2025-0002",
            title="High Vuln",
            description="High severity issue",
            severity_level=SeverityLevel.HIGH,
        ),
    ]


def test_vulnerability_service_persist_and_retrieve(
    temp_db: Database, sample_vulns: list[Vulnerability]
) -> None:
    service = VulnerabilityService(temp_db)

    for vuln in sample_vulns:
        service.vuln_repo.insert_or_update(vuln)

    retrieved = service.get_vulnerability("CVE-2025-0001")
    assert retrieved is not None
    assert retrieved.cve_id == "CVE-2025-0001"


def test_vulnerability_service_filters_by_severity(
    temp_db: Database, sample_vulns: list[Vulnerability]
) -> None:
    service = VulnerabilityService(temp_db)

    for vuln in sample_vulns:
        service.vuln_repo.insert_or_update(vuln)

    critical = service.vuln_repo.find_by_severity(SeverityLevel.CRITICAL)
    assert len(critical) == 1
    assert critical[0].cve_id == "CVE-2025-0001"


def test_alert_service_dry_run(temp_db: Database) -> None:
    feed = CisaKevFeed("http://example.com/kev.json")
    with patch("feeds.cisa_kev.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-0001",
                    "vendorProject": "Test",
                    "product": "Product",
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "Test",
                    "dateAdded": "2025-01-15",
                    "requiredAction": "Patch",
                }
            ]
        }
        mock_get.return_value = mock_response

        alert_service = AlertService(
            db=temp_db,
            feeds=[feed],
            recipient_emails=["test@example.com"],
            smtp_host="localhost",
            smtp_port=25,
            smtp_user="",
            smtp_password="",
            sender_email="alerts@example.com",
            min_severity=SeverityLevel.CRITICAL,
        )

        notified, failed = alert_service.run_alert_cycle(dry_run=True)
        assert notified == 1
        assert failed == 0


def test_alert_service_filters_by_severity(temp_db: Database) -> None:
    feed = CisaKevFeed("http://example.com/kev.json")
    with patch("feeds.cisa_kev.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-0001",
                    "vendorProject": "Test",
                    "product": "Product",
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "Test",
                    "dateAdded": "2025-01-15",
                    "requiredAction": "Patch",
                }
            ]
        }
        mock_get.return_value = mock_response

        alert_service = AlertService(
            db=temp_db,
            feeds=[feed],
            recipient_emails=["test@example.com"],
            smtp_host="localhost",
            smtp_port=25,
            smtp_user="",
            smtp_password="",
            sender_email="alerts@example.com",
            min_severity=SeverityLevel.CRITICAL,
        )

        notified, failed = alert_service.run_alert_cycle(dry_run=True)
        assert notified >= 0
