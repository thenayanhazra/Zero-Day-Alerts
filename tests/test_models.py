from datetime import datetime
import pytest
from models import Vulnerability, SeverityLevel, ExploitStatus


def test_vulnerability_creation_valid() -> None:
    vuln = Vulnerability(
        cve_id="CVE-2025-1234",
        title="Test Vulnerability",
        description="Test description",
        severity_level=SeverityLevel.HIGH,
        cvss_v3_score=8.5,
    )
    assert vuln.cve_id == "CVE-2025-1234"
    assert vuln.severity_level == SeverityLevel.HIGH


def test_vulnerability_invalid_cve_id() -> None:
    with pytest.raises(ValueError, match="Invalid CVE ID"):
        Vulnerability(
            cve_id="INVALID-ID",
            title="Test",
            description="Test",
            severity_level=SeverityLevel.HIGH,
        )


def test_vulnerability_risk_score_calculation() -> None:
    vuln = Vulnerability(
        cve_id="CVE-2025-1234",
        title="Test",
        description="Test",
        severity_level=SeverityLevel.CRITICAL,
        cvss_v3_score=9.8,
        epss_percentile=95.0,
        exploit_status=ExploitStatus.EXPLOITED,
    )
    score = vuln.risk_score()
    assert score > 0
    assert score <= 500.0


def test_vulnerability_to_dict() -> None:
    vuln = Vulnerability(
        cve_id="CVE-2025-1234",
        title="Test",
        description="Test",
        severity_level=SeverityLevel.HIGH,
        published_date=datetime(2025, 1, 15),
    )
    data = vuln.to_dict()
    assert data["cve_id"] == "CVE-2025-1234"
    assert data["severity_level"] == "HIGH"
    assert "2025-01-15" in data["published_date"]
