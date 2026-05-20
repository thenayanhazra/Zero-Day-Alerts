from unittest.mock import patch, MagicMock
import pytest
from models import SeverityLevel, ExploitStatus
from feeds import CisaKevFeed


@pytest.fixture
def sample_kev_catalog() -> dict:
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-0001",
                "vendorProject": "Example Corp",
                "product": "Router",
                "vulnerabilityName": "Remote Code Execution",
                "shortDescription": "Allows RCE",
                "dateAdded": "2025-01-15",
                "requiredAction": "Apply patch",
            }
        ]
    }


def test_cisa_kev_fetch_and_normalize(sample_kev_catalog: dict) -> None:
    feed = CisaKevFeed("http://example.com/kev.json")
    with patch("feeds.cisa_kev.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = sample_kev_catalog
        mock_get.return_value = mock_response

        vulns = feed.fetch()

        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln.cve_id == "CVE-2025-0001"
        assert vuln.title == "Remote Code Execution"
        assert vuln.severity_level == SeverityLevel.CRITICAL
        assert vuln.exploit_status == ExploitStatus.EXPLOITED


def test_cisa_kev_skips_malformed_records(sample_kev_catalog: dict) -> None:
    feed = CisaKevFeed("http://example.com/kev.json")
    sample_kev_catalog["vulnerabilities"].append(
        {
            "cveID": "CVE-2025-0002",
            "vendorProject": "Bad Corp",
            "product": "BadProduct",
            "vulnerabilityName": "Bad Entry",
            "shortDescription": "Missing dateAdded",
            "requiredAction": "N/A",
        }
    )

    with patch("feeds.cisa_kev.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = sample_kev_catalog
        mock_get.return_value = mock_response

        vulns = feed.fetch()
        assert len(vulns) == 1


def test_cisa_kev_handles_json_error() -> None:
    feed = CisaKevFeed("http://example.com/kev.json")
    with patch("feeds.cisa_kev.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Failed to parse KEV catalog JSON"):
            feed.fetch()
