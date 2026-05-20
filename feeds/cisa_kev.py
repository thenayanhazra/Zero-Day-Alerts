from __future__ import annotations

from datetime import datetime
import requests
from models import Vulnerability, SeverityLevel, ExploitStatus
from .base import FeedSource


class CisaKevFeed(FeedSource):
    name = "CISA_KEV"

    def __init__(self, url: str, timeout_seconds: int = 20) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds

    def fetch(self) -> list[Vulnerability]:
        try:
            response = requests.get(self.url, timeout=self.timeout_seconds)
            response.raise_for_status()
            catalog = response.json()
        except ValueError as exc:
            raise ValueError(f"Failed to parse KEV catalog JSON: {exc}") from exc
        except requests.RequestException as exc:
            raise requests.RequestException(f"Failed to fetch KEV catalog: {exc}") from exc

        vulnerabilities = []
        for item in catalog.get("vulnerabilities", []):
            try:
                vuln = self.normalize(item)
                if vuln:
                    vulnerabilities.append(vuln)
            except (KeyError, ValueError):
                pass

        return vulnerabilities

    def normalize(self, item: dict) -> Vulnerability | None:
        try:
            cve_id = item.get("cveID", "").strip()
            if not cve_id:
                return None

            vendor_project = item.get("vendorProject", "").strip()
            product = item.get("product", "").strip()
            vuln_name = item.get("vulnerabilityName", "").strip()
            description = item.get("shortDescription", "").strip()
            required_action = item.get("requiredAction", "").strip()
            date_added_str = item.get("dateAdded", "").strip()

            if not date_added_str:
                return None

            discovered_date = datetime.fromisoformat(date_added_str).date()
            affected_products = [p for p in [vendor_project, product] if p]

            return Vulnerability(
                cve_id=cve_id,
                title=vuln_name,
                description=description or "",
                severity_level=SeverityLevel.CRITICAL,
                exploit_status=ExploitStatus.EXPLOITED,
                affected_products=affected_products,
                discovered_date=datetime.combine(discovered_date, datetime.min.time()),
                feed_sources=[self.name],
                remediation=required_action,
                source_url=self.url,
            )
        except (KeyError, ValueError):
            return None
