from __future__ import annotations

from abc import ABC, abstractmethod
from models import Vulnerability


class FeedSource(ABC):
    name: str

    @abstractmethod
    def fetch(self) -> list[Vulnerability]:
        """Fetch and return vulnerabilities from this feed."""
        pass

    @abstractmethod
    def normalize(self, raw: dict) -> Vulnerability | None:
        """Convert a raw feed item to a normalized Vulnerability."""
        pass

    def supports_incremental_sync(self) -> bool:
        """Whether this feed supports ETag-based incremental syncing."""
        return False
