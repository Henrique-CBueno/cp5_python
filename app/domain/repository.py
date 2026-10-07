from datetime import datetime
from typing import Protocol

from app.domain.vulnerability import Vulnerability


class VulnerabilityRepository(Protocol):
    def save(
        self,
        record: Vulnerability,
        now: datetime,
        baseline: bool = False,
        run_id: str | None = None,
    ) -> str: ...
    def get(self, cve_id: str) -> dict | None: ...
    def list_records(self, filters: dict, page: int = 1, page_size: int = 20) -> dict: ...
    def enrichment_ids(self) -> list[str]: ...
    def save_enrichment(self, cve_id: str, value: dict | None, now: datetime) -> None: ...
