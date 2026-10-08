from datetime import UTC, datetime
from typing import Protocol

from app.domain.repository import VulnerabilityRepository


class EnrichmentSource(Protocol):
    def fetch(self, ids: list[str]) -> dict: ...


class Enrich:
    def __init__(self, source: EnrichmentSource, repository: VulnerabilityRepository):
        self.source, self.repository = source, repository

    def run(self):
        ids = self.repository.enrichment_ids()
        counts = {"enriched": 0, "missing": 0}
        for offset in range(0, len(ids), 100):
            batch = ids[offset : offset + 100]
            values = self.source.fetch(batch)
            for cve_id in batch:
                value = values.get(cve_id)
                self.repository.save_enrichment(cve_id, value, datetime.now(UTC))
                counts["enriched" if value else "missing"] += 1
        return counts
