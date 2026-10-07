from datetime import datetime, timezone

from app.application.source import VulnerabilitySource
from app.domain.repository import VulnerabilityRepository


class Collect:
    def __init__(self, source: VulnerabilitySource, repository: VulnerabilityRepository):
        self.source, self.repository = source, repository

    def run(self, max_pages=0, baseline=False, progress=lambda _: None):
        counts = {"pages": 0, "new": 0, "changed": 0, "unchanged": 0}
        for _, records in self.source.pages(max_pages):
            for record in records:
                state = self.repository.save(record, datetime.now(timezone.utc), baseline=baseline)
                counts[state] += 1
            counts["pages"] += 1
            progress(counts.copy())
        return counts
