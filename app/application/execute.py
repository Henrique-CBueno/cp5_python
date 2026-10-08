from datetime import UTC, datetime

from app.application.collect import Collect
from app.application.enrich import Enrich


class Execute:
    def __init__(self, repository, source, enrichment):
        self.repository, self.source, self.enrichment = repository, source, enrichment

    def run(self, job):
        counts = job["progress"].copy()
        warning = None

        def progress(value):
            counts.update(value)
            self.repository.progress_run(job["id"], counts, datetime.now(UTC))

        try:
            Collect(self.source, self.repository).run(
                job["max_pages"], job["baseline"], progress, job["id"]
            )
            try:
                counts.update(Enrich(self.enrichment, self.repository).run())
            except Exception as exc:
                warning = f"Enriquecimento NVD pendente: {type(exc).__name__}"
        except Exception as exc:
            self.repository.finish_run(
                job["id"], counts, datetime.now(UTC), error=f"{type(exc).__name__}: {exc}"
            )
        else:
            self.repository.finish_run(job["id"], counts, datetime.now(UTC), warning=warning)
