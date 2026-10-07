from datetime import datetime, timezone

from app.application.execute import Execute
from app.application.notify import Notify


def tick(repository, source, enrichment, sender):
    job = repository.reserve_run(datetime.now(timezone.utc))
    if job:
        Execute(repository, source, enrichment).run(job)
    return Notify(repository, sender).run()
