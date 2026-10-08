from datetime import UTC, datetime

from app.application.execute import Execute
from app.application.notify import Notify


def tick(repository, source, enrichment, sender):
    job = repository.reserve_run(datetime.now(UTC))
    if job:
        Execute(repository, source, enrichment).run(job)
    return Notify(repository, sender).run()
