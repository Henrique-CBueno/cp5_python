from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.integration
def test_recollection_preserves_identity_and_first_seen(repository, vulnerability):
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert repository.save(vulnerability, first, baseline=True) == "new"
    assert repository.save(vulnerability, first + timedelta(hours=12)) == "unchanged"
    updated = vulnerability.model_copy(update={"action": "Upgrade immediately"})
    assert repository.save(updated, first + timedelta(days=1)) == "changed"
    page = repository.list_records({})
    assert page["total"] == 1
    record = repository.get(vulnerability.cve_id)
    assert record["first_collected_at"] == first
    assert record["last_collected_at"] == first + timedelta(days=1)
    assert record["action"] == "Upgrade immediately"
