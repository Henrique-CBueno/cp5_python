from datetime import UTC, datetime, timedelta

import pytest


@pytest.mark.integration
def test_reset_erases_operational_data_but_preserves_accounts_subscriptions_and_schedule(
    repository, vulnerability
):
    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": True, "interval_hours": 6, "max_pages": 0}, now)
    repository.db.settings.update_one({"_id": "schedule"}, {"$set": {"baseline_completed": True}})
    repository.configure_identity({"pool_id": "existing-pool", "client_id": "existing-client"})
    repository.save_session("session", "token", now + timedelta(hours=1), "csrf")
    subscription = repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alice@example.org",
            "products": ["apache::log4j"],
            "changes": True,
            "enabled": True,
        },
    )
    repository.save(vulnerability, now)
    repository.enqueue_run("admin")
    result = repository.reset_operational_data(now)
    assert result == {"vulnerabilities": 1, "runs": 1, "deliveries": 1}
    assert repository.list_records({})["total"] == 0
    assert repository.runs() == []
    assert repository.alerts("alice") == []
    assert repository.subscriptions("alice")[0]["id"] == subscription["id"]
    assert repository.identity_config()["pool_id"] == "existing-pool"
    assert repository.session("session")
    schedule = repository.schedule()
    assert schedule["enabled"] is True
    assert schedule["interval_hours"] == 6
    assert schedule["max_pages"] == 0
    assert schedule["baseline_completed"] is False
    assert abs((schedule["next_run_at"] - now - timedelta(hours=6)).total_seconds()) < 0.001
    repository.save(vulnerability, now + timedelta(minutes=1), baseline=True)
    assert repository.alerts("alice") == []


@pytest.mark.integration
@pytest.mark.parametrize("activity", ["collection", "delivery"])
def test_reset_refuses_active_work_without_deleting_anything(repository, vulnerability, activity):
    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": False, "interval_hours": 12, "max_pages": 0}, now)
    repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alice@example.org",
            "products": ["apache::log4j"],
            "changes": True,
            "enabled": True,
        },
    )
    repository.save(vulnerability, now)
    repository.enqueue_run("admin")
    if activity == "collection":
        assert repository.reserve_run(now)
    else:
        assert repository.reserve_delivery(now)
    with pytest.raises(ValueError, match="andamento"):
        repository.reset_operational_data(now + timedelta(seconds=1))
    assert repository.get(vulnerability.cve_id)
    assert len(repository.runs()) == 1
    assert len(repository.alerts("alice")) == 1


@pytest.mark.integration
def test_reset_rolls_back_all_deletions_if_a_collection_fails(
    repository, vulnerability, monkeypatch
):
    from pymongo.collection import Collection

    now = datetime.now(UTC)
    repository.save(vulnerability, now, baseline=True)
    repository.enqueue_run("admin")
    original = Collection.delete_many

    def fail_on_runs(self, *args, **kwargs):
        if self.name == "runs":
            raise RuntimeError("Delete failed")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Collection, "delete_many", fail_on_runs)
    with pytest.raises(RuntimeError):
        repository.reset_operational_data(now)
    assert repository.get(vulnerability.cve_id)
    assert len(repository.runs()) == 1
