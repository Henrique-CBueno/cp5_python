from datetime import UTC, datetime, timedelta

import pytest


@pytest.mark.integration
def test_admin_schedule_queue_and_exclusive_reservation(repository):
    now = datetime.now(UTC)
    assert repository.schedule()["interval_hours"] == 12
    repository.configure_schedule({"enabled": False, "interval_hours": 6, "max_pages": 2}, now)
    assert repository.reserve_run(now) is None
    queued = repository.enqueue_run("admin", max_pages=1)
    job = repository.reserve_run(now + timedelta(seconds=1))
    assert job["id"] == queued["id"]
    assert job["max_pages"] == 1
    assert repository.reserve_run(now + timedelta(seconds=2)) is None
    repository.progress_run(job["id"], {"pages": 1, "new": 20}, now)
    repository.finish_run(job["id"], {"pages": 1, "new": 20}, now)
    assert repository.runs()[0]["status"] == "completed"
    assert repository.reserve_run(now + timedelta(seconds=3)) is None
    repository.configure_schedule({"enabled": True, "interval_hours": 6, "max_pages": 0}, now)
    scheduled = repository.reserve_run(now + timedelta(hours=6, seconds=1))
    assert scheduled["requested_by"] == "schedule"


@pytest.mark.integration
def test_worker_collects_then_releases_grouped_alerts_and_reports_nvd_failure(
    repository, vulnerability
):
    from app.application.execute import Execute

    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": False, "interval_hours": 12, "max_pages": 0}, now)
    repository.db.settings.update_one({"_id": "schedule"}, {"$set": {"baseline_completed": True}})
    repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alerts@example.org",
            "products": ["apache::log4j"],
            "changes": True,
            "enabled": True,
        },
    )
    repository.enqueue_run("admin", max_pages=1)
    job = repository.reserve_run(now + timedelta(seconds=1))

    class Source:
        def pages(self, max_pages=0):
            yield (
                "https://www.cisa.gov/catalog",
                [vulnerability, vulnerability.model_copy(update={"cve_id": "CVE-2026-12345"})],
            )

    class Missing:
        def fetch(self, ids):
            raise ValueError("invalid NVD response")

    Execute(repository, Source(), Missing()).run(job)
    execution = repository.runs()[0]
    assert execution["status"] == "completed"
    assert execution["progress"]["new"] == 2
    assert "NVD" in execution["warning"]
    alerts = repository.alerts("alice")
    assert len(alerts) == 1
    assert len(alerts[0]["items"]) == 2
    assert repository.reserve_delivery(datetime.now(UTC)) is not None


@pytest.mark.integration
def test_interrupted_worker_is_recovered_and_stale_owner_cannot_finish(repository):
    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": False, "interval_hours": 12, "max_pages": 0}, now)
    repository.enqueue_run("admin")
    first = repository.reserve_run(now)
    repository.enqueue_run("admin")
    second = repository.reserve_run(now + timedelta(minutes=16))
    assert first["id"] != second["id"]
    assert repository.finish_run(first["id"], {}, now + timedelta(minutes=16)) is False
    assert any(r["status"] == "failed" for r in repository.runs())


@pytest.mark.integration
def test_failed_initial_collection_preserves_data_without_completing_baseline(
    repository, vulnerability
):
    from app.application.execute import Execute

    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": False, "interval_hours": 12, "max_pages": 0}, now)
    repository.enqueue_run("admin")
    job = repository.reserve_run(now)

    class BrokenSource:
        def pages(self, max_pages=0):
            yield "https://www.cisa.gov/catalog", [vulnerability]
            raise ValueError("Source unavailable")

    Execute(repository, BrokenSource(), None).run(job)
    assert repository.runs()[0]["status"] == "failed"
    assert repository.runs()[0]["progress"]["pages"] == 1
    assert repository.get(vulnerability.cve_id)
    assert repository.schedule()["baseline_completed"] is False


@pytest.mark.integration
def test_stale_worker_cannot_write_vulnerabilities(repository, vulnerability):
    now = datetime.now(UTC)
    repository.configure_schedule({"enabled": False, "interval_hours": 12, "max_pages": 0}, now)
    repository.enqueue_run("admin")
    job = repository.reserve_run(now)
    with pytest.raises(ValueError, match="expirada"):
        repository.save(vulnerability, now + timedelta(minutes=16), run_id=job["id"])
    assert repository.get(vulnerability.cve_id) is None
