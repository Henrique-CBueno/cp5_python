from datetime import UTC, datetime

import pytest


@pytest.mark.integration
def test_worker_tick_consumes_admin_job_and_sends_alerts(repository, vulnerability):
    from app.worker import tick

    repository.configure_schedule(
        {"enabled": False, "interval_hours": 12, "max_pages": 0}, datetime.now(UTC)
    )
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
    repository.enqueue_run("admin")

    class Source:
        def pages(self, max_pages=0):
            yield "https://www.cisa.gov/catalog", [vulnerability]

    class Enrichment:
        def fetch(self, ids):
            return {ids[0]: {"primary": None}}

    sent = []

    class Sender:
        def send(self, delivery):
            sent.append(delivery)

    assert tick(repository, Source(), Enrichment(), Sender())["sent"] == 1
    assert len(sent) == 1
    assert tick(repository, Source(), Enrichment(), Sender())["sent"] == 0


@pytest.mark.integration
def test_cli_bootstrap_collection_and_single_worker_cycle(
    repository, vulnerability, monkeypatch, capsys
):
    import uuid

    from app.cli import main

    monkeypatch.setenv("MONGO_DATABASE", repository.db.name)
    monkeypatch.setenv("ADMIN_EMAIL", f"admin-{uuid.uuid4().hex}@example.org")
    monkeypatch.setenv("ADMIN_PASSWORD", "AdminPass123!")
    assert main(["bootstrap"]) == 0
    assert "Senha inicial" in capsys.readouterr().out
    assert main(["bootstrap"]) == 0
    assert "Senha inicial" not in capsys.readouterr().out
    repository.configure_schedule(
        {"enabled": False, "interval_hours": 12, "max_pages": 0}, datetime.now(UTC)
    )

    class Source:
        def __init__(self, *args):
            pass

        def pages(self, max_pages=0):
            yield "https://www.cisa.gov/catalog", [vulnerability]

    class Enrichment:
        def __init__(self, *args):
            pass

        def fetch(self, ids):
            return {ids[0]: {"primary": None}}

    monkeypatch.setattr("app.cli.CisaCrawler", Source)
    monkeypatch.setattr("app.cli.NvdClient", Enrichment)
    assert main(["collect", "--pages", "1"]) == 0
    assert repository.get(vulnerability.cve_id)["nvd_status"] == "ready"
    assert main(["worker", "--once"]) == 0
    with pytest.raises(SystemExit):
        main(["collect", "--pages", "-1"])
