from datetime import datetime, timedelta, timezone

import httpx
import pytest


@pytest.mark.integration
def test_outbox_matches_subscriptions_and_does_not_repeat_recollection(repository, vulnerability):
    now = datetime.now(timezone.utc)
    repository.save(vulnerability, now, baseline=True)
    subscription = repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alerts@example.org",
            "products": ["apache::log4j"],
            "changes": False,
            "enabled": True,
        },
    )
    other = repository.save_subscription(
        "bob",
        {
            "name": "Other",
            "email": "bob@example.org",
            "products": ["other::server"],
            "changes": True,
            "enabled": True,
        },
    )
    new = vulnerability.model_copy(update={"cve_id": "CVE-2026-12345"})
    repository.save(new, now)
    repository.save(new, now + timedelta(hours=12))
    alerts = repository.alerts("alice")
    assert len(alerts) == 1
    assert alerts[0]["subscription_id"] == subscription["id"]
    assert alerts[0]["items"][0]["event"] == "new"
    assert repository.alerts("bob") == []
    repository.save(new.model_copy(update={"action": "New action"}), now + timedelta(days=1))
    assert len(repository.alerts("alice")) == 1
    repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alerts@example.org",
            "products": ["apache::log4j"],
            "changes": True,
            "enabled": True,
        },
        subscription["id"],
    )
    repository.save(new.model_copy(update={"action": "Urgent action"}), now + timedelta(days=2))
    assert len(repository.alerts("alice")) == 2
    assert repository.alerts("alice")[0]["items"][0]["event"] == "changed"
    assert other["id"] != subscription["id"]


@pytest.mark.integration
def test_transaction_rolls_back_cve_when_outbox_write_fails(repository, vulnerability, monkeypatch):
    now = datetime.now(timezone.utc)
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
    from pymongo.collection import Collection

    original = Collection.update_one

    def broken(self, *args, **kwargs):
        if self.name == "outbox":
            raise RuntimeError("outbox unavailable")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Collection, "update_one", broken)
    with pytest.raises(RuntimeError):
        repository.save(vulnerability, now)
    assert repository.get(vulnerability.cve_id) is None
    assert repository.alerts("alice") == []


@pytest.mark.integration
def test_delivery_reservation_retry_and_smtp_mailpit(repository, vulnerability):
    from app.application.notify import Notify
    from app.infrastructure.smtp import SmtpSender
    from app.settings import Settings

    now = datetime.now(timezone.utc)
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
    repository.save(vulnerability, now)
    delivery = repository.reserve_delivery(now)
    assert delivery
    assert repository.reserve_delivery(now) is None
    repository.finish_delivery(delivery, now, error="SMTP offline")
    assert repository.reserve_delivery(now) is None
    result = Notify(repository, SmtpSender(Settings())).run(now + timedelta(minutes=2))
    assert result == {"sent": 1, "failed": 0, "cancelled": 0}
    alert = repository.alerts("alice")[0]
    assert alert["status"] == "sent"
    assert alert["attempts"] == 2
    assert Notify(repository, SmtpSender(Settings())).run(now + timedelta(minutes=3))["sent"] == 0
    messages = httpx.get("http://localhost:8025/api/v1/messages").json()["messages"]
    assert any("Apache" in message["Subject"] for message in messages)


@pytest.mark.integration
def test_unsubscribed_delivery_is_cancelled_and_send_failure_is_retryable(
    repository, vulnerability
):
    from app.application.notify import Notify
    import smtplib

    now = datetime.now(timezone.utc)
    sub = repository.save_subscription(
        "alice",
        {
            "name": "Apache",
            "email": "alerts@example.org",
            "products": ["apache::log4j"],
            "changes": True,
            "enabled": True,
        },
    )
    repository.save(vulnerability, now)

    class Failing:
        def send(self, delivery):
            raise smtplib.SMTPException("offline")

    assert Notify(repository, Failing()).run(now)["failed"] == 1
    repository.delete_subscription("alice", sub["id"])
    assert Notify(repository, Failing()).run(now + timedelta(minutes=2))["cancelled"] == 1


@pytest.mark.integration
def test_exhausted_delivery_requires_explicit_retry_and_old_claim_cannot_finish(
    repository, vulnerability
):
    now = datetime.now(timezone.utc)
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
    repository.save(vulnerability, now)
    stale = repository.reserve_delivery(now)
    recovered = repository.reserve_delivery(now + timedelta(minutes=3))
    repository.finish_delivery(stale, now + timedelta(minutes=3))
    assert repository.alerts("alice")[0]["status"] == "sending"
    repository.finish_delivery(recovered, now + timedelta(minutes=3), error="offline")
    for minute in (6, 10, 15):
        claim = repository.reserve_delivery(now + timedelta(minutes=minute))
        repository.finish_delivery(claim, now + timedelta(minutes=minute), error="offline")
    alert = repository.alerts("alice")[0]
    assert alert["status"] == "failed"
    assert alert["attempts"] == 5
    assert repository.retry_delivery(alert["id"])
    assert repository.alerts("alice")[0]["status"] == "pending"
    assert repository.retry_delivery("missing") is False


@pytest.mark.integration
def test_invalid_smtp_message_is_recorded_as_failure_instead_of_poisoning_worker(
    repository, vulnerability
):
    from app.application.notify import Notify

    now = datetime.now(timezone.utc)
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
    repository.save(vulnerability, now)

    class InvalidMessage:
        def send(self, delivery):
            raise ValueError("Header values may not contain linefeed")

    assert Notify(repository, InvalidMessage()).run(now)["failed"] == 1
    assert repository.alerts("alice")[0]["status"] == "pending"
