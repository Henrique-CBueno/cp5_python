import smtplib
from datetime import datetime, timezone
from typing import Protocol


class NotificationSender(Protocol):
    def send(self, delivery: dict) -> None: ...


class Notify:
    def __init__(self, repository, sender: NotificationSender):
        self.repository, self.sender = repository, sender

    def run(self, now=None):
        now = now or datetime.now(timezone.utc)
        counts = {"sent": 0, "failed": 0, "cancelled": 0}
        while delivery := self.repository.reserve_delivery(now):
            if not self.repository.subscription_active(delivery):
                self.repository.finish_delivery(delivery, now, cancelled=True)
                counts["cancelled"] += 1
                continue
            try:
                self.sender.send(delivery)
            except (smtplib.SMTPException, OSError) as exc:
                self.repository.finish_delivery(delivery, now, error=str(exc))
                counts["failed"] += 1
            else:
                self.repository.finish_delivery(delivery, now)
                counts["sent"] += 1
        return counts
