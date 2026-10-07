import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from pymongo import ASCENDING, ReturnDocument

from app.domain.vulnerability import Vulnerability


class MongoRepository:
    def __init__(self, db):
        self.db = db

    def initialize(self):
        self.db.vulnerabilities.create_index("cve_id", unique=True)
        self.db.vulnerabilities.create_index(
            [("product_key", ASCENDING), ("date_added", ASCENDING)]
        )

        self.db.sessions.create_index("expires_at", expireAfterSeconds=0)
        self.db.subscriptions.create_index("owner")
        self.db.subscriptions.create_index("id", unique=True)
        self.db.outbox.create_index("id", unique=True)
        self.db.outbox.create_index([("status", 1), ("next_attempt", 1)])
        self.db.runs.create_index("id", unique=True)
        now = datetime.now(timezone.utc)
        self.db.settings.update_one({"_id": "schedule"}, {"$setOnInsert": {"enabled": True, "interval_hours": 12, "max_pages": 0, "next_run_at": now, "baseline_completed": False}}, upsert=True)
        self.db.settings.update_one({"_id": "collector"}, {"$setOnInsert": {"lease_until": now, "run_id": None}}, upsert=True)

    def schedule(self):
        return self.db.settings.find_one({"_id": "schedule"}, {"_id": 0})

    def configure_schedule(self, data, now):
        self.db.settings.update_one({"_id": "schedule"}, {"$set": data | {"next_run_at": now + timedelta(hours=data["interval_hours"])}})
        return self.schedule()

    def enqueue_run(self, requested_by, max_pages=None):
        config = self.schedule()
        if self.db.runs.count_documents({"status": "queued"}) >= 5:
            raise ValueError("Já há cinco execuções aguardando; espere a conclusão")
        job = {"id": uuid.uuid4().hex, "requested_by": requested_by, "max_pages": config["max_pages"] if max_pages is None else max_pages, "created_at": datetime.now(timezone.utc), "status": "queued", "progress": {"pages": 0, "new": 0, "changed": 0, "unchanged": 0}}
        self.db.runs.insert_one(job.copy())
        return job

    def reserve_run(self, now):
        claim = uuid.uuid4().hex
        lock = self.db.settings.find_one_and_update({"_id": "collector", "lease_until": {"$lte": now}}, {"$set": {"claim": claim, "run_id": None, "lease_until": now + timedelta(minutes=15)}}, return_document=ReturnDocument.BEFORE)
        if not lock:
            return None
        if lock.get("run_id"):
            self.db.runs.update_one({"id": lock["run_id"], "status": "running"}, {"$set": {"status": "failed", "error": "Worker interrompido; reserva expirada", "finished_at": now}})
            self.db.outbox.update_many({"run_id": lock["run_id"]}, {"$set": {"ready": True}})
        config = self.schedule()
        if not self.db.runs.count_documents({"status": "queued"}) and config["enabled"] and config["next_run_at"] <= now:
            self.enqueue_run("schedule")
            self.db.settings.update_one({"_id": "schedule"}, {"$set": {"next_run_at": now + timedelta(hours=config["interval_hours"])}})
        job = self.db.runs.find_one_and_update({"status": "queued"}, {"$set": {"status": "running", "started_at": now, "baseline": not config["baseline_completed"]}}, sort=[("created_at", 1)], return_document=ReturnDocument.AFTER, projection={"_id": 0})
        self.db.settings.update_one({"_id": "collector", "claim": claim}, {"$set": {"run_id": job["id"] if job else None, **({"lease_until": now} if not job else {})}})
        return job

    def progress_run(self, run_id, progress, now):
        lock = self.db.settings.update_one({"_id": "collector", "run_id": run_id, "lease_until": {"$gt": now}}, {"$set": {"lease_until": now + timedelta(minutes=15)}})
        if not lock.matched_count:
            raise ValueError("Reserva de execução expirada")
        self.db.runs.update_one({"id": run_id, "status": "running"}, {"$set": {"progress": progress}})

    def finish_run(self, run_id, progress, now, error=None, warning=None):
        with self.db.client.start_session() as session:
            def transaction(s):
                lock = self.db.settings.find_one({"_id": "collector", "run_id": run_id, "lease_until": {"$gt": now}}, session=s)
                if not lock:
                    return False
                job = self.db.runs.find_one({"id": run_id}, session=s)
                self.db.runs.update_one({"id": run_id}, {"$set": {"status": "failed" if error else "completed", "progress": progress, "finished_at": now, "error": error, "warning": warning}}, session=s)
                self.db.outbox.update_many({"run_id": run_id}, {"$set": {"ready": True}}, session=s)
                if not error and job["baseline"] and job["max_pages"] == 0:
                    self.db.settings.update_one({"_id": "schedule"}, {"$set": {"baseline_completed": True}}, session=s)
                self.db.settings.update_one({"_id": "collector"}, {"$set": {"run_id": None, "lease_until": now}}, session=s)
                return True
            return session.with_transaction(transaction)

    def runs(self):
        return list(self.db.runs.find({}, {"_id": 0}).sort("created_at", -1).limit(50))

    def identity_config(self):
        return self.db.settings.find_one({"_id": "identity"}, {"_id": 0})

    def configure_identity(self, config):
        self.db.settings.update_one({"_id": "identity"}, {"$set": config}, upsert=True)

    def save_session(self, session_id, token, expires, csrf):
        self.db.sessions.insert_one({"_id": session_id, "token": token, "expires_at": expires, "csrf": csrf})

    def session(self, session_id):
        return self.db.sessions.find_one({"_id": session_id, "expires_at": {"$gt": datetime.now(timezone.utc)}})

    def delete_session(self, session_id):
        self.db.sessions.delete_one({"_id": session_id})

    def save_subscription(self, owner, data, subscription_id=None):
        now = datetime.now(timezone.utc)
        if subscription_id:
            existing = self.db.subscriptions.find_one({"id": subscription_id, "owner": owner})
            if not existing:
                return None
            self.db.subscriptions.update_one({"id": subscription_id, "owner": owner}, {"$set": data | {"updated_at": now}})
        else:
            subscription_id = uuid.uuid4().hex
            self.db.subscriptions.insert_one(data | {"id": subscription_id, "owner": owner, "created_at": now, "updated_at": now})
        return self.db.subscriptions.find_one({"id": subscription_id, "owner": owner}, {"_id": 0})

    def subscriptions(self, owner):
        return list(self.db.subscriptions.find({"owner": owner}, {"_id": 0}).sort("created_at", -1))

    def delete_subscription(self, owner, subscription_id):
        return self.db.subscriptions.delete_one({"id": subscription_id, "owner": owner}).deleted_count == 1

    def alerts(self, owner=None):
        return list(self.db.outbox.find({"owner": owner} if owner else {}, {"_id": 0}).sort([("created_at", -1), ("id", 1)]).limit(100))

    def reserve_delivery(self, now):
        return self.db.outbox.find_one_and_update({"ready": True, "$or": [{"status": "pending", "next_attempt": {"$lte": now}}, {"status": "sending", "lease_until": {"$lte": now}}]}, {"$set": {"status": "sending", "claim": uuid.uuid4().hex, "lease_until": now + timedelta(minutes=2)}, "$inc": {"attempts": 1}}, sort=[("created_at", 1)], return_document=ReturnDocument.AFTER, projection={"_id": 0})

    def delivery_counts(self):
        return {r["_id"]: r["count"] for r in self.db.outbox.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}])}

    def retry_delivery(self, delivery_id):
        return self.db.outbox.update_one({"id": delivery_id, "status": "failed"}, {"$set": {"status": "pending", "attempts": 0, "next_attempt": datetime.now(timezone.utc)}}).modified_count == 1

    def queue_test(self, owner, subscription_id):
        subscription = self.db.subscriptions.find_one({"id": subscription_id, "owner": owner, "enabled": True})
        if not subscription:
            return False
        now = datetime.now(timezone.utc)
        record = self.db.vulnerabilities.find_one({"product_key": {"$in": subscription["products"]}, "simulated": False})
        if not record:
            return False
        self.db.outbox.insert_one({"id": uuid.uuid4().hex, "owner": owner, "subscription_id": subscription_id, "name": subscription["name"], "email": subscription["email"], "run_id": None, "created_at": now, "status": "pending", "ready": True, "attempts": 0, "next_attempt": now, "items": [{"cve_id": record["cve_id"], "event": "new", "vendor": record["vendor"], "product": record["product"], "title": "DEMONSTRAÇÃO — teste de entrega SMTP", "action": "Nenhuma ação: teste de envio.", "simulated": True}]})
        return True

    def subscription_active(self, delivery):
        return bool(self.db.subscriptions.find_one({"id": delivery["subscription_id"], "owner": delivery["owner"], "enabled": True}))

    def finish_delivery(self, delivery, now, error=None, cancelled=False):
        state = "cancelled" if cancelled else ("failed" if error and delivery["attempts"] >= 5 else "pending" if error else "sent")
        self.db.outbox.update_one({"id": delivery["id"], "claim": delivery["claim"], "status": "sending"}, {"$set": {"status": state, "error": error, "next_attempt": now + timedelta(seconds=60 * delivery["attempts"]), "finished_at": now}})

    def save(self, record: Vulnerability, now, baseline=False, run_id=None):
        snapshot = record.snapshot()
        # A URL de paginação pode mudar sem que a vulnerabilidade mude.
        fingerprint = hashlib.sha256(
            json.dumps(
                {k: v for k, v in snapshot.items() if k != "source_url"},
                sort_keys=True,
            ).encode()
        ).hexdigest()
        with self.db.client.start_session() as session:

            def transaction(s):
                if run_id and not self.db.settings.find_one({"_id": "collector", "run_id": run_id, "lease_until": {"$gt": now}}, session=s):
                    raise ValueError("Reserva de execução expirada")
                existing = self.db.vulnerabilities.find_one({"cve_id": record.cve_id}, session=s)
                state = (
                    "new"
                    if not existing
                    else ("unchanged" if existing["fingerprint"] == fingerprint else "changed")
                )
                revision = (existing.get("revision", 1) if existing else 0) + (state != "unchanged")
                self.db.vulnerabilities.update_one(
                    {"cve_id": record.cve_id},
                    {
                        "$set": snapshot | {"fingerprint": fingerprint, "last_collected_at": now, "revision": revision},
                        "$setOnInsert": {"first_collected_at": now, "nvd_status": "pending"},
                    },
                    upsert=True,
                    session=s,
                )
                if state != "unchanged" and not baseline:
                    recipients = self.db.subscriptions.find({"enabled": True, "products": record.product_key, **({"changes": True} if state == "changed" else {})}, session=s)
                    for subscription in recipients:
                        delivery_id = f"{subscription['id']}:{run_id or record.cve_id + ':' + str(revision)}"
                        event = {"cve_id": record.cve_id, "revision": revision, "event": state, "vendor": record.vendor, "product": record.product, "title": record.title, "action": record.action, "simulated": record.simulated}
                        self.db.outbox.update_one({"id": delivery_id}, {"$setOnInsert": {"id": delivery_id, "owner": subscription["owner"], "subscription_id": subscription["id"], "name": subscription["name"], "email": subscription["email"], "run_id": run_id, "created_at": now, "status": "pending", "ready": not bool(run_id), "attempts": 0, "next_attempt": now}, "$addToSet": {"items": event}}, upsert=True, session=s)
                return state

            return session.with_transaction(transaction)

    def get(self, cve_id):
        return self.db.vulnerabilities.find_one({"cve_id": cve_id}, {"_id": 0, "fingerprint": 0})

    def list_records(self, filters, page=1, page_size=20):
        query = filters | {"simulated": False}
        items = list(
            self.db.vulnerabilities.find(query, {"_id": 0, "fingerprint": 0})
            .sort([("date_added", -1), ("cve_id", 1)])
            .skip((page - 1) * page_size)
            .limit(page_size)
        )
        return {
            "items": items,
            "total": self.db.vulnerabilities.count_documents(query),
            "page": page,
            "page_size": page_size,
        }

    def products(self):
        return list(self.db.vulnerabilities.aggregate([
            {"$match": {"simulated": False}},
            {"$group": {"_id": "$product_key", "vendor": {"$first": "$vendor"}, "product": {"$first": "$product"}, "count": {"$sum": 1}}},
            {"$project": {"_id": 0, "key": "$_id", "vendor": 1, "product": 1, "count": 1}},
            {"$sort": {"vendor": 1, "product": 1}},
        ]))

    def enrichment_ids(self):
        return [r["cve_id"] for r in self.db.vulnerabilities.find({"simulated": False}, {"cve_id": 1}).sort("nvd_updated_at", 1)]

    def save_enrichment(self, cve_id, value, now):
        fields = {"nvd_status": "ready" if value else "pending", "nvd_checked_at": now}
        if value:
            fields |= {"nvd": value, "nvd_updated_at": now}
        self.db.vulnerabilities.update_one({"cve_id": cve_id}, {"$set": fields})

    def statistics(self, filters):
        recent = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        def grouped(expression):
            return [{"$group": {"_id": expression, "count": {"$sum": 1}}}, {"$sort": {"count": -1, "_id": 1}}, {"$project": {"_id": 0, "label": "$_id", "count": 1}}]
        result = next(self.db.vulnerabilities.aggregate([
            {"$match": filters | {"simulated": False}},
            {"$facet": {
                "totals": [{"$group": {"_id": None, "total": {"$sum": 1}, "vendors": {"$addToSet": "$vendor"}, "ransomware": {"$sum": {"$cond": [{"$eq": ["$ransomware", "Known"]}, 1, 0]}}, "recent": {"$sum": {"$cond": [{"$gte": ["$date_added", recent]}, 1, 0]}}, "assessed": {"$sum": {"$cond": [{"$ifNull": ["$nvd.primary", False]}, 1, 0]}}, "critical_ransomware": {"$sum": {"$cond": [{"$and": [{"$eq": ["$ransomware", "Known"]}, {"$eq": ["$nvd.primary.severity", "CRITICAL"]}]}, 1, 0]}}}}],
                "vendors": grouped("$vendor") + [{"$limit": 10}],
                "months": grouped({"$substr": ["$date_added", 0, 7]}) + [{"$sort": {"label": 1}}],
                "severity": grouped({"$ifNull": ["$nvd.primary.severity", "UNASSESSED"]}),
                "cwes": [{"$unwind": "$cwes"}] + grouped("$cwes") + [{"$limit": 10}],
                "ransomware_vendors": [{"$match": {"ransomware": "Known"}}] + grouped("$vendor") + [{"$limit": 10}],
            }},
        ]))
        totals = result.pop("totals")
        summary = totals[0] if totals else {"total": 0, "vendors": [], "ransomware": 0, "recent": 0, "assessed": 0, "critical_ransomware": 0}
        total = summary["total"]
        def percent(value):
            return round(100 * value / total, 1) if total else 0
        return result | {"total": total, "vendors_count": len(summary["vendors"]), "ransomware_percent": percent(summary["ransomware"]), "recent_count": summary["recent"], "assessed_percent": percent(summary["assessed"]), "critical_ransomware": summary["critical_ransomware"], "top5_percent": percent(sum(v["count"] for v in result["vendors"][:5]))}
