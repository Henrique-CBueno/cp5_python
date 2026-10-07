import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from pymongo import ASCENDING

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

    def save(self, record: Vulnerability, now, baseline=False):
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
                existing = self.db.vulnerabilities.find_one({"cve_id": record.cve_id}, session=s)
                state = (
                    "new"
                    if not existing
                    else ("unchanged" if existing["fingerprint"] == fingerprint else "changed")
                )
                self.db.vulnerabilities.update_one(
                    {"cve_id": record.cve_id},
                    {
                        "$set": snapshot | {"fingerprint": fingerprint, "last_collected_at": now},
                        "$setOnInsert": {"first_collected_at": now, "nvd_status": "pending"},
                    },
                    upsert=True,
                    session=s,
                )
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
