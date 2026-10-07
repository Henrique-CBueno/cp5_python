import hashlib
import json

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
