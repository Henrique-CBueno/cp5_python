import uuid
from datetime import datetime, timezone

from app.domain.vulnerability import Vulnerability


class Simulate:
    def __init__(self, repository):
        self.repository = repository

    def run(self, product_key):
        items = self.repository.list_records({"product_key": product_key}, page_size=1)["items"]
        if not items:
            raise ValueError("Produto não encontrado")
        data = {k: v for k, v in items[0].items() if k in Vulnerability.model_fields}
        data |= {
            "cve_id": f"CVE-2099-{int(uuid.uuid4().hex[:10], 16):012d}",
            "title": "DEMONSTRAÇÃO — evento sintético para validar alertas",
            "description": "Registro sintético, sem correspondência com uma vulnerabilidade real.",
            "action": "Nenhuma ação operacional: demonstração do fluxo de notificações.",
            "simulated": True,
        }
        record = Vulnerability(**data)
        self.repository.save(record, datetime.now(timezone.utc))
        return {"cve_id": record.cve_id, "simulated": True}
