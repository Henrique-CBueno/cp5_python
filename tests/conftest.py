import os
import uuid

import pytest
from pymongo import MongoClient


@pytest.fixture
def repository():
    from app.infrastructure.mongo import MongoRepository

    uri = os.getenv(
        "TEST_MONGO_URI", "mongodb://localhost:27018/?replicaSet=rs0&directConnection=true"
    )
    client = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
    db = client[f"vigilia_test_{uuid.uuid4().hex}"]
    repo = MongoRepository(db)
    repo.initialize()
    yield repo
    client.drop_database(db.name)
    client.close()


@pytest.fixture
def vulnerability():
    from app.domain.vulnerability import Vulnerability

    return Vulnerability(
        cve_id="CVE-2021-44228",
        vendor="Apache",
        product="Log4j",
        title="Log4Shell",
        description="Remote execution",
        action="Upgrade",
        date_added="2021-12-10",
        due_date="2021-12-24",
        ransomware="Known",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
