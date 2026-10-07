from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api(repository):
    from app.main import create_app

    with TestClient(create_app(repository=repository)) as client:
        yield client


@pytest.mark.integration
def test_public_queries_are_paginated_filtered_and_statistics_are_not_page_limited(
    api, repository, vulnerability
):
    now = datetime.now(timezone.utc)
    repository.save(vulnerability, now, baseline=True)
    repository.save(
        vulnerability.model_copy(
            update={
                "cve_id": "CVE-2020-1234",
                "vendor": "Other",
                "product": "Server",
                "title": "Server issue",
                "ransomware": "Unknown",
            }
        ),
        now,
        baseline=True,
    )
    page = api.get("/api/vulnerabilities", params={"page_size": 1}).json()
    assert page["total"] == 2
    assert len(page["items"]) == 1
    assert api.get("/api/vulnerabilities", params={"q": "log4"}).json()["total"] == 1
    assert api.get("/api/vulnerabilities", params={"q": ".*"}).json()["total"] == 0
    assert api.get("/api/vulnerabilities/CVE-2021-44228").json()["product"] == "Log4j"
    assert api.get("/api/vulnerabilities/CVE-2000-9999").status_code == 404
    assert api.get("/api/vulnerabilities", params={"page": 0}).status_code == 422
    stats = api.get("/api/statistics").json()
    assert stats["total"] == 2
    assert stats["vendors_count"] == 2
    assert stats["ransomware_percent"] == 50.0
    assert stats["severity"] == [{"label": "UNASSESSED", "count": 2}]
    assert api.get("/api/statistics", params={"vendor": "Apache"}).json()["total"] == 1
    assert api.get("/api/statistics", params={"ransomware": "Known"}).json()["total"] == 1
    assert api.get("/api/statistics", params={"date_from": "2030-01-01"}).json()["total"] == 0
    assert len(api.get("/api/products").json()) == 2
    assert api.get("/api/health").json()["status"] == "ok"
    assert (
        api.get(
            "/api/vulnerabilities", params={"severity": "UNASSESSED", "date_to": "2026-01-01"}
        ).json()["total"]
        == 2
    )
    assert (
        api.get(
            "/api/vulnerabilities", params={"date_from": "2026-01-01", "date_to": "2025-01-01"}
        ).status_code
        == 422
    )
    csrf = api.get("/api/session").json()["csrf"]
    assert (
        api.post(
            "/api/auth/signup",
            headers={"X-CSRF-Token": csrf, "Origin": "https://example.org"},
            json={"email": "user@example.org", "password": "TestPass123!"},
        ).status_code
        == 403
    )
    assert (
        api.post(
            "/api/auth/signup",
            headers={"X-CSRF-Token": csrf},
            json={"email": "user@example.org", "password": "TestPass123!"},
        ).status_code
        == 503
    )
