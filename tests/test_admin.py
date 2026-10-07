import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
def test_admin_can_schedule_run_and_demonstrate_alert_without_polluting_catalog(repository, vulnerability):
    from app.infrastructure.cognito import CognitoIdentity
    from app.main import create_app
    from app.settings import Settings
    identity = CognitoIdentity(Settings(), repository)
    identity.provision()
    email = f"admin-{uuid.uuid4().hex}@example.org"
    identity.bootstrap_admin(email, "AdminPass123!")
    identity.bootstrap_admin(email, "AdminPass123!")
    repository.save(vulnerability, datetime.now(timezone.utc), baseline=True)
    with TestClient(create_app(repository, identity)) as api:
        api.headers["X-CSRF-Token"] = api.get("/api/session").json()["csrf"]
        assert api.post("/api/auth/login", json={"email": email, "password": "AdminPass123!"}).status_code == 200
        api.headers["X-CSRF-Token"] = api.get("/api/session").json()["csrf"]
        assert api.get("/api/session").json()["user"]["admin"]
        assert api.get("/api/admin/status").status_code == 200
        assert api.put("/api/admin/schedule", json={"enabled": False, "interval_hours": 6, "max_pages": 1}).status_code == 200
        assert api.post("/api/admin/runs", json={"max_pages": 1}).status_code == 202
        assert api.get("/api/admin/runs").json()[0]["status"] == "queued"
        sub = api.post("/api/subscriptions", json={"name": "Apache", "products": ["apache::log4j"]}).json()
        assert sub["email"] == email
        updated = api.put(f"/api/subscriptions/{sub['id']}", json={"name": "Apache", "products": ["apache::log4j"], "changes": True}).json()
        assert updated["changes"] is True
        response = api.post("/api/admin/simulate", json={"product_key": "apache::log4j"})
        assert response.status_code == 201
        assert api.get("/api/statistics").json()["total"] == 1
        assert len(api.get("/api/alerts").json()) == 1
        assert api.get("/api/vulnerabilities/" + response.json()["cve_id"]).status_code == 404
        assert api.post(f"/api/subscriptions/{sub['id']}/test").status_code == 202
        assert len(api.get("/api/admin/deliveries").json()) == 2
