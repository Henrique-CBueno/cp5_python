import uuid

import jwt
import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
def test_cognito_signup_confirmation_and_validated_tokens(repository):
    from app.infrastructure.cognito import CognitoIdentity
    from app.settings import Settings
    identity = CognitoIdentity(Settings(), repository)
    identity.provision()
    email = f"test-{uuid.uuid4().hex}@example.org"
    identity.signup(email, "TestPass123!")
    with pytest.raises(ValueError):
        identity.login(email, "TestPass123!")
    identity.confirm(email, "123456")
    token = identity.login(email, "TestPass123!")
    claims = identity.validate(token)
    assert claims["email"] == email
    assert claims["sub"]
    with pytest.raises((jwt.PyJWTError, ValueError)):
        identity.validate(token[:-8] + "invalid")
    with pytest.raises(ValueError):
        identity.login(email, "WrongPass123!")


@pytest.mark.integration
def test_alerts_require_login_and_subscriptions_are_owned(repository, vulnerability):
    from app.main import create_app
    from app.infrastructure.cognito import CognitoIdentity
    from app.settings import Settings
    from datetime import datetime, timezone
    identity = CognitoIdentity(Settings(), repository)
    identity.provision()
    repository.save(vulnerability, datetime.now(timezone.utc), baseline=True)
    with TestClient(create_app(repository, identity)) as alice, TestClient(create_app(repository, identity)) as bob:
        assert alice.get("/api/subscriptions").status_code == 401
        assert alice.post("/api/auth/login", json={"email": "x@example.org", "password": "TestPass123!"}).status_code == 403
        for client in (alice, bob):
            csrf = client.get("/api/session").json()["csrf"]
            client.headers["X-CSRF-Token"] = csrf
            email = f"user-{uuid.uuid4().hex}@example.org"
            assert client.post("/api/auth/signup", json={"email": email, "password": "TestPass123!"}).status_code == 201
            assert client.post("/api/auth/confirm", json={"email": email, "code": "123456"}).status_code == 200
            assert client.post("/api/auth/login", json={"email": email, "password": "TestPass123!"}).status_code == 200
            client.headers["X-CSRF-Token"] = client.get("/api/session").json()["csrf"]
        body = {"name": "Produtos do trabalho", "products": ["apache::log4j"], "email": "alerts@example.org", "changes": True}
        response = alice.post("/api/subscriptions", json=body)
        assert response.status_code == 201
        subscription = response.json()
        assert subscription["email"] == "alerts@example.org"
        assert len(alice.get("/api/subscriptions").json()) == 1
        assert bob.get("/api/subscriptions").json() == []
        assert bob.delete(f"/api/subscriptions/{subscription['id']}").status_code == 404
        assert alice.post("/api/subscriptions", json=body | {"products": ["unknown::product"]}).status_code == 422
        assert alice.get("/api/admin/status").status_code == 403
        assert alice.delete(f"/api/subscriptions/{subscription['id']}").status_code == 204
        assert alice.post("/api/auth/logout").status_code == 204
        assert alice.get("/api/subscriptions").status_code == 401
