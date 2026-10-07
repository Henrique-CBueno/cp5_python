import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
def test_public_pages_render_and_private_pages_require_identity(repository):
    from app.main import create_app

    with TestClient(create_app(repository)) as api:
        for path in ("/", "/panorama", "/vulnerabilidades/CVE-2021-44228", "/entrar", "/cadastrar"):
            response = api.get(path)
            assert response.status_code == 200
            assert "Vigília" in response.text
            assert 'lang="pt-BR"' in response.text
        assert api.get("/alertas", follow_redirects=False).status_code == 303
        assert api.get("/admin", follow_redirects=False).status_code == 303
        assert api.get("/static/styles.css").status_code == 200
