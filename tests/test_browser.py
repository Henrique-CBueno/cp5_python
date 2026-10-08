import os
import re
import uuid

import pytest


@pytest.mark.browser
@pytest.mark.parametrize("path", ["/entrar", "/cadastrar"])
def test_account_footer_ends_at_viewport_or_after_long_content(path):
    from playwright.sync_api import expect, sync_playwright

    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        for width, height in ((1440, 1000), (1920, 1080), (1280, 720), (390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            page.goto(base + path)
            expect(page.get_by_label("E-mail da conta")).to_be_enabled()
            dimensions = page.evaluate("""() => {
                const footer = document.querySelector('.footer').getBoundingClientRect();
                const form = document.querySelector('.account-form-panel').getBoundingClientRect();
                return {footerBottom: footer.bottom + scrollY, footerTop: footer.top + scrollY,
                    formBottom: form.bottom + scrollY, documentHeight: document.documentElement.scrollHeight,
                    overflow: document.documentElement.scrollWidth > innerWidth};
            }""")
            assert dimensions["footerBottom"] >= height - 1
            assert abs(dimensions["footerBottom"] - dimensions["documentHeight"]) <= 1
            assert dimensions["footerTop"] >= dimensions["formBottom"]
            assert dimensions["overflow"] is False
        browser.close()


@pytest.mark.browser
def test_browser_investigation_subscription_admin_and_email():
    from playwright.sync_api import expect, sync_playwright

    from app.settings import Settings

    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    settings = Settings()
    assert settings.admin_password, "Configure ADMIN_PASSWORD no .env para testar o fluxo admin"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base)
        page.get_by_role("searchbox", name="Buscar CVE, produto, fornecedor ou título").fill(
            "CVE-2021-44228"
        )
        page.get_by_role("button", name="Aplicar", exact=True).click()
        expect(page.get_by_role("heading", name="CVE-2021-44228", exact=True)).to_be_visible()
        page.get_by_role("link", name="Investigar em detalhes").click()
        expect(
            page.get_by_role("heading", name="Produtos e versões afetados", exact=True)
        ).to_be_visible()
        product_key = context.request.get(base + "/api/vulnerabilities/CVE-2021-44228").json()[
            "product_key"
        ]
        page.get_by_role("link", name="Acompanhar este produto").click()
        page.get_by_role("link", name="Cadastre-se").click()
        email = f"browser-{uuid.uuid4().hex}@example.org"
        subscription_name = f"Apache — navegador {uuid.uuid4().hex[:8]}"
        page.get_by_label("E-mail da conta").fill(email)
        page.get_by_label("Senha", exact=True).fill("BrowserPass123!")
        page.get_by_role("button", name="Criar conta", exact=True).click()
        page.get_by_label("Código de confirmação").fill("123456")
        page.get_by_role("button", name="Confirmar conta", exact=True).click()
        page.get_by_label("E-mail da conta").fill(email)
        page.get_by_label("Senha", exact=True).fill("BrowserPass123!")
        page.get_by_role("button", name="Entrar", exact=True).click()
        expect(page.get_by_role("heading", name="Meus alertas", exact=True)).to_be_visible()
        page.get_by_label("Nome da assinatura").fill(subscription_name)
        page.get_by_label("Enviar alertas para").select_option("other")
        page.get_by_label("E-mail destinatário").fill("browser-alerts@example.org")
        expect(page.get_by_text("1 produto(s) selecionado(s)")).to_be_visible()
        page.get_by_role("button", name="Salvar assinatura").click()
        expect(page.get_by_role("heading", name=subscription_name, exact=True)).to_be_visible()
        subscription_id = context.request.get(base + "/api/subscriptions").json()[0]["id"]
        page.get_by_role("button", name="Testar e-mail").click()
        expect(page.get_by_text("Enviado", exact=True).first).to_be_visible(timeout=30000)
        page.get_by_role("button", name="Sair", exact=True).click()
        expect(page).to_have_url(base + "/")
        if settings.admin_password:
            page.goto(base + "/entrar?next=/admin")
            page.get_by_label("E-mail da conta").fill(settings.admin_email)
            page.get_by_label("Senha", exact=True).fill(settings.admin_password)
            page.get_by_role("button", name="Entrar", exact=True).click()
            expect(
                page.get_by_role("heading", name="Operação da coleta", exact=True)
            ).to_be_visible()
            page.get_by_label("Produto acompanhado", exact=True).select_option(product_key)
            page.get_by_role("button", name="Simular nova vulnerabilidade").click()
            expect(page.get_by_text("Evento sintético criado.", exact=False)).to_be_visible()
        page.goto("http://localhost:8025")
        page.wait_for_function(
            "async name => {const data=await (await fetch('/api/v1/messages')).json();return data.messages.filter(m=>m.Subject.includes(name)).length >= 2;}",
            arg=subscription_name,
            timeout=30000,
        )
        expect(page.get_by_text(subscription_name, exact=False).first).to_be_visible(timeout=30000)
        csrf = context.request.get(base + "/api/session").json()["csrf"]
        context.request.post(base + "/api/auth/logout", headers={"X-CSRF-Token": csrf})
        csrf = context.request.get(base + "/api/session").json()["csrf"]
        login = context.request.post(
            base + "/api/auth/login",
            data={"email": email, "password": "BrowserPass123!"},
            headers={"X-CSRF-Token": csrf},
        ).json()
        assert (
            context.request.delete(
                base + "/api/subscriptions/" + subscription_id,
                headers={"X-CSRF-Token": login["csrf"]},
            ).status
            == 204
        )
        context.request.post(base + "/api/auth/logout", headers={"X-CSRF-Token": login["csrf"]})
        page.goto(base)
        for width in (1440, 900, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            for link in page.locator("nav[aria-label='Navegação principal'] a:visible").all():
                assert link.get_attribute("aria-label") or link.inner_text().strip()
        assert errors == []
        browser.close()


@pytest.mark.browser
def test_login_redirect_stays_on_the_application_origin():
    from playwright.sync_api import expect, sync_playwright

    from app.settings import Settings

    settings = Settings()
    assert settings.admin_password, "Configure ADMIN_PASSWORD no .env"
    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.route("http://example.org/**", lambda route: route.abort())
        page.route("https://example.org/**", lambda route: route.abort())
        page.goto(base + "/entrar?next=%2F%0A%2Fexample.org")
        page.get_by_label("E-mail da conta").fill(settings.admin_email)
        page.get_by_label("Senha", exact=True).fill(settings.admin_password)
        page.get_by_role("button", name="Entrar", exact=True).click()
        expect(page).to_have_url(base + "/alertas")
        browser.close()


@pytest.mark.browser
def test_selection_is_available_in_first_column_and_preserves_investigation():
    from playwright.sync_api import expect, sync_playwright

    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        records = page.request.get(base + "/api/vulnerabilities?q=Citrix&page_size=2").json()[
            "items"
        ]
        for width in (1440, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            page.goto(base + "/?q=Citrix")
            expect(
                page.get_by_role("heading", name=records[0]["cve_id"], exact=True)
            ).to_be_visible()
            page_label = page.locator("#page-label").inner_text()
            selector = (
                page.locator(".results-table tbody tr")
                .nth(1)
                .locator("td")
                .first.get_by_role("button", name="Inspecionar " + records[1]["cve_id"], exact=True)
            )
            expect(selector).to_be_visible()
            box = selector.bounding_box()
            assert box["x"] + box["width"] <= width
            selector.focus()
            selector.press("Enter")
            expect(
                page.get_by_role("heading", name=records[1]["cve_id"], exact=True)
            ).to_be_visible()
            expect(page).to_have_url(base + "/?q=Citrix")
            assert page.locator("#page-label").inner_text() == page_label
            assert (
                page.get_by_role(
                    "searchbox", name="Buscar CVE, produto, fornecedor ou título"
                ).input_value()
                == "Citrix"
            )
        browser.close()


@pytest.mark.browser
def test_mobile_details_offer_navigation_before_long_evidence():
    from playwright.sync_api import expect, sync_playwright

    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 844})
        page.goto(base + "/vulnerabilidades/CVE-2021-44228")
        navigation = page.get_by_role("navigation", name="Seções da vulnerabilidade")
        expect(navigation).to_be_visible()
        assert navigation.bounding_box()["y"] < page.locator("#description").bounding_box()["y"]
        assert navigation.bounding_box()["y"] < 844
        navigation.get_by_role("link", name="Avaliações CVSS").click()
        page.wait_for_function(
            "document.querySelector('#cvss').getBoundingClientRect().top < innerHeight"
        )
        expect(page).to_have_url(base + "/vulnerabilidades/CVE-2021-44228#cvss")
        browser.close()


@pytest.mark.browser
def test_returning_to_account_email_ignores_unused_invalid_destination():
    from playwright.sync_api import expect, sync_playwright

    from app.settings import Settings

    settings = Settings()
    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(base + "/entrar?next=/alertas")
        page.get_by_label("E-mail da conta").fill(settings.admin_email)
        page.get_by_label("Senha", exact=True).fill(settings.admin_password)
        page.get_by_role("button", name="Entrar", exact=True).click()
        expect(page.get_by_role("heading", name="Meus alertas", exact=True)).to_be_visible()
        name = "Alternância de destino " + uuid.uuid4().hex[:8]
        page.get_by_label("Nome da assinatura").fill(name)
        page.get_by_label("Enviar alertas para").select_option("other")
        page.get_by_label("E-mail destinatário").fill("invalid-email")
        page.get_by_label("Enviar alertas para").select_option("account")
        page.get_by_label("Produtos que quero acompanhar").fill("Log4j2")
        page.get_by_role("checkbox", name="Log4j2", exact=False).check()
        page.get_by_role("button", name="Salvar assinatura").click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        csrf = page.request.get(base + "/api/session").json()["csrf"]
        subscriptions = page.request.get(base + "/api/subscriptions").json()
        own = next(s for s in subscriptions if s["name"] == name)
        assert own["email"] == settings.admin_email
        assert (
            page.request.delete(
                base + "/api/subscriptions/" + own["id"], headers={"X-CSRF-Token": csrf}
            ).status
            == 204
        )
        browser.close()


@pytest.mark.browser
def test_expired_private_session_returns_to_login_instead_of_repeating_poll_errors():
    from playwright.sync_api import expect, sync_playwright

    from app.settings import Settings

    settings = Settings()
    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(base + "/entrar?next=/admin")
        page.get_by_label("E-mail da conta").fill(settings.admin_email)
        page.get_by_label("Senha", exact=True).fill(settings.admin_password)
        page.get_by_role("button", name="Entrar", exact=True).click()
        expect(page.get_by_role("heading", name="Operação da coleta", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Atualizar estado", exact=True)).to_be_enabled()
        page.route(
            "**/api/admin/status",
            lambda route: route.fulfill(status=401, json={"detail": "Sessão expirada"}),
        )
        page.get_by_role("button", name="Atualizar estado", exact=True).click()
        expect(page).to_have_url(re.compile(r"/entrar\?next=%2Fadmin$"))
        browser.close()


@pytest.mark.browser
def test_admin_reset_requires_confirmation_and_refreshes_the_view_without_touching_live_data():
    from playwright.sync_api import expect, sync_playwright

    from app.settings import Settings

    settings = Settings()
    base = os.getenv("BROWSER_BASE_URL", "http://localhost:8000")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(base + "/entrar?next=/admin")
        page.get_by_label("E-mail da conta").fill(settings.admin_email)
        page.get_by_label("Senha", exact=True).fill(settings.admin_password)
        page.get_by_role("button", name="Entrar", exact=True).click()
        expect(page.get_by_role("button", name="Atualizar estado", exact=True)).to_be_enabled()
        original_total = page.request.get(base + "/api/statistics").json()["total"]
        status = page.request.get(base + "/api/admin/status").json()
        submitted = []

        def reset_response(route):
            submitted.append(route.request.post_data_json)
            cleared = status | {
                "records": 0,
                "runs": [],
                "deliveries": {},
                "schedule": status["schedule"] | {"baseline_completed": False},
            }
            page.route("**/api/admin/status", lambda r: r.fulfill(json=cleared))
            for endpoint in ("/api/admin/runs", "/api/admin/deliveries", "/api/products"):
                page.route("**" + endpoint, lambda r: r.fulfill(json=[]))
            route.fulfill(json={"vulnerabilities": original_total, "runs": 1, "deliveries": 1})

        page.route("**/api/admin/reset", reset_response)
        confirmation = page.get_by_label("Digite ZERAR para confirmar", exact=True)
        confirmation.fill("APAGA")
        page.get_by_role("button", name="Zerar dados operacionais", exact=True).click()
        assert submitted == []
        confirmation.fill("ZERAR")
        page.get_by_role("button", name="Zerar dados operacionais", exact=True).click()
        expect(page.get_by_text("Dados operacionais zerados.", exact=False)).to_be_visible()
        expect(page.locator("#admin-summary .metric strong").first).to_have_text("0")
        expect(page.locator("#simulate-product option")).to_have_count(1)
        assert submitted == [{"confirmation": "ZERAR"}]
        assert page.request.get(base + "/api/statistics").json()["total"] == original_total
        browser.close()
