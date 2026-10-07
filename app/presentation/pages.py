from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.presentation.auth import current_user, identity

ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=ROOT / "templates")
router = APIRouter(include_in_schema=False)


def render(request, template, view, title, **context):
    return templates.TemplateResponse(
        request=request, name=template, context={"view": view, "title": title, **context}
    )


@router.get("/")
def workbench(request: Request):
    return render(request, "workbench.html", "workbench", "Investigar vulnerabilidades")


@router.get("/panorama")
def panorama(request: Request):
    return render(request, "panorama.html", "panorama", "Panorama da base")


@router.get("/vulnerabilidades/{cve_id}")
def detail(request: Request, cve_id: str):
    return render(request, "detail.html", "detail", "Evidências da vulnerabilidade", cve_id=cve_id)


@router.get("/entrar")
def login(request: Request):
    return render(request, "account.html", "login", "Entre no Vigília", mode="login")


@router.get("/cadastrar")
def signup(request: Request):
    return render(request, "account.html", "signup", "Crie sua conta", mode="signup")


def private_page(request, template, view, title, require_admin=False):
    try:
        user = current_user(request, request.app.state.repository, identity(request))
    except HTTPException:
        return RedirectResponse("/entrar?next=" + request.url.path, status_code=303)
    if require_admin and not user["admin"]:
        raise HTTPException(403, "Acesso exclusivo de administrador")
    return render(request, template, view, title)


@router.get("/alertas")
def alerts(request: Request):
    return private_page(request, "alerts.html", "alerts", "Meus alertas")


@router.get("/admin")
def admin(request: Request):
    return private_page(request, "admin.html", "admin", "Operação da coleta", require_admin=True)
