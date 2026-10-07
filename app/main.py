from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib
import secrets

from app.presentation.routes import router
from app.presentation.auth import router as auth_router
from app.presentation.admin import router as admin_router
from app.presentation.alerts import router as alerts_router
from app.infrastructure.cognito import CognitoIdentity
from app.settings import Settings, connect


def create_app(repository=None, identity=None):
    settings = Settings()

    @asynccontextmanager
    async def lifespan(app):
        app.state.repository = repository or connect(settings)
        app.state.repository.initialize()
        app.state.settings = settings
        app.state.identity = identity or CognitoIdentity(settings, app.state.repository)
        yield
        if repository is None:
            app.state.repository.db.client.close()

    app = FastAPI(title="Vigília", version="0.1.0", lifespan=lifespan, description="Catálogo CISA KEV enriquecido pela NVD e alertas por produto.")
    app.include_router(router)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(alerts_router)

    @app.middleware("http")
    async def csrf_protection(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            cookie = request.cookies.get("vigilia_csrf", "")
            header = request.headers.get("X-CSRF-Token", "")
            valid = bool(cookie and header and secrets.compare_digest(cookie, header))
            origin = request.headers.get("origin")
            if origin and origin != settings.public_url:
                valid = False
            sid = request.cookies.get("vigilia_session")
            if sid:
                session = app.state.repository.session(hashlib.sha256(sid.encode()).hexdigest())
                if not session or not secrets.compare_digest(session["csrf"], header):
                    valid = False
            if not valid:
                return JSONResponse({"detail": "Token CSRF inválido; atualize a página"}, status_code=403)
        return await call_next(request)

    return app


app = create_app()
