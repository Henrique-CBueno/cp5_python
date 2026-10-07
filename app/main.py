from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.presentation.routes import router
from app.settings import Settings, connect


def create_app(repository=None, identity=None):
    settings = Settings()

    @asynccontextmanager
    async def lifespan(app):
        app.state.repository = repository or connect(settings)
        app.state.repository.initialize()
        app.state.settings = settings
        app.state.identity = identity
        yield
        if repository is None:
            app.state.repository.db.client.close()

    app = FastAPI(title="Vigília", version="0.1.0", lifespan=lifespan, description="Catálogo CISA KEV enriquecido pela NVD e alertas por produto.")
    app.include_router(router)
    return app


app = create_app()
