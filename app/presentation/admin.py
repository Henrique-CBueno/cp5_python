from fastapi import APIRouter, Depends

from app.presentation.auth import admin
from app.presentation.routes import repository

router = APIRouter(prefix="/api/admin", tags=["Administração"], dependencies=[Depends(admin)])


@router.get("/status")
def status(repo=Depends(repository)):
    return {"status": "ok", "records": repo.list_records({}, page_size=1)["total"]}
