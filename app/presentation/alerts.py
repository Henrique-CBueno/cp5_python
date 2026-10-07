from fastapi import APIRouter, Depends, HTTPException

from app.presentation.auth import current_user
from app.presentation.routes import repository

router = APIRouter(prefix="/api", tags=["Alertas"])


@router.get("/alerts")
def alerts(user=Depends(current_user), repo=Depends(repository)):
    return repo.alerts(user["sub"])


@router.post("/subscriptions/{subscription_id}/test", status_code=202)
def test_email(subscription_id: str, user=Depends(current_user), repo=Depends(repository)):
    if not repo.queue_test(user["sub"], subscription_id):
        raise HTTPException(404, "Assinatura ativa não encontrada")
    return {"message": "E-mail de teste aguardando envio pelo worker"}
