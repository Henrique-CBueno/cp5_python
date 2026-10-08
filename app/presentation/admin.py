from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.application.simulate import Simulate
from app.presentation.auth import admin
from app.presentation.routes import repository

router = APIRouter(prefix="/api/admin", tags=["Administração"], dependencies=[Depends(admin)])


@router.get("/status")
def status(repo=Depends(repository)):
    return {
        "status": "ok",
        "records": repo.list_records({}, page_size=1)["total"],
        "schedule": repo.schedule(),
        "runs": repo.runs()[:5],
        "deliveries": repo.delivery_counts(),
    }


class Schedule(BaseModel):
    enabled: bool
    interval_hours: int = Field(ge=1, le=168)
    max_pages: int = Field(ge=0, le=1000)


class RunRequest(BaseModel):
    max_pages: int | None = Field(default=None, ge=0, le=1000)


class Simulation(BaseModel):
    product_key: str = Field(min_length=1, max_length=400)


class ResetRequest(BaseModel):
    confirmation: Literal["ZERAR"]


@router.post("/reset")
def reset(body: ResetRequest, repo=Depends(repository)):
    try:
        return repo.reset_operational_data(datetime.now(UTC))
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.put("/schedule")
def schedule(body: Schedule, repo=Depends(repository)):
    return repo.configure_schedule(body.model_dump(), datetime.now(UTC))


@router.get("/runs")
def runs(repo=Depends(repository)):
    return repo.runs()


@router.post("/runs", status_code=202)
def run(body: RunRequest, user=Depends(admin), repo=Depends(repository)):
    try:
        return repo.enqueue_run(user["sub"], body.max_pages)
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.get("/deliveries")
def deliveries(repo=Depends(repository)):
    return repo.alerts()


@router.post("/deliveries/{delivery_id}/retry", status_code=202)
def retry(delivery_id: str, repo=Depends(repository)):
    if not repo.retry_delivery(delivery_id):
        raise HTTPException(404, "Entrega com falha não encontrada")
    return {"message": "Entrega agendada para nova tentativa"}


@router.post("/simulate", status_code=201)
def simulate(body: Simulation, repo=Depends(repository)):
    try:
        return Simulate(repo).run(body.product_key)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
