from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.application.query import filters

router = APIRouter(prefix="/api")


def repository(request: Request):
    return request.app.state.repository


def selection(
    q: str = Query("", max_length=200), vendor: str = Query("", max_length=200),
    product_key: str = Query("", max_length=400),
    ransomware: Literal["", "Known", "Unknown"] = "",
    severity: Literal["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNASSESSED"] = "",
    date_from: date | None = None, date_to: date | None = None,
):
    if date_from and date_to and date_from > date_to:
        raise HTTPException(422, "Período inválido")
    return filters(q, vendor, product_key, ransomware, severity, date_from, date_to)


@router.get("/vulnerabilities", tags=["Catálogo"])
def list_records(repo=Depends(repository), selected=Depends(selection), page: Annotated[int, Query(ge=1)] = 1, page_size: Annotated[int, Query(ge=1, le=100)] = 20):
    return repo.list_records(selected, page, page_size)


@router.get("/vulnerabilities/{cve_id}", tags=["Catálogo"])
def detail(cve_id: str, repo=Depends(repository)):
    record = repo.get(cve_id)
    if not record or record["simulated"]:
        raise HTTPException(404, "Vulnerabilidade não encontrada")
    return record


@router.get("/statistics", tags=["Panorama"])
def statistics(repo=Depends(repository), selected=Depends(selection)):
    return repo.statistics(selected)


@router.get("/products", tags=["Catálogo"])
def products(repo=Depends(repository)):
    return repo.products()


@router.get("/health", tags=["Sistema"])
def health(repo=Depends(repository)):
    repo.db.command("ping")
    return {"status": "ok"}
