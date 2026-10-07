import hashlib
import secrets
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field

from app.application.subscribe import Subscribe
from app.domain.subscription import Subscription
from app.presentation.routes import repository

router = APIRouter(prefix="/api", tags=["Conta e assinaturas"])


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class Confirmation(BaseModel):
    email: EmailStr
    code: str = Field(min_length=1, max_length=20)


def identity(request: Request):
    adapter = request.app.state.identity
    if adapter and not adapter.config:
        adapter.config = request.app.state.repository.identity_config()
    if not adapter or not adapter.config:
        raise HTTPException(503, "Identidade não provisionada; execute o bootstrap")
    return adapter


def current_user(request: Request, repo=Depends(repository), adapter=Depends(identity)):
    session_id = request.cookies.get("vigilia_session", "")
    session = repo.session(hashlib.sha256(session_id.encode()).hexdigest())
    if not session:
        raise HTTPException(401, "Entre para gerenciar seus alertas")
    try:
        claims = adapter.validate(session["token"])
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(401, "Sessão expirada; entre novamente")
    return {"sub": claims["sub"], "email": claims["email"], "admin": "admin" in claims.get("cognito:groups", [])}


def admin(user=Depends(current_user)):
    if not user["admin"]:
        raise HTTPException(403, "Acesso exclusivo de administrador")
    return user


@router.get("/session")
def session(request: Request, response: Response, repo=Depends(repository)):
    csrf = request.cookies.get("vigilia_csrf") or secrets.token_urlsafe(32)
    response.set_cookie("vigilia_csrf", csrf, samesite="strict", secure=request.app.state.settings.cookie_secure)
    user = None
    if request.cookies.get("vigilia_session"):
        try:
            user = current_user(request, repo, identity(request))
        except HTTPException:
            response.delete_cookie("vigilia_session")
    return {"user": user, "csrf": csrf}


@router.post("/auth/signup", status_code=201)
def signup(body: Credentials, adapter=Depends(identity)):
    try:
        adapter.signup(str(body.email), body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"message": "Conta criada. Confirmação local simulada: use o código 123456."}


@router.post("/auth/confirm")
def confirm(body: Confirmation, adapter=Depends(identity)):
    try:
        adapter.confirm(str(body.email), body.code)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"message": "Conta confirmada"}


@router.post("/auth/login")
def login(body: Credentials, request: Request, response: Response, repo=Depends(repository), adapter=Depends(identity)):
    try:
        token = adapter.login(str(body.email), body.password)
        claims = adapter.validate(token)
    except (ValueError, jwt.PyJWTError) as exc:
        raise HTTPException(401, str(exc))
    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    repo.save_session(hashlib.sha256(session_id.encode()).hexdigest(), token, datetime.fromtimestamp(claims["exp"], timezone.utc), csrf)
    secure = request.app.state.settings.cookie_secure
    response.set_cookie("vigilia_session", session_id, httponly=True, samesite="strict", secure=secure, max_age=3600)
    response.set_cookie("vigilia_csrf", csrf, samesite="strict", secure=secure, max_age=3600)
    return {"message": "Sessão iniciada", "csrf": csrf}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, repo=Depends(repository)):
    repo.delete_session(hashlib.sha256(request.cookies.get("vigilia_session", "").encode()).hexdigest())
    response.delete_cookie("vigilia_session")
    response.delete_cookie("vigilia_csrf")


@router.get("/subscriptions")
def subscriptions(user=Depends(current_user), repo=Depends(repository)):
    return repo.subscriptions(user["sub"])


@router.post("/subscriptions", status_code=201)
def subscribe(body: Subscription, user=Depends(current_user), repo=Depends(repository)):
    try:
        return Subscribe(repo).save(user["sub"], user["email"], body)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.put("/subscriptions/{subscription_id}")
def update_subscription(subscription_id: str, body: Subscription, user=Depends(current_user), repo=Depends(repository)):
    try:
        result = Subscribe(repo).save(user["sub"], user["email"], body, subscription_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not result:
        raise HTTPException(404, "Assinatura não encontrada")
    return result


@router.delete("/subscriptions/{subscription_id}", status_code=204)
def delete_subscription(subscription_id: str, user=Depends(current_user), repo=Depends(repository)):
    if not repo.delete_subscription(user["sub"], subscription_id):
        raise HTTPException(404, "Assinatura não encontrada")
