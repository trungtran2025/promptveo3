import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session
from .database import get_db
from .models import User, RefreshToken
from .schemas import RegisterRequest, LoginRequest, UserResponse, AccessTokenResponse
from .security import (
    JWT_SECRET, JWT_ALGORITHM, ACCESS_TOKEN_MINUTES,
    hash_password, verify_password, create_access_token,
    create_refresh_token, hash_refresh_token
)

router = APIRouter(prefix="/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)
COOKIE_NAME = "refresh_token"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "")

def ensure_origin(request: Request):
    origin = request.headers.get("origin")
    if FRONTEND_ORIGIN and origin and origin.rstrip("/") != FRONTEND_ORIGIN.rstrip("/"):
        raise HTTPException(status_code=403, detail="Origin not allowed")

def user_response(user: User) -> UserResponse:
    return UserResponse(id=user.id, email=user.email, is_active=user.is_active)

def issue_refresh_cookie(response: Response, raw: str):
    response.set_cookie(
        COOKIE_NAME, raw, httponly=True, secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE, path="/auth", max_age=60*60*24*30
    )

def create_session(user: User, db: Session, response: Response):
    raw, digest, expires = create_refresh_token()
    db.add(RefreshToken(user_id=user.id, token_hash=digest, expires_at=expires))
    db.commit()
    issue_refresh_cookie(response, raw)
    return AccessTokenResponse(
        access_token=create_access_token(user.id),
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        user=user_response(user)
    )

@router.post("/register", response_model=AccessTokenResponse, status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ensure_origin(request)
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=email, password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    return create_session(user, db, response)

@router.post("/login", response_model=AccessTokenResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ensure_origin(request)
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    return create_session(user, db, response)

@router.post("/refresh", response_model=AccessTokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    ensure_origin(request)
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    token_hash = hash_refresh_token(raw)
    record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    now = datetime.now(timezone.utc)
    if not record or record.revoked_at or record.expires_at.replace(tzinfo=timezone.utc) <= now:
        response.delete_cookie(COOKIE_NAME, path="/auth", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")
    user = db.get(User, record.user_id)
    if not user or not user.is_active:
        record.revoked_at = now
        db.commit()
        response.delete_cookie(COOKIE_NAME, path="/auth", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
        raise HTTPException(status_code=401, detail="User unavailable")
    # Rotate refresh token: revoke the old token and issue a new one.
    record.revoked_at = now
    raw_new, digest, expires = create_refresh_token()
    db.add(RefreshToken(user_id=user.id, token_hash=digest, expires_at=expires))
    db.commit()
    issue_refresh_cookie(response, raw_new)
    return AccessTokenResponse(access_token=create_access_token(user.id), expires_in=ACCESS_TOKEN_MINUTES*60, user=user_response(user))

@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    ensure_origin(request)
    raw = request.cookies.get(COOKIE_NAME)
    if raw:
        record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw)))
        if record and not record.revoked_at:
            record.revoked_at = datetime.now(timezone.utc)
            db.commit()
    response.delete_cookie(COOKIE_NAME, path="/auth", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)

@router.get("/me", response_model=UserResponse)
def me(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Access token required")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid access token")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User unavailable")
    return user_response(user)
