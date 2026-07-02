from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User

ACCESS_TOKEN_COOKIE = "access_token"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


def _resolve_user(raw_token: Optional[str], db: Session) -> Optional[User]:
    if not raw_token:
        return None
    payload = decode_access_token(raw_token)
    if payload is None:
        return None
    username = payload.get("sub")
    if not username:
        return None
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        return None
    return user


def _extract_token(request: Request, header_token: Optional[str]) -> Optional[str]:
    if header_token:
        return header_token
    return request.cookies.get(ACCESS_TOKEN_COOKIE)


def current_user_from_request(request: Request, db: Session) -> Optional[User]:
    """Plain helper (no FastAPI DI) for use inside route bodies."""
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    return _resolve_user(token, db)


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les identifiants",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user = _resolve_user(_extract_token(request, token), db)
    if user is None:
        raise credentials_exception
    return user


def get_optional_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    return _resolve_user(_extract_token(request, token), db)


def require_role(*roles: str):
    def checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rôle requis : {', '.join(roles)}",
            )
        return current_user
    return checker


require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")
