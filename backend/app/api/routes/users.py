"""Gestion des utilisateurs (admin uniquement).

Endpoints CRUD pour l'administration des comptes utilisateurs.
Toutes les routes nécessitent le rôle `admin`.

  GET    /api/users/        liste tous les utilisateurs
  POST   /api/users/        crée un nouvel utilisateur (choix du rôle)
  PATCH  /api/users/{id}    modifie un utilisateur (rôle, statut actif, mot de passe)
  DELETE /api/users/{id}    supprime un utilisateur

Le mot de passe est haché en bcrypt avant stockage.
L'admin ne peut pas se supprimer / se désactiver lui-même
(pour éviter le verrouillage total de l'application).
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_admin
from app.core.database import get_db
from app.core.security import hash_password
from app.models.scan import AuditLog
from app.models.user import User

router = APIRouter()


# ── Schémas Pydantic ──────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=4, max_length=128)
    role: str = Field(..., pattern="^(admin|analyst|reader)$")


class UserUpdate(BaseModel):
    role: Optional[str] = Field(None, pattern="^(admin|analyst|reader)$")
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=4, max_length=128)


# ── Endpoints ─────────────────────────────────────────────────

@router.get("/", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Liste tous les utilisateurs (admin uniquement)."""
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Crée un utilisateur avec le rôle choisi (admin/analyst/reader)."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Nom d'utilisateur déjà pris")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email déjà utilisé")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_pwd=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(
        user_id=admin.id,
        action="user_create",
        ip_address=request.client.host,
        detail=f"created user '{user.username}' with role '{user.role}'",
    ))
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Modifie un utilisateur (rôle, statut, mot de passe)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # Garde-fous : empêcher l'admin de se rétrograder ou se désactiver lui-même
    if user.id == admin.id:
        if payload.role is not None and payload.role != "admin":
            raise HTTPException(status_code=400, detail="Impossible de changer son propre rôle")
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="Impossible de désactiver son propre compte")

    changes = {}
    if payload.role is not None and payload.role != user.role:
        user.role = payload.role
        changes["role"] = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        changes["is_active"] = payload.is_active
    if payload.password:
        user.hashed_pwd = hash_password(payload.password)
        changes["password"] = "reset"

    if changes:
        change_str = ", ".join(f"{k}={v}" for k, v in changes.items())
        db.add(AuditLog(
            user_id=admin.id,
            action="user_update",
            ip_address=request.client.host,
            detail=f"updated user '{user.username}': {change_str}",
        ))
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Supprime un utilisateur (sauf soi-même)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Impossible de se supprimer soi-même")

    deleted_name = user.username
    db.delete(user)
    db.add(AuditLog(
        user_id=admin.id,
        action="user_delete",
        ip_address=request.client.host,
        detail=f"deleted user '{deleted_name}'",
    ))
    db.commit()
    return None
