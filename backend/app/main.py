"""Entry point du service API pur.

Ce service expose uniquement les endpoints /api/* et /health.
Les pages HTML et le formulaire de login sont servis par le service web
(voir app/web_main.py).

Lancement :
    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import auth, dashboard, defensive, modules, reports, users
from app.core.config import settings
from app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ToolboxV8 API",
    description="Plateforme automatisée de tests d'intrusion – Mastère Cybersécurité",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

app.include_router(auth.router,      prefix="/api/auth",      tags=["Authentification"])
app.include_router(users.router,     prefix="/api/users",     tags=["Gestion utilisateurs"])
app.include_router(modules.router,   prefix="/api/modules",   tags=["Modules Pentest"])
app.include_router(reports.router,   prefix="/api/reports",   tags=["Rapports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(defensive.router, prefix="/api/defensive", tags=["SIEM Défensif"])


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "api", "version": "1.0.0"}
