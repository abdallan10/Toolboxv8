"""Entry point du service web (Jinja + proxy /api/*).

Ce service :
- sert les pages HTML (login, dashboard, modules, reports, siem) ;
- gère le login via un formulaire POST /login qui appelle l'API en interne
  et pose un cookie HttpOnly contenant le JWT ;
- proxifie toutes les requêtes /api/* vers l'API, en injectant le Bearer
  token lu depuis le cookie.

Lancement :
    uvicorn app.web_main:app --host 0.0.0.0 --port 3000
"""
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import pages
from app.core.config import settings
from app.web import proxy

app = FastAPI(
    title="ToolboxV8 Web",
    description="Interface web (pages HTML + proxy API)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Pages HTML + auth via formulaire
app.include_router(pages.router)

# Proxy de toutes les requêtes /api/* vers l'API interne
app.include_router(proxy.router, prefix="/api")


@app.get("/health", include_in_schema=False)
def health_check():
    return {"status": "ok", "service": "web"}
