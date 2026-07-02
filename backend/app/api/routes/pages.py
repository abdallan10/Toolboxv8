from typing import Optional

import httpx
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.auth import ACCESS_TOKEN_COOKIE
from app.core.config import settings
from app.core.security import decode_access_token

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

COOKIE_MAX_AGE = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def _auth_payload(request: Request) -> Optional[dict]:
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        return None
    return decode_access_token(token)


def _is_authenticated(request: Request) -> bool:
    return _auth_payload(request) is not None


def _guard(request: Request):
    payload = _auth_payload(request)
    if payload is None:
        return RedirectResponse(url="/login", status_code=302)
    return {"username": payload.get("sub"), "role": payload.get("role")}


@router.get("/", include_in_schema=False)
def root(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    url = f"{settings.INTERNAL_API_URL.rstrip('/')}/api/auth/token"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                data={"username": username, "password": password},
            )
    except httpx.RequestError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "API injoignable", "username": username},
            status_code=502,
        )

    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", "Identifiants incorrects")
        except Exception:
            detail = "Identifiants incorrects"
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": detail, "username": username},
            status_code=resp.status_code,
        )

    token = resp.json()["access_token"]
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


@router.post("/logout", include_in_schema=False)
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/")
    return response


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    guard = _guard(request)
    if isinstance(guard, RedirectResponse):
        return guard
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": guard})


@router.get("/modules", response_class=HTMLResponse, include_in_schema=False)
def modules_page(request: Request):
    guard = _guard(request)
    if isinstance(guard, RedirectResponse):
        return guard
    # Reader : accès refusé à Modules (lecture seule = pas de lancement de scans)
    if guard.get("role") == "reader":
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("modules.html", {"request": request, "user": guard})


@router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
def reports_page(request: Request):
    guard = _guard(request)
    if isinstance(guard, RedirectResponse):
        return guard
    return templates.TemplateResponse("reports.html", {"request": request, "user": guard})


@router.get("/siem", response_class=HTMLResponse, include_in_schema=False)
def siem_page(request: Request):
    guard = _guard(request)
    if isinstance(guard, RedirectResponse):
        return guard
    # SIEM : admin uniquement (analyst et reader redirigés vers /dashboard)
    if guard.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("siem.html", {"request": request, "user": guard})


@router.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
def admin_users_page(request: Request):
    """Page de gestion des utilisateurs (admin uniquement).

    L'accès est garde par la route, mais la verification stricte du role
    se fait cote API : si un non-admin tente d'utiliser les endpoints
    /api/users/, ils renverront 403.
    """
    guard = _guard(request)
    if isinstance(guard, RedirectResponse):
        return guard
    if guard.get("role") != "admin":
        # Non-admin : redirige vers le dashboard
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": guard})
