import httpx
from fastapi import APIRouter, Request, Response

from app.core.auth import ACCESS_TOKEN_COOKIE
from app.core.config import settings

router = APIRouter()

_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# En-têtes qu'on ne doit pas retransmettre telles quelles
_HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailers",
    "cookie",  # le cookie du front n'a pas à atteindre l'API
}

_RESP_STRIP = {"content-encoding", "transfer-encoding", "connection"}


@router.api_route("/{path:path}", methods=_PROXY_METHODS, include_in_schema=False)
async def proxy(path: str, request: Request):
    # Extraction du token depuis le cookie HttpOnly du site web
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)

    # Recopie des en-têtes sauf hop-by-hop + cookie
    fwd_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP
    }
    if token:
        fwd_headers["Authorization"] = f"Bearer {token}"

    # IP client réel à transmettre à l'API pour les logs d'audit
    client_host = request.client.host if request.client else ""
    if client_host:
        fwd_headers["X-Forwarded-For"] = client_host

    body = await request.body()
    url = f"{settings.INTERNAL_API_URL.rstrip('/')}/api/{path}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream = await client.request(
                request.method,
                url,
                params=request.query_params,
                headers=fwd_headers,
                content=body,
            )
    except httpx.RequestError as exc:
        return Response(
            content=f'{{"detail":"API injoignable: {exc.__class__.__name__}"}}',
            status_code=502,
            media_type="application/json",
        )

    out_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _RESP_STRIP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=out_headers,
    )
