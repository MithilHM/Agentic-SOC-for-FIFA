"""
api/auth.py — lightweight auth gate for the sensitive API surface.

Protects /api/export, /api/incidents/{id}/ask, and the incidents WebSocket.

Mechanism (today): a shared static API key.
  - HTTP: send it as the ``X-API-Key`` header (or ``Authorization: Bearer <key>``).
  - WebSocket: browsers cannot set custom headers on a WS handshake, so the key
    is also accepted as a ``?token=<key>`` query parameter.

Designed to be JWT-ready: replace the body of ``_verify_token()`` with signature
/ claim validation and every protected endpoint keeps working unchanged, because
they all depend on ``require_auth`` / ``authorize_ws`` — never on the raw key.

If ``API_KEY`` is unset, auth is DISABLED (open) so local/demo runs keep working,
but a warning is logged at import so the open state is never silent.
"""
from __future__ import annotations

import hmac
import logging
import os

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import APIKeyHeader
from starlette.websockets import WebSocket

logger = logging.getLogger(__name__)

_HEADER_NAME = "X-API-Key"

# auto_error=False: we raise our own 401 with a helpful message and also accept
# an Authorization: Bearer token, so we don't let APIKeyHeader short-circuit.
_api_key_header = APIKeyHeader(name=_HEADER_NAME, auto_error=False)


def _current_key() -> str:
    # Read at call time (not import) so config is dynamic and testable.
    return os.getenv("API_KEY", "").strip()


if not _current_key():
    logger.warning("API_KEY is not set — API auth is DISABLED (open). "
                   "Set API_KEY in the environment to require authentication.")
else:
    logger.info("API auth enabled (static API key).")


def auth_enabled() -> bool:
    return bool(_current_key())


def _verify_token(token: str | None) -> dict | None:
    """Return a principal dict if the token is valid, else None.

    JWT swap-in point: replace the constant-time key comparison with
    ``jwt.decode(token, JWT_SECRET, algorithms=[...])`` and return the claims.
    """
    key = _current_key()
    if not token or not key:
        return None
    if hmac.compare_digest(token, key):   # constant-time; avoids timing leak
        return {"principal": "api-key"}
    return None


def _extract_http_token(api_key: str | None, authorization: str | None) -> str | None:
    if api_key:
        return api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


async def require_auth(
    api_key: str | None = Depends(_api_key_header),
    authorization: str | None = Header(default=None),
) -> dict | None:
    """FastAPI dependency guarding protected HTTP endpoints."""
    if not auth_enabled():
        return None
    principal = _verify_token(_extract_http_token(api_key, authorization))
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing or invalid credentials (send {_HEADER_NAME} header or Bearer token).",
            headers={"WWW-Authenticate": _HEADER_NAME},
        )
    return principal


async def authorize_ws(websocket: WebSocket) -> bool:
    """Authorize a WebSocket handshake via ?token= (or X-API-Key header).

    Returns True if allowed; otherwise closes the handshake and returns False.
    """
    if not auth_enabled():
        return True
    token = websocket.query_params.get("token") or websocket.headers.get(_HEADER_NAME)
    if _verify_token(token) is not None:
        return True
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    return False
