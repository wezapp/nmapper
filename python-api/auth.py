import hashlib
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

_KEY_FILE = Path(__file__).parent / "scans" / ".apikey"

SESSION_COOKIE = "nmapper_sid"
SESSION_TTL    = int(os.getenv("SESSION_TTL", str(8 * 3600)))

# Hiérarchie des rôles : viewer < it < admin
ROLE_LEVELS = {"viewer": 0, "it": 1, "admin": 2}

# Sessions en mémoire : {token: {expiry, username, role}}
_sessions: dict[str, dict] = {}


# ── Clé API ──────────────────────────────────────────────────

def _resolve_key() -> str:
    env_key = os.getenv("API_KEY", "").strip()
    if env_key:
        logger.info("Clé API chargée depuis la variable d'environnement")
        return env_key
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_text().strip()
        if key:
            return key
    key = secrets.token_urlsafe(32)
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key)
    _KEY_FILE.chmod(0o600)
    key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
    logger.warning(
        "═══════════════════════════════════════════════════════\n"
        f"  Clé API générée (SHA256 tronqué : {key_hash}...)\n"
        "  Récupérez-la : docker exec nmapper-api cat /scans/.apikey\n"
        "  Ou ajoutez API_KEY=<valeur> dans .env avant de redéployer\n"
        "═══════════════════════════════════════════════════════"
    )
    return key


API_KEY: str = _resolve_key()
_api_key_log_hash = hashlib.sha256(API_KEY.encode()).hexdigest()[:16]


# ── Gestion des sessions ─────────────────────────────────────

def create_session(username: str = "", role: str = "admin") -> str:
    """Crée un token de session aléatoire et l'enregistre avec le rôle utilisateur."""
    _cleanup_sessions()
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "expiry":   time.time() + SESSION_TTL,
        "username": username,
        "role":     role,
    }
    return token


def get_session_info(token: str) -> Optional[dict]:
    """Retourne {expiry, username, role} ou None si invalide/expirée."""
    info = _sessions.get(token)
    if not info:
        return None
    if time.time() > info["expiry"]:
        del _sessions[token]
        return None
    return info


def _verify_session(token: str) -> bool:
    return get_session_info(token) is not None


def _cleanup_sessions() -> None:
    now = time.time()
    expired = [t for t, info in list(_sessions.items()) if now > info["expiry"]]
    for t in expired:
        _sessions.pop(t, None)


# ── Dépendances FastAPI ───────────────────────────────────────

def check_session(token: str) -> bool:
    return get_session_info(token) is not None


async def verify_auth(request: Request) -> str:
    """Route protégée — cookie de session HttpOnly uniquement."""
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token and _verify_session(session_token):
        return "session"
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expirée ou absente — connectez-vous via /auth",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(min_role: str = "viewer"):
    """
    Factory de dépendance FastAPI qui exige un rôle minimum.

    Exemple :
        @app.delete("/admin/users/{u}")
        async def del_user(_: dict = Depends(require_role("admin"))):
    """
    async def _check(request: Request) -> dict:
        token = request.cookies.get(SESSION_COOKIE)
        info = get_session_info(token) if token else None
        if not info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expirée ou absente",
            )
        user_level = ROLE_LEVELS.get(info.get("role", "viewer"), 0)
        req_level  = ROLE_LEVELS.get(min_role, 0)
        if user_level < req_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Droits insuffisants — rôle requis : {min_role}",
            )
        return info
    return _check


# Alias conservé pour les imports existants
verify_api_key = verify_auth
