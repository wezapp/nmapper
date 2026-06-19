import base64
import io
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Optional

import bcrypt as _bcrypt_lib
import pyotp
import qrcode

logger = logging.getLogger(__name__)

_USERS_FILE = Path(__file__).parent / "scans" / "users.json"

_pending_mfa: dict[str, dict] = {}
PENDING_TTL = 300


def _pwd_bytes(password: str) -> bytes:
    b = password.encode("utf-8")
    return b[:72] if len(b) > 72 else b


def _hash_password(password: str) -> str:
    return _bcrypt_lib.hashpw(_pwd_bytes(password), _bcrypt_lib.gensalt(rounds=12)).decode("utf-8")


def _verify_password_hash(password: str, hashed: str) -> bool:
    return _bcrypt_lib.checkpw(_pwd_bytes(password), hashed.encode("utf-8"))


def setup_done() -> bool:
    if not _USERS_FILE.exists():
        return False
    try:
        return bool(_load_users())
    except Exception:
        return False


def _load_users() -> dict:
    if not _USERS_FILE.exists():
        return {}
    with open(_USERS_FILE) as f:
        return json.load(f)


def _save_users(users: dict) -> None:
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    _USERS_FILE.chmod(0o600)


# ── Création du premier compte admin ─────────────────────────

def create_user(username: str, password: str) -> str:
    """Crée le compte admin initial (un seul appel possible)."""
    users = _load_users()
    if users:
        raise ValueError("Un compte administrateur existe déjà")
    if len(username) < 3:
        raise ValueError("Nom d'utilisateur trop court (min 3 caractères)")
    if len(password) < 8:
        raise ValueError("Mot de passe trop court (min 8 caractères)")

    hashed = _hash_password(password)
    totp_secret = pyotp.random_base32()
    users[username] = {
        "password_hash": hashed,
        "totp_secret":   totp_secret,
        "created_at":    time.time(),
        "mfa_verified":  False,
        "role":          "admin",
    }
    _save_users(users)
    logger.info(f"Compte admin créé pour : {username}")
    return totp_secret


# ── Gestion multi-utilisateurs ────────────────────────────────

def add_managed_user(username: str, password: str, role: str) -> str:
    """
    Crée un utilisateur supplémentaire (IT ou Viewer).
    Réservé à l'admin. Retourne le totp_secret pour QR code.
    """
    valid_roles = {"admin", "it", "viewer"}
    if role not in valid_roles:
        raise ValueError(f"Rôle invalide : {role} (acceptés : admin, it, viewer)")
    users = _load_users()
    if username in users:
        raise ValueError(f"L'utilisateur '{username}' existe déjà")
    if len(username) < 3:
        raise ValueError("Nom d'utilisateur trop court (min 3 caractères)")
    if len(password) < 8:
        raise ValueError("Mot de passe trop court (min 8 caractères)")

    hashed = _hash_password(password)
    totp_secret = pyotp.random_base32()
    users[username] = {
        "password_hash": hashed,
        "totp_secret":   totp_secret,
        "created_at":    time.time(),
        "mfa_verified":  False,
        "role":          role,
    }
    _save_users(users)
    logger.info(f"Utilisateur créé : {username} (rôle : {role})")
    return totp_secret


def list_users() -> list:
    """Retourne la liste des utilisateurs sans les hashes de mots de passe."""
    users = _load_users()
    return [
        {
            "username":     u,
            "role":         data.get("role", "admin"),
            "created_at":   data.get("created_at", 0),
            "mfa_verified": data.get("mfa_verified", False),
        }
        for u, data in users.items()
    ]


def delete_user(username: str) -> bool:
    """Supprime un utilisateur. Refuse de supprimer le dernier admin."""
    users = _load_users()
    if username not in users:
        return False
    admins = [u for u, d in users.items() if d.get("role") == "admin"]
    if users[username].get("role") == "admin" and len(admins) <= 1:
        raise ValueError("Impossible de supprimer le dernier administrateur")
    del users[username]
    _save_users(users)
    logger.info(f"Utilisateur supprimé : {username}")
    return True


def update_user_role(username: str, new_role: str) -> bool:
    """Met à jour le rôle d'un utilisateur."""
    valid_roles = {"admin", "it", "viewer"}
    if new_role not in valid_roles:
        return False
    users = _load_users()
    if username not in users:
        return False
    if users[username].get("role") == "admin" and new_role != "admin":
        admins = [u for u, d in users.items() if d.get("role") == "admin"]
        if len(admins) <= 1:
            raise ValueError("Impossible de rétrograder le dernier administrateur")
    users[username]["role"] = new_role
    _save_users(users)
    return True


def get_user_role(username: str) -> str:
    """Retourne le rôle de l'utilisateur ('admin' par défaut)."""
    users = _load_users()
    return users.get(username, {}).get("role", "admin")


# ── Auth principale ───────────────────────────────────────────

def get_totp_qr(username: str, totp_secret: str) -> str:
    totp = pyotp.TOTP(totp_secret)
    uri  = totp.provisioning_uri(name=username, issuer_name="NMAPPER")
    img  = qrcode.make(uri)
    buf  = io.BytesIO()
    img.save(buf, format="PNG")
    b64  = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def verify_password(username: str, password: str) -> Optional[str]:
    users = _load_users()
    user  = users.get(username)
    if not user:
        return None
    if not _verify_password_hash(password, user["password_hash"]):
        return None
    return user["totp_secret"]


def verify_totp_code(username: str, code: str) -> bool:
    users = _load_users()
    user  = users.get(username)
    if not user:
        return False
    totp = pyotp.TOTP(user["totp_secret"])
    return totp.verify(code.strip(), valid_window=1)


def is_mfa_verified(username: str) -> bool:
    users = _load_users()
    return bool(users.get(username, {}).get("mfa_verified", False))


def mark_mfa_verified(username: str) -> None:
    users = _load_users()
    if username in users:
        users[username]["mfa_verified"] = True
        _save_users(users)


def create_pending(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _pending_mfa[token] = {
        "username": username,
        "expires":  time.time() + PENDING_TTL,
    }
    return token


def consume_pending(temp_token: str) -> Optional[str]:
    entry = _pending_mfa.pop(temp_token, None)
    if not entry:
        return None
    if time.time() > entry["expires"]:
        return None
    return entry["username"]
