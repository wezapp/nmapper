"""
NMAPPER — Journal d'activité (via SQLite).
API identique à l'ancienne version fichier JSON — aucun changement requis dans main.py.
"""
import database as _db


def append_log(
    action: str,
    target: str = "",
    status: str = "info",
    detail: str = "",
) -> None:
    _db.add_log(action, target, status, detail)


def get_logs(limit: int = 200, action_prefix=None) -> list:
    return _db.get_logs(limit, action_prefix)


def clear_logs() -> None:
    _db.clear_logs_db()
