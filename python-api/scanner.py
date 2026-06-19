import asyncio
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from activity_log import append_log
from models import ScanProfile, ScanRequest, ScanResponse, ScanStatus

logger = logging.getLogger(__name__)

SCANS_DIR = Path(__file__).parent / "scans"
MAX_CONCURRENT: int = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "600"))
MAX_SCAN_HISTORY: int = int(os.getenv("MAX_SCAN_HISTORY", "500"))

# Whitelisted profiles — no arbitrary nmap flags accepted from the user
SCAN_PROFILES: dict[str, list[str]] = {
    ScanProfile.discovery: ["-sn", "-T3", "--min-hostgroup", "32"],
    ScanProfile.quick:     ["-sV", "--top-ports", "100", "-T3"],
    ScanProfile.standard:  ["-sV", "-sC", "--top-ports", "1000", "-T3"],
    ScanProfile.full:      ["-sV", "-sC", "-p-", "-T3"],
    ScanProfile.stealth:   ["-sS", "-T2", "--top-ports", "100"],
}

_semaphore: Optional[asyncio.Semaphore] = None

# Tracks running nmap subprocesses keyed by scan_id — used to kill on cancel
_running_procs: dict[str, asyncio.subprocess.Process] = {}


def init_semaphore() -> None:
    global _semaphore
    _semaphore = asyncio.Semaphore(MAX_CONCURRENT)


def _get_semaphore() -> asyncio.Semaphore:
    if _semaphore is None:
        init_semaphore()
    return _semaphore


# ── Security helpers ─────────────────────────────────────────

def _validate_scan_id(scan_id: str) -> None:
    """Rejects any scan_id that is not a strict UUID4 — prevents path traversal."""
    try:
        parsed = uuid.UUID(scan_id, version=4)
        if str(parsed) != scan_id:
            raise ValueError
    except (ValueError, AttributeError):
        raise ValueError(f"Identifiant de scan invalide : '{scan_id}'")


def _enforce_scan_quota() -> None:
    """Purge les scans les plus anciens si la limite MAX_SCAN_HISTORY est atteinte."""
    if not SCANS_DIR.exists():
        return
    dirs = sorted(
        [d for d in SCANS_DIR.iterdir() if d.is_dir() and (d / "meta.json").exists()],
        key=lambda d: d.stat().st_mtime,
    )
    while len(dirs) >= MAX_SCAN_HISTORY:
        oldest = dirs.pop(0)
        shutil.rmtree(oldest, ignore_errors=True)
        logger.info(f"Quota: ancien scan supprimé ({oldest.name})")


# ── File helpers ─────────────────────────────────────────────

def _scan_dir(scan_id: str) -> Path:
    d = SCANS_DIR / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _meta_path(scan_id: str) -> Path:
    return SCANS_DIR / scan_id / "meta.json"


def _result_path(scan_id: str) -> Path:
    return SCANS_DIR / scan_id / "result.xml"


def _read_meta(scan_id: str) -> dict:
    p = _meta_path(scan_id)
    if not p.exists():
        return {}
    with open(p) as f:
        return json.load(f)


def _write_meta(scan_id: str, data: dict) -> None:
    with open(_meta_path(scan_id), "w") as f:
        json.dump(data, f, indent=2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _meta_to_response(scan_id: str, meta: dict) -> ScanResponse:
    return ScanResponse(
        id=scan_id,
        status=ScanStatus(meta.get("status", ScanStatus.queued)),
        target=meta.get("target", ""),
        profile=meta.get("profile", ""),
        vlan_name=meta.get("vlan_name"),
        created_at=meta.get("created_at", ""),
        started_at=meta.get("started_at"),
        finished_at=meta.get("finished_at"),
        error=meta.get("error"),
        result_available=_result_path(scan_id).exists(),
    )


# ── Public API ───────────────────────────────────────────────

async def create_scan(req: ScanRequest) -> str:
    _enforce_scan_quota()
    scan_id = str(uuid.uuid4())
    _scan_dir(scan_id)
    _write_meta(scan_id, {
        "id": scan_id,
        "status": ScanStatus.queued,
        "target": req.target,
        "profile": req.profile,
        "ports": req.ports,
        "vlan_name": req.vlan_name,
        "created_at": _now(),
        "started_at": None,
        "finished_at": None,
        "error": None,
    })
    asyncio.create_task(_run_scan(scan_id, req))
    append_log("scan_start", req.target, "info", f"profile={req.profile}")
    return scan_id


def get_scan(scan_id: str) -> Optional[ScanResponse]:
    _validate_scan_id(scan_id)
    meta = _read_meta(scan_id)
    return _meta_to_response(scan_id, meta) if meta else None


def list_scans(limit: int = 20, offset: int = 0) -> tuple[list[ScanResponse], int]:
    if not SCANS_DIR.exists():
        return [], 0

    dirs = sorted(
        [d for d in SCANS_DIR.iterdir() if d.is_dir() and (d / "meta.json").exists()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    total = len(dirs)
    results = []
    for d in dirs[offset: offset + limit]:
        meta = _read_meta(d.name)
        if meta:
            results.append(_meta_to_response(d.name, meta))
    return results, total


def get_result_path(scan_id: str) -> Optional[Path]:
    _validate_scan_id(scan_id)
    p = _result_path(scan_id)
    return p if p.exists() else None


async def cancel_scan(scan_id: str) -> bool:
    _validate_scan_id(scan_id)
    meta = _read_meta(scan_id)
    if not meta:
        return False
    if meta["status"] not in (ScanStatus.queued, ScanStatus.running):
        return False

    # Tue le processus nmap en cours si présent
    proc = _running_procs.get(scan_id)
    if proc is not None:
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass

    meta["status"] = ScanStatus.cancelled
    meta["finished_at"] = _now()
    _write_meta(scan_id, meta)
    append_log("scan_cancel", meta.get("target", scan_id[:8]), "info", "")
    return True


# ── Export organisé par label ────────────────────────────────

def _export_by_label(scan_id: str, req: ScanRequest) -> None:
    """Copie le résultat XML dans SCANS_DIR/<label>/<label>.xml pour accès direct."""
    src = _result_path(scan_id)
    if not src.exists():
        return
    # Nom de dossier : label fourni ou date courte si absent
    raw_label = (req.vlan_name or _now()[:10]).strip()
    # Sanitize : garde uniquement alphanum, tirets, underscores, points
    safe_label = "".join(c for c in raw_label if c.isalnum() or c in "-_.")
    if not safe_label:
        safe_label = scan_id[:8]
    label_dir = SCANS_DIR / safe_label
    label_dir.mkdir(parents=True, exist_ok=True)
    dst = label_dir / f"{safe_label}.xml"
    shutil.copy2(src, dst)
    # 644 : nginx (UID 101 = "other") doit pouvoir lire ce fichier exporté
    dst.chmod(0o644)
    logger.info(f"Résultat exporté → {dst.relative_to(SCANS_DIR)}")


# ── Internal execution ───────────────────────────────────────

async def _run_scan(scan_id: str, req: ScanRequest) -> None:
    sem = _get_semaphore()
    async with sem:
        meta = _read_meta(scan_id)
        if meta.get("status") == ScanStatus.cancelled:
            return

        meta["status"] = ScanStatus.running
        meta["started_at"] = _now()
        _write_meta(scan_id, meta)

        try:
            await _execute_nmap(scan_id, req)

            # Re-lit le statut : peut avoir été annulé pendant l'exécution
            meta = _read_meta(scan_id)
            if meta.get("status") == ScanStatus.cancelled:
                return
            meta["status"] = ScanStatus.done
            meta["finished_at"] = _now()
            _write_meta(scan_id, meta)
            _export_by_label(scan_id, req)
            append_log("scan_done", req.target, "success", f"profile={req.profile}")
            logger.info(f"Scan {scan_id} terminé ({req.target})")

        except asyncio.TimeoutError:
            meta = _read_meta(scan_id)
            if meta.get("status") == ScanStatus.cancelled:
                return
            meta["status"] = ScanStatus.error
            meta["error"] = "Timeout dépassé"
            meta["finished_at"] = _now()
            _write_meta(scan_id, meta)
            append_log("scan_error", req.target, "error", "Timeout dépassé")
            logger.warning(f"Scan {scan_id} timeout ({req.target})")

        except Exception as exc:
            meta = _read_meta(scan_id)
            if meta.get("status") == ScanStatus.cancelled:
                return
            meta["status"] = ScanStatus.error
            # Message générique côté client — détails complets uniquement dans les logs
            meta["error"] = "Échec du scan — consultez les logs du conteneur"
            meta["finished_at"] = _now()
            _write_meta(scan_id, meta)
            append_log("scan_error", req.target, "error", str(exc)[:200])
            logger.error(f"Scan {scan_id} erreur : {exc!r}")


async def _execute_nmap(scan_id: str, req: ScanRequest) -> None:
    result_file = str(_result_path(scan_id))

    if req.profile not in SCAN_PROFILES:
        raise ValueError(f"Profil invalide : {req.profile}")

    # Vérifie que nmap est disponible
    nmap_bin = shutil.which("nmap")
    if nmap_bin is None:
        raise RuntimeError(
            "nmap n'est pas installé sur ce serveur. "
            "Le scanner actif est indisponible dans cet environnement. "
            "Utilisez le mode import (Sources / Import) pour analyser des fichiers XML/TXT nmap."
        )

    profile_flags = SCAN_PROFILES[req.profile]

    # Commande construite entièrement depuis des valeurs whitelistées
    cmd = [nmap_bin, "-oX", result_file] + profile_flags

    if req.ports:
        cmd += ["-p", req.ports]

    # target peut contenir plusieurs cibles séparées par des espaces (validator.py)
    cmd.extend(req.target.split())

    logger.info(f"Scan {scan_id} → profil={req.profile} targets={len(req.target.split())}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _running_procs[scan_id] = proc

    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise
    finally:
        _running_procs.pop(scan_id, None)

    # nmap exit 1 = avertissement non fatal (ex: "host seems down")
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"nmap a échoué (code {proc.returncode})")

    # Restreint la lecture du XML brut au seul processus API
    result = Path(result_file)
    if result.exists():
        result.chmod(0o600)
