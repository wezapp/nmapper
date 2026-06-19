import logging
import os
import secrets
import uuid as _uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request

import activity_log as _activity_log
import database as _db
import user_auth
from auth import (
    API_KEY,
    SESSION_COOKIE,
    SESSION_TTL,
    _api_key_log_hash,
    check_session,
    create_session,
    get_session_info,
    require_role,
    verify_auth,
)
from models import AuthRequest, ScanListResponse, ScanRequest, ScanResponse, ScanStatus
from scanner import (
    SCANS_DIR,
    cancel_scan,
    create_scan,
    get_result_path,
    get_scan,
    init_semaphore,
    list_scans,
)
from validator import validate_ports, validate_target, validate_vlan_name

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration runtime ────────────────────────────────────
SECURE_COOKIE = os.getenv("SECURE_COOKIE", "false").lower() == "true"
MAX_RESULT_SIZE = int(os.getenv("MAX_RESULT_FILE_MB", "100")) * 1024 * 1024

_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
_allowed_origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    _db.init_db()
    init_semaphore()
    logger.info("NMAPPER API démarrée")
    logger.info(f"Clé API active (hash: {_api_key_log_hash}...)")
    if SECURE_COOKIE:
        logger.info("SECURE_COOKIE=true — le cookie de session requiert HTTPS")
    yield


app = FastAPI(
    title="NMAPPER API",
    description="API de scan réseau embarquée",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=r"https?://.*\.replit\.dev|https?://.*\.repl\.co|https?://localhost.*",
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
    allow_credentials=True,
    max_age=600,
)


# ── Handler global : transforme les 500 non attendus en message propre ──

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Erreur non gérée sur {request.method} {request.url.path}: {exc!r}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne du serveur — consultez les logs pour le détail"},
    )


def _require_uuid(scan_id: str) -> str:
    try:
        parsed = _uuid.UUID(scan_id, version=4)
        if str(parsed) != scan_id:
            raise ValueError
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Identifiant de scan invalide")
    return scan_id


# ── Health ────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


# ── Auth ──────────────────────────────────────────────────────

@app.post("/auth", include_in_schema=False)
@limiter.limit("10/minute")
async def auth_endpoint(request: Request, body: AuthRequest) -> JSONResponse:
    """
    Vérifie la clé API (body JSON) et crée une session HttpOnly.
    Après cet appel le navigateur envoie automatiquement le cookie sur /api/*
    — la clé brute ne circule plus dans les headers JS.
    """
    if not secrets.compare_digest(body.api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Clé API invalide")

    token = create_session()
    response = JSONResponse({"ok": True, "session_ttl": SESSION_TTL})
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_TTL,
        path="/",
        secure=SECURE_COOKIE,
    )
    return response


@app.delete("/auth", include_in_schema=False)
async def logout_endpoint() -> JSONResponse:
    """Supprime le cookie de session (déconnexion)."""
    response = JSONResponse({"ok": True})
    response.delete_cookie(key=SESSION_COOKIE, path="/")
    return response


# ── Auth utilisateur : setup / login / MFA ────────────────

class _SetupRequest(BaseModel):
    username: str
    password: str

class _LoginRequest(BaseModel):
    username: str
    password: str

class _MFARequest(BaseModel):
    temp_token: str
    code: str

class _VerifySetupMFA(BaseModel):
    username: str
    code: str


@app.get("/auth/status", include_in_schema=False)
async def auth_status(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    info  = get_session_info(token) if token else None
    return {
        "authenticated": bool(info),
        "setup_done":    user_auth.setup_done(),
        "username":      info["username"] if info else None,
        "role":          info["role"]     if info else None,
    }


@app.post("/auth/setup", include_in_schema=False)
@limiter.limit("5/minute")
async def auth_setup(request: Request, body: _SetupRequest):
    try:
        totp_secret = user_auth.create_user(body.username, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    qr_url = user_auth.get_totp_qr(body.username, totp_secret)
    logger.info(f"Setup compte : {body.username}")
    return {"ok": True, "qr_url": qr_url, "totp_secret": totp_secret, "username": body.username}


@app.post("/auth/verify-setup-mfa", include_in_schema=False)
@limiter.limit("10/minute")
async def auth_verify_setup_mfa(request: Request, body: _VerifySetupMFA):
    if not user_auth.verify_totp_code(body.username, body.code):
        raise HTTPException(status_code=401, detail="Code MFA invalide")
    user_auth.mark_mfa_verified(body.username)
    return {"ok": True}


@app.post("/auth/login", include_in_schema=False)
@limiter.limit("10/minute")
async def auth_login(request: Request, body: _LoginRequest):
    secret = user_auth.verify_password(body.username, body.password)
    if secret is None:
        _activity_log.append_log("login", body.username, "error", "Échec mot de passe")
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    temp_token = user_auth.create_pending(body.username)
    # Si MFA jamais vérifiée (ex : reset), renvoyer le QR pour re-scan
    needs_qr = not user_auth.is_mfa_verified(body.username)
    if needs_qr:
        qr_url = user_auth.get_totp_qr(body.username, secret)
        return {"ok": True, "needs_mfa": True, "temp_token": temp_token,
                "needs_qr_setup": True, "qr_url": qr_url, "totp_secret": secret}
    return {"ok": True, "needs_mfa": True, "temp_token": temp_token}


@app.post("/auth/mfa", include_in_schema=False)
@limiter.limit("10/minute")
async def auth_mfa(request: Request, body: _MFARequest):
    username = user_auth.consume_pending(body.temp_token)
    if not username:
        raise HTTPException(status_code=401, detail="Session MFA expirée — reconnectez-vous")
    if not user_auth.verify_totp_code(username, body.code):
        raise HTTPException(status_code=401, detail="Code MFA invalide")
    user_auth.mark_mfa_verified(username)
    role  = user_auth.get_user_role(username)
    token = create_session(username=username, role=role)
    response = JSONResponse({"ok": True, "username": username, "role": role})
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_TTL,
        path="/",
        secure=SECURE_COOKIE,
    )
    _activity_log.append_log("login", username, "success", "")
    return response


@app.delete("/auth/logout", include_in_schema=False)
async def auth_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(key=SESSION_COOKIE, path="/")
    _activity_log.append_log("logout", "", "info", "")
    return response


# ── Scans ─────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def start_scan(
    request: Request,
    body: ScanRequest,
    _: str = Depends(verify_auth),
):
    """Lance un scan nmap. Retourne immédiatement l'ID pour polling."""
    try:
        body.target = validate_target(body.target)
        body.ports = validate_ports(body.ports)
        body.vlan_name = validate_vlan_name(body.vlan_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    scan_id = await create_scan(body)
    logger.info(
        f"Scan créé {scan_id} | target={body.target} profile={body.profile} "
        f"ip={request.client.host if request.client else 'unknown'}"
    )
    return get_scan(scan_id)


@app.get("/scan/{scan_id}", response_model=ScanResponse)
@limiter.limit("60/minute")
async def get_scan_status(
    request: Request,
    scan_id: str,
    _: str = Depends(verify_auth),
):
    _require_uuid(scan_id)
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return result


@app.get("/scan/{scan_id}/result")
@limiter.limit("30/minute")
async def get_scan_result(
    request: Request,
    scan_id: str,
    _: str = Depends(verify_auth),
):
    """Retourne le fichier XML nmap du scan une fois terminé."""
    _require_uuid(scan_id)
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if scan.status != ScanStatus.done:
        raise HTTPException(
            status_code=409,
            detail=f"Résultat non disponible — statut actuel : {scan.status}",
        )

    path = get_result_path(scan_id)
    if not path:
        raise HTTPException(status_code=404, detail="Fichier résultat introuvable")

    if path.stat().st_size > MAX_RESULT_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Fichier résultat trop volumineux (max {MAX_RESULT_SIZE // (1024*1024)} MB)",
        )

    return FileResponse(
        path=str(path),
        media_type="application/xml",
        filename=f"nmap-{scan.vlan_name or scan_id[:8]}.xml",
    )


@app.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def cancel_scan_endpoint(
    request: Request,
    scan_id: str,
    _: str = Depends(verify_auth),
):
    _require_uuid(scan_id)
    cancelled = await cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail="Scan introuvable ou déjà dans un état terminal",
        )


@app.get("/scans", response_model=ScanListResponse)
@limiter.limit("30/minute")
async def list_all_scans(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(verify_auth),
):
    scans, total = list_scans(limit=limit, offset=offset)
    return ScanListResponse(scans=scans, total=total)


# ── Monitoring : persistance SQLite ───────────────────────
import time as _time


def _verify_agent_key(request: Request) -> bool:
    """Vérifie la clé agent dans le header X-Agent-Key."""
    key = request.headers.get("X-Agent-Key", "")
    return bool(key) and secrets.compare_digest(key.encode(), API_KEY.encode())


class _MonitorPushRequest(BaseModel):
    agent_id:       str
    agent_hostname: str
    criticality:    str  = "normal"
    hosts:          list


class _ConnectivityRequest(BaseModel):
    from_agent: str
    from_ip:    str
    matrix:     dict   # { to_ip: { "port": bool } }
    ts:         float  = 0.0


@app.post("/monitor/push", include_in_schema=False)
@limiter.limit("120/minute")
async def monitor_push(request: Request, body: _MonitorPushRequest):
    """Endpoint pour les agents de collecte — clé API dans X-Agent-Key."""
    if not _verify_agent_key(request):
        raise HTTPException(status_code=401, detail="Clé agent invalide")

    now = _time.time()
    client_ip = request.client.host if request.client else "unknown"

    is_new = _db.upsert_agent({
        "agent_id":    body.agent_id,
        "hostname":    body.agent_hostname,
        "ip":          client_ip,
        "criticality": body.criticality,
        "last_seen":   now,
    })
    if is_new:
        _activity_log.append_log(
            "agent_connect",
            body.agent_id,
            "info",
            f"host={body.agent_hostname} ip={client_ip}",
        )

    for h in body.hosts:
        ip = h.get("ip")
        if not ip:
            continue
        h["agent_id"]  = body.agent_id
        h["last_seen"] = now

        prev = _db.get_host(ip)
        if prev:
            prev_ports = {p["port"] for p in prev.get("ports", []) if p.get("state") == "open"}
            new_ports  = {p["port"] for p in h.get("ports",  []) if p.get("state") == "open"}
            opened = new_ports - prev_ports
            closed = prev_ports - new_ports
            if opened:
                _db.add_event("warn", f"[{ip}] Nouveau(x) port(s) : {sorted(opened)}")
            if closed:
                _db.add_event("info", f"[{ip}] Port(s) fermé(s) : {sorted(closed)}")
        else:
            _db.add_event("info",
                f"Nouvel hôte : {ip} ({h.get('hostname','?')}) — VLAN {h.get('vlan','?')}")

        _db.upsert_host(h)

    logger.info(f"Monitor push agent={body.agent_id} hosts={len(body.hosts)}")
    return {"ok": True, "hosts_recorded": len(body.hosts)}


@app.get("/dashboard/stats", include_in_schema=False)
@limiter.limit("60/minute")
async def dashboard_stats(request: Request, _: str = Depends(verify_auth)):
    """KPIs agrégés pour le dashboard (agents, hôtes, vulnérabilités)."""
    return _db.get_dashboard_stats()


@app.get("/monitor/hosts", include_in_schema=False)
@limiter.limit("60/minute")
async def monitor_get_hosts(request: Request):
    """Retourne tous les hôtes surveillés + liste des agents.
    Accepte session cookie (interface web) OU X-Agent-Key (agents)."""
    session_token = request.cookies.get(SESSION_COOKIE)
    if not (_verify_agent_key(request) or check_session(session_token or "")):
        raise HTTPException(status_code=401, detail="Non autorisé")
    hosts  = _db.get_all_hosts()
    agents = _db.get_all_agents()
    return {"hosts": hosts, "agents": agents, "total": len(hosts)}


@app.get("/monitor/events", include_in_schema=False)
@limiter.limit("60/minute")
async def monitor_get_events(request: Request, _: str = Depends(verify_auth)):
    """Retourne les événements de monitoring (max 200)."""
    return {"events": _db.get_events(200)}


class _CritRequest(BaseModel):
    criticality: str  # critical | high | normal | low


@app.patch("/monitor/hosts/{ip}/criticality", include_in_schema=False)
@limiter.limit("30/minute")
async def monitor_set_host_criticality(
    request: Request,
    ip: str,
    body: _CritRequest,
    _: str = Depends(verify_auth),
):
    """Définit la criticité explicite d'un hôte (remplace l'héritage agent)."""
    valid = {"critical", "high", "normal", "low"}
    if body.criticality not in valid:
        raise HTTPException(status_code=422, detail=f"Criticité invalide : {body.criticality}")
    ok = _db.update_host_criticality(ip, body.criticality)
    if not ok:
        raise HTTPException(status_code=404, detail="Hôte introuvable")
    return {"ok": True, "ip": ip, "criticality": body.criticality}


@app.delete("/monitor/hosts", include_in_schema=False)
@limiter.limit("10/minute")
async def monitor_clear(request: Request, _: str = Depends(verify_auth)):
    """Vide tous les hôtes et événements surveillés."""
    _db.clear_hosts()
    return {"ok": True}


@app.post("/monitor/connectivity", include_in_schema=False)
@limiter.limit("120/minute")
async def monitor_push_connectivity(request: Request, body: _ConnectivityRequest):
    """
    Reçoit la matrice de connectivité d'un agent.
    La clé agent doit être dans X-Agent-Key.
    """
    if not _verify_agent_key(request):
        raise HTTPException(status_code=401, detail="Clé agent invalide")

    ts = body.ts if body.ts > 0 else _time.time()
    _db.upsert_connectivity(body.from_agent, body.from_ip, body.matrix, ts)

    total     = sum(len(v) for v in body.matrix.values())
    reachable = sum(
        1 for ports in body.matrix.values()
        for ok in ports.values() if ok
    )
    logger.info(
        f"Connectivity push agent={body.from_agent} "
        f"peers={len(body.matrix)} ports={total} reachable={reachable}"
    )
    return {"ok": True, "peers": len(body.matrix),
            "ports": total, "reachable": reachable}


@app.get("/monitor/connectivity", include_in_schema=False)
@limiter.limit("60/minute")
async def monitor_get_connectivity(
    request: Request,
    summary: bool = True,
    _: str = Depends(verify_auth),
):
    """
    Retourne la matrice de connectivité.
    ?summary=true  → agrégat (from_ip, to_ip, total/reachable ports) — pour le graphe
    ?summary=false → toutes les lignes brutes
    """
    if summary:
        return {"edges": _db.get_connectivity_summary()}
    return {"entries": _db.get_connectivity(max_age_s=0)}


# ── ASGI wrapper : supprime le préfixe /scanner-api ──────
# Le reverse-proxy Replit transmet le chemin COMPLET au backend.
# Ce wrapper retire "/scanner-api" avant que FastAPI route la requête,
# ce qui permet de garder des routes courtes (/health, /auth, …).

# ── Déploiement SSH ───────────────────────────────────────────────────────────
import deploy as _deploy


class _DeployRequest(BaseModel):
    host:        str
    ssh_port:    int  = 22
    user:        str
    auth_type:   str  # "password" | "key"
    auth_value:  str  # mot de passe ou clé privée
    role:        str  # "agent" | "server"
    server_ip:   str  = ""
    api_key:     str  = ""
    server_port: int  = 25774
    interval:    int  = 30
    systemd:     bool = True


class _ProbeRequest(BaseModel):
    host: str
    port: int = 22


@app.post("/deploy/probe", include_in_schema=False)
@limiter.limit("30/minute")
async def deploy_probe(
    request: Request,
    body: _ProbeRequest,
    _: str = Depends(verify_auth),
):
    """Test TCP de connectivité vers host:port (non bloquant)."""
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _deploy.probe_host, body.host, body.port)
    return result


@app.post("/deploy/start", include_in_schema=False)
@limiter.limit("10/minute")
async def deploy_start(
    request: Request,
    body: _DeployRequest,
    _: str = Depends(verify_auth),
):
    """Lance un job de déploiement SSH en arrière-plan."""
    # Validation précoce (hostname, port, clé SSH, rôle, intervalle)
    try:
        _deploy.validate_deploy_cfg(body.dict())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Log de sécurité — jamais les credentials
    client_ip = request.client.host if request.client else "unknown"
    logger.info(
        f"DEPLOY START | role={body.role} target={body.user}@{body.host}:{body.ssh_port} "
        f"auth={body.auth_type} from={client_ip}"
    )
    job_id = _deploy.start_job(body.dict())
    return {"job_id": job_id}


@app.get("/deploy/status/{job_id}", include_in_schema=False)
async def deploy_status(
    request: Request,
    job_id: str,
    _: str = Depends(verify_auth),
):
    """Retourne l'état et les logs d'un job de déploiement."""
    job = _deploy.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job introuvable")
    return job


@app.delete("/deploy/jobs/{job_id}", include_in_schema=False)
async def deploy_delete_job(
    job_id: str,
    _: str = Depends(verify_auth),
):
    ok = _deploy.delete_job(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job introuvable ou encore en cours")
    return {"deleted": job_id}


@app.get("/deploy/jobs", include_in_schema=False)
async def deploy_jobs(
    request: Request,
    _: str = Depends(verify_auth),
):
    """Liste tous les jobs de déploiement de la session."""
    return _deploy.list_jobs()


# ── Journal d'activité ────────────────────────────────────────────────────────

class _ActivityLogEntry(BaseModel):
    action: str
    target: str = ""
    status: str = "info"
    detail: str = ""


@app.get("/activity/logs", include_in_schema=False)
@limiter.limit("60/minute")
async def activity_get_logs(
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    _: str = Depends(verify_auth),
):
    """Retourne les entrées du journal (les plus récentes en premier)."""
    return {"logs": _activity_log.get_logs(limit=limit)}


@app.post("/activity/log", include_in_schema=False)
@limiter.limit("120/minute")
async def activity_post_log(
    request: Request,
    body: _ActivityLogEntry,
    _: str = Depends(verify_auth),
):
    """Enregistre un événement client dans le journal."""
    _activity_log.append_log(body.action, body.target, body.status, body.detail)
    return {"ok": True}


@app.delete("/activity/logs", include_in_schema=False)
@limiter.limit("5/minute")
async def activity_clear_logs(
    request: Request,
    _: str = Depends(verify_auth),
):
    """Vide le journal d'activité."""
    _activity_log.clear_logs()
    return {"ok": True}


# ── Administration : gestion des utilisateurs ─────────────────────────────────

class _AddUserRequest(BaseModel):
    username: str
    password: str
    role:     str  # admin | it | viewer


class _UpdateRoleRequest(BaseModel):
    role: str


@app.get("/admin/users", include_in_schema=False)
@limiter.limit("30/minute")
async def admin_list_users(
    request: Request,
    _: dict = Depends(require_role("admin")),
):
    """Liste tous les utilisateurs (sans mots de passe)."""
    return {"users": user_auth.list_users()}


@app.post("/admin/users", include_in_schema=False)
@limiter.limit("10/minute")
async def admin_add_user(
    request: Request,
    body: _AddUserRequest,
    _: dict = Depends(require_role("admin")),
):
    """Crée un utilisateur supplémentaire (admin, it ou viewer)."""
    try:
        totp_secret = user_auth.add_managed_user(body.username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    qr_url = user_auth.get_totp_qr(body.username, totp_secret)
    _activity_log.append_log("admin_create_user", body.username, "info", f"role={body.role}")
    return {"ok": True, "username": body.username, "role": body.role,
            "qr_url": qr_url, "totp_secret": totp_secret}


@app.put("/admin/users/{username}/role", include_in_schema=False)
@limiter.limit("10/minute")
async def admin_update_role(
    request: Request,
    username: str,
    body: _UpdateRoleRequest,
    _: dict = Depends(require_role("admin")),
):
    """Modifie le rôle d'un utilisateur."""
    try:
        ok = user_auth.update_user_role(username, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    _activity_log.append_log("admin_update_role", username, "info", f"new_role={body.role}")
    return {"ok": True, "username": username, "role": body.role}


@app.delete("/admin/users/{username}", include_in_schema=False)
@limiter.limit("10/minute")
async def admin_delete_user(
    request: Request,
    username: str,
    _: dict = Depends(require_role("admin")),
):
    """Supprime un utilisateur."""
    try:
        ok = user_auth.delete_user(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    _activity_log.append_log("admin_delete_user", username, "warn", "")
    return {"ok": True, "deleted": username}


@app.get("/deploy/apikey", include_in_schema=False)
async def deploy_apikey(
    request: Request,
    _: str = Depends(verify_auth),
):
    """Retourne la clé API courante pour configuration manuelle des agents."""
    return {"api_key": API_KEY}


class _StripPrefix:
    def __init__(self, inner, prefix: str) -> None:
        self.inner = inner
        self.prefix = prefix.rstrip("/")

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") in ("http", "websocket"):
            path: str = scope.get("path", "")
            if path == self.prefix or path.startswith(self.prefix + "/"):
                scope = dict(scope)
                scope["path"] = path[len(self.prefix):] or "/"
        await self.inner(scope, receive, send)


asgi_app = _StripPrefix(app, "/scanner-api")
