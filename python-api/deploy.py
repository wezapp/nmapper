"""
NMAPPER — Déploiement SSH d'agents et du serveur backend.
Jobs en arrière-plan, logs streamés par polling.
"""
import io
import ipaddress
import logging
import re
import secrets
import socket
import threading
import time
import uuid
from pathlib import Path

_log = logging.getLogger("nmapper.deploy")

try:
    from activity_log import append_log as _append_log
except Exception:
    def _append_log(*a, **kw): pass

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ── Job store (in-memory) ─────────────────────────────────────────────────────
_jobs: dict = {}
_MAX_JOBS   = 50

AGENT_DIR   = Path("/opt/nmapper-agent")
INSTALL_DIR = Path("/opt/nmapper")
API_SUBDIR  = INSTALL_DIR / "python-api"   # où vivent main.py + scans/

# Sources locales — cherchées dans plusieurs endroits pour fonctionner
# aussi bien en dev (Replit) qu'en prod (/opt/nmapper/python-api/)
def _find_install_src() -> Path:
    candidates = [
        Path(__file__).parent.parent / "installation",   # dev : python-api/../installation
        INSTALL_DIR / "installation",                      # prod : /opt/nmapper/installation
        Path("/opt/nmapper_src/installation"),             # source clonée
    ]
    for c in candidates:
        if (c / "agent.py").exists():
            return c
    # Retourne le premier candidat même absent (l'erreur sera levée à l'usage)
    return candidates[0]

_INSTALL_SRC = _find_install_src()
_API_SRC     = Path(__file__).parent          # python-api/


class DeployJob:
    def __init__(self, job_id: str, cfg: dict):
        self.job_id     = job_id
        self.cfg        = cfg
        self.status     = "running"
        self.logs: list = []
        self.started_at = time.time()

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info"):
        self.logs.append({"time": time.strftime("%H:%M:%S"), "level": level, "msg": msg})

    def to_dict(self) -> dict:
        return {
            "job_id":     self.job_id,
            "status":     self.status,
            "host":       self.cfg.get("host", "?"),
            "role":       self.cfg.get("role", "?"),
            "logs":       self.logs,
            "started_at": self.started_at,
        }

    # ── SSH helpers ───────────────────────────────────────────────────────────

    def _connect(self) -> "paramiko.SSHClient":
        cfg  = self.cfg
        host = cfg["host"]
        port = cfg.get("ssh_port", 22)
        user = cfg["user"]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if cfg["auth_type"] == "password":
            client.connect(host, port=port, username=user,
                           password=cfg["auth_value"], timeout=15)
        else:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(cfg["auth_value"]))
            client.connect(host, port=port, username=user, pkey=pkey, timeout=15)
        return client

    def _exec(self, client: "paramiko.SSHClient", cmd: str, timeout: int = 60) -> str:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        for line in out.splitlines():
            if line.strip():
                self._log(line)
        for line in err.splitlines():
            if line.strip() and line not in out:
                self._log(line, "warn")
        return out

    def _upload(self, sftp: "paramiko.SFTPClient", local: Path, remote: str):
        sftp.put(str(local), remote)
        self._log(f"↑ {local.name} → {remote}")

    def _which_python(self, client: "paramiko.SSHClient") -> str:
        py = self._exec(client, "which python3 2>/dev/null || which python 2>/dev/null", 10)
        return (py.splitlines()[0].strip()) if py else "/usr/bin/python3"

    # ── Déploiement agent ─────────────────────────────────────────────────────

    def _deploy_agent(self, client: "paramiko.SSHClient"):
        cfg        = self.cfg
        server_ip  = cfg.get("server_ip", "")
        api_key    = cfg.get("api_key", "")
        srv_port   = cfg.get("server_port", 25774)
        interval   = cfg.get("interval", 30)
        systemd    = cfg.get("systemd", True)

        if not server_ip or not api_key:
            raise ValueError("IP serveur et clé API obligatoires pour un agent")

        # Créer le répertoire
        self._exec(client, f"mkdir -p {AGENT_DIR}", 10)
        self._exec(client, f"chmod 755 {AGENT_DIR}", 5)

        # Uploader agent.py
        local_agent = _INSTALL_SRC / "agent.py"
        if not local_agent.exists():
            raise FileNotFoundError(f"agent.py introuvable dans {_INSTALL_SRC}")

        sftp = client.open_sftp()
        self._log(f"Transfert agent.py → {AGENT_DIR}/agent.py …")
        self._upload(sftp, local_agent, str(AGENT_DIR / "agent.py"))
        sftp.close()
        self._exec(client, f"chmod +x {AGENT_DIR}/agent.py", 5)

        py = self._which_python(client)
        self._log(f"Python : {py}")

        if systemd:
            self._log("Création du service systemd nmapper-agent…")
            unit = "\n".join([
                "[Unit]",
                "Description=NMAPPER Agent de collecte",
                "After=network-online.target",
                "Wants=network-online.target",
                "",
                "[Service]",
                "Type=simple",
                f"ExecStart={py} {AGENT_DIR}/agent.py "
                f"--server-ip {server_ip} --port {srv_port} "
                f"--key {api_key} --interval {interval}",
                "Restart=always",
                "RestartSec=15",
                "StandardOutput=journal",
                "StandardError=journal",
                "",
                "[Install]",
                "WantedBy=multi-user.target",
            ])
            # Écrire via heredoc base64 pour éviter les problèmes de quoting
            import base64
            b64 = base64.b64encode(unit.encode()).decode()
            self._exec(client,
                f"echo '{b64}' | base64 -d > /etc/systemd/system/nmapper-agent.service",
                10)
            self._exec(client, "systemctl daemon-reload", 10)
            self._exec(client, "systemctl enable nmapper-agent", 10)
            self._exec(client, "systemctl restart nmapper-agent", 15)
            self._log("✅ Service nmapper-agent actif et activé au démarrage", "success")
        else:
            log_path = f"{AGENT_DIR}/agent.log"
            self._exec(client,
                f"nohup {py} {AGENT_DIR}/agent.py "
                f"--server-ip {server_ip} --port {srv_port} "
                f"--key {api_key} --interval {interval} "
                f"> {log_path} 2>&1 &",
                10)
            self._log(f"✅ Agent lancé (logs : {log_path})", "success")

    # ── Déploiement serveur ───────────────────────────────────────────────────

    def _deploy_server(self, client: "paramiko.SSHClient"):
        cfg       = self.cfg
        srv_port  = cfg.get("server_port", 25774)
        systemd   = cfg.get("systemd", True)

        py = self._which_python(client)
        self._log(f"Python : {py}")

        # Créer /opt/nmapper/python-api/scans/
        self._exec(client, f"mkdir -p {API_SUBDIR}/scans", 10)
        self._exec(client, f"chmod 700 {API_SUBDIR}/scans", 5)

        # Uploader les fichiers python-api/ dans le sous-dossier
        sftp = client.open_sftp()
        self._exec(client, f"mkdir -p {API_SUBDIR}", 5)
        py_files = sorted(_API_SRC.glob("*.py"))
        self._log(f"Transfert de {len(py_files)} fichier(s) Python vers {API_SUBDIR}…")
        for f in py_files:
            self._upload(sftp, f, str(API_SUBDIR / f.name))
        sftp.close()

        # pip install deps (avec paramiko pour le déploiement SSH)
        self._log("Installation des dépendances pip…")
        pkgs = (
            "fastapi 'uvicorn[standard]' slowapi bcrypt "
            "pyotp 'qrcode[pil]' pillow python-multipart pydantic starlette paramiko"
        )
        self._exec(client, f"{py} -m pip install --quiet {pkgs}", 180)
        self._log("✅ Dépendances installées")

        # Générer la clé API
        key = secrets.token_urlsafe(32)
        import base64
        b64key = base64.b64encode(key.encode()).decode()
        self._exec(client,
            f"echo '{b64key}' | base64 -d > {API_SUBDIR}/scans/.apikey && "
            f"chmod 600 {API_SUBDIR}/scans/.apikey",
            10)
        self._log(f"🔑 CLÉ API AGENT : {key}", "key")

        if systemd:
            self._log("Création du service systemd nmapper-server…")
            unit = "\n".join([
                "[Unit]",
                "Description=NMAPPER Backend API",
                "After=network.target",
                "",
                "[Service]",
                "Type=simple",
                f"WorkingDirectory={INSTALL_DIR}",
                f"ExecStart={py} -m uvicorn main:asgi_app --host 0.0.0.0 --port {srv_port} --app-dir {API_SUBDIR}",
                "Restart=always",
                "RestartSec=5",
                "StandardOutput=journal",
                "StandardError=journal",
                "",
                "[Install]",
                "WantedBy=multi-user.target",
            ])
            b64 = base64.b64encode(unit.encode()).decode()
            self._exec(client,
                f"echo '{b64}' | base64 -d > /etc/systemd/system/nmapper-server.service",
                10)
            self._exec(client, "systemctl daemon-reload", 10)
            self._exec(client, "systemctl enable nmapper-server", 10)
            self._exec(client, "systemctl restart nmapper-server", 15)
            self._log("✅ Service nmapper-server actif et activé au démarrage", "success")
        else:
            log_path = "/tmp/nmapper-server.log"
            self._exec(client,
                f"cd {INSTALL_DIR} && nohup {py} -m uvicorn main:asgi_app "
                f"--host 0.0.0.0 --port {srv_port} > {log_path} 2>&1 &",
                10)
            self._log(f"✅ Serveur lancé (logs : {log_path})", "success")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self):
        cfg  = self.cfg
        host = cfg.get("host", "?")
        role = cfg.get("role", "?")
        # Log sécurité (pas de credentials)
        _log.info(
            "DEPLOY | role=%s target=%s@%s:%s auth=%s",
            role, cfg.get("user", "?"), host, cfg.get("ssh_port", 22), cfg.get("auth_type", "?")
        )
        _append_log("deploy_start", f"{role}@{host}", "info", f"auth={cfg.get('auth_type','?')}")
        try:
            if not HAS_PARAMIKO:
                raise ImportError("paramiko non installé — pip install paramiko")

            self._log(f"Connexion SSH → {cfg.get('user','?')}@{host}:{cfg.get('ssh_port',22)} …")
            client = self._connect()
            self._log("✅ SSH connecté")

            py_ver = self._exec(client, "python3 --version 2>&1 || python --version 2>&1", 10)
            if not py_ver:
                raise EnvironmentError("python3 introuvable sur la machine cible")
            self._log(f"✅ {py_ver.splitlines()[0]}")

            if role == "agent":
                self._deploy_agent(client)
            elif role == "server":
                self._deploy_server(client)
            else:
                raise ValueError(f"Rôle inconnu : {role}")

            client.close()
            self.status = "success"
            self._log("🎉 Déploiement terminé avec succès !", "success")
            _append_log("deploy_done", f"{role}@{host}", "success", "")

        except Exception as exc:
            self._log(f"❌ {exc}", "error")
            self.status = "error"
            _append_log("deploy_error", f"{role}@{host}", "error", str(exc)[:200])


# ── API publique ──────────────────────────────────────────────────────────────

def probe_host(host: str, port: int = 22, timeout: float = 4.0) -> dict:
    """Test TCP — retourne {reachable, latency_ms, error}. Jamais de credentials."""
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        ms = round((time.monotonic() - t0) * 1000)
        return {"reachable": True, "latency_ms": ms, "error": None}
    except socket.timeout:
        return {"reachable": False, "latency_ms": None,
                "error": f"Timeout ({int(timeout)}s) — hôte inaccessible ou port {port} filtré"}
    except ConnectionRefusedError:
        return {"reachable": False, "latency_ms": None,
                "error": f"Port {port} fermé (connexion refusée)"}
    except OSError as exc:
        return {"reachable": False, "latency_ms": None, "error": str(exc)}


def validate_deploy_cfg(cfg: dict) -> None:
    """
    Valide la configuration avant de lancer le job SSH.
    Lève ValueError avec un message lisible en cas de problème.
    """
    host = cfg.get("host", "").strip()
    if not host:
        raise ValueError("L'adresse de l'hôte est obligatoire")

    # Vérifie que le host est une IP valide OU un nom de domaine acceptable
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Pas une IP — vérifie que c'est un FQDN raisonnable (pas de shell injection)
        if not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?", host):
            raise ValueError(f"Hostname invalide : « {host} »")

    ssh_port = cfg.get("ssh_port", 22)
    if not (1 <= int(ssh_port) <= 65535):
        raise ValueError(f"Port SSH invalide : {ssh_port}")

    auth_type = cfg.get("auth_type", "")
    if auth_type not in ("password", "key"):
        raise ValueError(f"Type d'authentification invalide : « {auth_type} »")

    role = cfg.get("role", "")
    if role not in ("agent", "server"):
        raise ValueError(f"Rôle invalide : « {role} »")

    # Validation du format de la clé privée SSH
    if auth_type == "key":
        key_val = cfg.get("auth_value", "")
        if not key_val.strip().startswith("-----BEGIN"):
            raise ValueError(
                "La clé privée SSH semble invalide — "
                "elle doit commencer par « -----BEGIN ... PRIVATE KEY----- »"
            )
        if HAS_PARAMIKO:
            try:
                paramiko.RSAKey.from_private_key(io.StringIO(key_val))
            except Exception:
                try:
                    paramiko.Ed25519Key.from_private_key(io.StringIO(key_val))
                except Exception:
                    try:
                        paramiko.ECDSAKey.from_private_key(io.StringIO(key_val))
                    except Exception:
                        raise ValueError(
                            "Impossible de lire la clé privée SSH — "
                            "vérifiez le format (RSA, Ed25519 ou ECDSA attendu)"
                        )

    # Validation spécifique au rôle agent
    if role == "agent":
        server_ip = cfg.get("server_ip", "").strip()
        if not server_ip:
            raise ValueError("L'adresse IP du serveur NMAPPER est obligatoire pour un agent")
        try:
            ipaddress.ip_address(server_ip)
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?", server_ip):
                raise ValueError(f"IP serveur invalide : « {server_ip} »")
        if not cfg.get("api_key", "").strip():
            raise ValueError("La clé API est obligatoire pour déployer un agent")
        interval = int(cfg.get("interval", 30))
        if not (10 <= interval <= 3600):
            raise ValueError(f"L'intervalle de collecte doit être entre 10 et 3600 secondes (reçu : {interval})")


def start_job(cfg: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    job    = DeployJob(job_id, cfg)
    _jobs[job_id] = job

    if len(_jobs) > _MAX_JOBS:
        oldest = sorted(_jobs, key=lambda k: _jobs[k].started_at)
        for old in oldest[:len(_jobs) - _MAX_JOBS]:
            del _jobs[old]

    threading.Thread(target=job.run, daemon=True).start()
    return job_id


def get_job(job_id: str) -> dict | None:
    job = _jobs.get(job_id)
    return job.to_dict() if job else None


def delete_job(job_id: str) -> bool:
    """Supprime un job de la liste (uniquement si terminé)."""
    job = _jobs.get(job_id)
    if job is None:
        return False
    if job.status == "running":
        return False
    del _jobs[job_id]
    return True


def list_jobs() -> list:
    return sorted(
        [j.to_dict() for j in _jobs.values()],
        key=lambda j: j["started_at"],
        reverse=True,
    )
