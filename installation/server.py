#!/usr/bin/env python3
"""
NMAPPER — Script d'installation et de démarrage du serveur backend

Modes :
  Installation complète dans /opt/nmapper/ (recommandé) :
      sudo python3 installation/server.py --install

  Démarrage rapide depuis le dossier du projet (test local) :
      python3 installation/server.py

Options :
      --port 8080        port personnalisé (défaut: 25774)
      --host 0.0.0.0     interface d'écoute (défaut: 0.0.0.0)
      --key-only         afficher la clé API et quitter
      --install-only     installer les dépendances et quitter
      --install          copier dans /opt/nmapper/ + créer service systemd
"""

import argparse
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

# ── Chemins ───────────────────────────────────────────────────────────────────
DEFAULT_PORT  = 25774
DEFAULT_HOST  = "0.0.0.0"
INSTALL_DIR   = Path("/opt/nmapper")               # racine de l'installation
API_SUBDIR    = INSTALL_DIR / "python-api"         # où vivent main.py, scans/, …
SERVICE_NAME  = "nmapper-server"
SERVICE_FILE  = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

# python-api/ cherché dans l'installation, sinon dans le projet source
def _find_api_dir() -> Path:
    # Installation existante (post-install)
    if (API_SUBDIR / "main.py").exists():
        return API_SUBDIR
    # Fallback ancien : fichiers à plat dans /opt/nmapper/
    if (INSTALL_DIR / "main.py").exists():
        return INSTALL_DIR
    # Script dans installation/ → python-api est un niveau au-dessus
    candidate = Path(__file__).parent.parent / "python-api"
    if candidate.exists():
        return candidate
    print(_r("❌ python-api/ introuvable. Lancez depuis le dossier NMAPPER ou installez avec --install."))
    sys.exit(1)

# ── Couleurs terminal ─────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t
_g  = lambda t: _c("32;1", t)
_cy = lambda t: _c("36;1", t)
_y  = lambda t: _c("33;1", t)
_r  = lambda t: _c("31;1", t)
_d  = lambda t: _c("2",    t)
_b  = lambda t: _c("1",    t)

REQUIRED_PACKAGES = [
    "fastapi", "uvicorn[standard]", "slowapi", "bcrypt",
    "pyotp", "qrcode[pil]", "pillow", "python-multipart",
    "pydantic", "starlette", "paramiko",
]


# ── Utilitaires ───────────────────────────────────────────────────────────────

def _check_python():
    v = sys.version_info
    if v < (3, 9):
        print(_r(f"❌ Python 3.9+ requis (actuel : {v.major}.{v.minor})"))
        sys.exit(1)
    print(_g(f"✅ Python {v.major}.{v.minor}.{v.micro}"))


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"


VENV_DIR = INSTALL_DIR / "venv"
VENV_PYTHON = VENV_DIR / "bin" / "python3"
VENV_PIP    = VENV_DIR / "bin" / "pip"


def _create_venv():
    """Crée le virtualenv dans /opt/nmapper/venv/ si absent ou incomplet."""
    if VENV_PYTHON.exists() and VENV_PIP.exists():
        print(_g("✅ Virtualenv déjà présent"))
        return
    # Venv incomplet ou absent — supprimer et recréer
    if VENV_DIR.exists():
        print(_y("⚠  Virtualenv incomplet — suppression et recréation…"))
        import shutil as _shutil
        _shutil.rmtree(VENV_DIR)
    print(f"   Création du virtualenv dans {VENV_DIR} …")
    # --without-pip évite l'erreur sur Debian 13 / Python 3.13
    r = subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(VENV_DIR)],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(_r("❌ Erreur venv :")); print(r.stderr or r.stdout); sys.exit(1)

    # Bootstrap pip : ensurepip d'abord, fallback get-pip.py si absent
    r2 = subprocess.run(
        [str(VENV_PYTHON), "-m", "ensurepip", "--upgrade"],
        capture_output=True, text=True
    )
    if r2.returncode != 0:
        print(_y("⚠  ensurepip indisponible — téléchargement de get-pip.py…"))
        import urllib.request, tempfile
        get_pip = Path(tempfile.mktemp(suffix=".py"))
        try:
            urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", str(get_pip))
            r3 = subprocess.run([str(VENV_PYTHON), str(get_pip)], capture_output=True, text=True)
            if r3.returncode != 0:
                print(_r("❌ get-pip.py échoué :")); print(r3.stderr or r3.stdout); sys.exit(1)
        finally:
            get_pip.unlink(missing_ok=True)

    # Mise à jour pip
    subprocess.run([str(VENV_PYTHON), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
                   capture_output=True)
    print(_g(f"✅ Virtualenv créé → {VENV_DIR}"))


def _pip_install():
    print(f"\n{_b('📦 Installation des dépendances Python…')}")
    _create_venv()
    # Utilise python -m pip (fonctionne même si pip/pip3 n'est pas dans le PATH)
    cmd = [str(VENV_PYTHON), "-m", "pip", "install", "--quiet"] + REQUIRED_PACKAGES
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(_r("❌ Erreur pip :")); print(r.stderr); sys.exit(1)
    print(_g("✅ Dépendances installées dans le virtualenv"))


def _check_packages() -> bool:
    if not VENV_PYTHON.exists():
        return False
    r = subprocess.run([str(VENV_PYTHON), "-c", "import uvicorn, fastapi"], capture_output=True)
    return r.returncode == 0


def _get_or_create_key(scans_dir: Path) -> str:
    key_file = scans_dir / ".apikey"
    if key_file.exists():
        key = key_file.read_text().strip()
        if key:
            return key
    import secrets
    key = secrets.token_urlsafe(32)
    scans_dir.mkdir(parents=True, exist_ok=True)
    key_file.write_text(key)
    key_file.chmod(0o600)
    return key


def _print_key(key: str, scans_dir: Path, port: int = DEFAULT_PORT):
    local_ip = _get_local_ip()
    print(f"\n{'─'*58}")
    print(_cy(_b("  🔑  CLÉ API AGENT")))
    print(f"{'─'*58}")
    print(f"  {_y(key)}")
    print(f"{'─'*58}")
    print(_d(f"  Fichier : {scans_dir / '.apikey'}"))
    print()
    print(_b("  Commande prête à copier sur chaque machine à surveiller :"))
    print(f"  {_g('sudo python3 installation/install-agent.py')} \\")
    print(f"      {_y(f'--server-ip {local_ip}')} \\")
    print(f"      {_y(f'--port {port}')} \\")
    print(f"      {_y(f'--key {key}')}")
    print()


def _print_usage(host: str, port: int, key: str, api_dir: Path):
    local_ip  = _get_local_ip()
    disp_host = local_ip if host == "0.0.0.0" else host

    print(f"\n{'─'*58}")
    print(_cy(_b("  🌐  SERVEUR NMAPPER DÉMARRÉ")))
    print(f"{'─'*58}")
    print(f"  Répertoire : {_g(str(api_dir))}")
    print(f"  Adresse    : {_g(f'http://{disp_host}:{port}')}")
    print(f"  API        : {_g(f'http://{disp_host}:{port}/scanner-api')}")
    print(f"{'─'*58}")
    print(f"\n{_b('  Pour connecter un agent — copiez cette commande sur chaque machine :')}")
    print(f"  {_g('sudo python3 installation/install-agent.py')} \\")
    print(f"      {_y(f'--server-ip {disp_host}')} \\")
    print(f"      {_y(f'--port {port}')} \\")
    print(f"      {_y(f'--key {key}')}")
    print(f"\n  {_d('Ctrl+C pour arrêter le serveur')}\n")


# ── Installation dans /opt/nmapper/ ──────────────────────────────────────────

def do_install(host: str, port: int):
    """Copie les fichiers dans /opt/nmapper/ et crée le service systemd."""
    print(f"\n{_b('═'*50)}")
    print(_cy(_b("  NMAPPER — Installation serveur")))
    print(f"{_b('═'*50)}\n")

    # 1. Droits root
    if os.geteuid() != 0:
        print(_r("❌ Droits root requis."))
        print(_d("   Relancez avec : sudo python3 installation/server.py --install"))
        sys.exit(1)

    # 2. Trouver les sources python-api/
    candidates = [
        Path(__file__).parent.parent / "python-api",  # installation/../python-api
        Path.cwd() / "python-api",                     # répertoire courant
        Path(__file__).parent / "python-api",          # installation/python-api
        Path("/opt/nmapper_src/python-api"),           # chemin absolu courant
    ]
    src_api = next((p for p in candidates if p.exists()), None)
    if src_api is None:
        print(_r(f"❌ Sources introuvables. Chemins testés :"))
        for p in candidates:
            print(_d(f"   - {p}"))
        print(_d("   Assurez-vous que le dossier python-api/ est dans le projet."))
        sys.exit(1)
    print(_g(f"  Sources trouvées : {src_api}"))

    # 3. Créer /opt/nmapper/python-api/ (structure attendue par le code)
    print(f"{_b('1. Copie des fichiers dans')} {_g(str(API_SUBDIR))}")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    API_SUBDIR.mkdir(parents=True, exist_ok=True)
    os.chmod(INSTALL_DIR, 0o755)

    # Nettoyer les anciens fichiers à plat dans /opt/nmapper/ si présents
    for old in INSTALL_DIR.glob("*.py"):
        old.unlink(missing_ok=True)

    for f in src_api.glob("*.py"):
        shutil.copy2(f, API_SUBDIR / f.name)
        print(_g(f"  ✅ {f.name}"))

    # Scripts shell
    for f in src_api.glob("*.sh"):
        shutil.copy2(f, API_SUBDIR / f.name)
        os.chmod(API_SUBDIR / f.name, 0o755)

    # Répertoire de scans (python-api/scans/ → chemin attendu par main.py)
    scans_dir = API_SUBDIR / "scans"
    scans_dir.mkdir(exist_ok=True)
    os.chmod(scans_dir, 0o700)
    print(_g(f"  ✅ scans/ créé → {scans_dir}"))

    # Copie du dossier installation/ (agent.py, install-agent.py)
    # Requis par deploy.py pour envoyer agent.py sur les machines cibles
    install_src = Path(__file__).parent
    install_dst = INSTALL_DIR / "installation"
    install_dst.mkdir(exist_ok=True)
    for f in install_src.glob("*.py"):
        shutil.copy2(f, install_dst / f.name)
    for f in install_src.glob("*.sh"):
        shutil.copy2(f, install_dst / f.name)
        os.chmod(install_dst / f.name, 0o755)
    print(_g(f"  ✅ installation/ copié → {install_dst}"))

    # 4. Dépendances
    print(f"\n{_b('2. Dépendances')}")
    if _check_packages():
        print(_g("✅ Dépendances déjà installées"))
    else:
        _pip_install()

    # 5. Clé API
    print(f"\n{_b('3. Clé API')}")
    key = _get_or_create_key(scans_dir)
    print(_g("✅ Clé API générée/chargée"))
    _print_key(key, scans_dir, port)

    # 6. Service systemd
    print(f"{_b('4. Service systemd')}")
    unit = f"""[Unit]
Description=NMAPPER Backend API
After=network.target

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={VENV_PYTHON} -m uvicorn main:asgi_app --host {host} --port {port} --app-dir {API_SUBDIR}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    SERVICE_FILE.write_text(unit)
    print(_g(f"  ✅ Service écrit → {SERVICE_FILE}"))

    for cmd in [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", SERVICE_NAME],
        ["systemctl", "start",  SERVICE_NAME],
    ]:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            print(_r(f"  ❌ {' '.join(cmd)}")); print(r.stderr.decode())
            sys.exit(1)
        print(_g(f"  ✅ {' '.join(cmd)}"))

    # 7. Résumé
    local_ip = _get_local_ip()
    disp     = local_ip if host == "0.0.0.0" else host
    print(f"\n{'═'*58}")
    print(_cy(_b("  ✅  NMAPPER SERVEUR INSTALLÉ")))
    print(f"{'═'*58}")
    print(f"  Répertoire : {_g(str(INSTALL_DIR))}")
    print(f"  API        : {_g(f'http://{disp}/scanner-api')}")
    print(f"  Clé API    : {_y(key)}")
    print(f"\n{_d('  Commandes utiles :')}")
    print(_d(f"    sudo systemctl status {SERVICE_NAME}"))
    print(_d(f"    sudo journalctl -u {SERVICE_NAME} -f"))
    print(_d(f"    sudo systemctl restart {SERVICE_NAME}"))
    print(f"{'═'*58}\n")


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NMAPPER — Setup et démarrage du serveur backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",         default=DEFAULT_HOST)
    parser.add_argument("--port",         type=int, default=DEFAULT_PORT)
    parser.add_argument("--key-only",     action="store_true",
                        help="Afficher la clé API et quitter")
    parser.add_argument("--install-only", action="store_true",
                        help="Installer les dépendances pip et quitter")
    parser.add_argument("--install",      action="store_true",
                        help="Copier dans /opt/nmapper/ et créer le service systemd")
    args = parser.parse_args()

    # ── Mode installation complète (/opt/nmapper/ + systemd)
    if args.install:
        do_install(args.host, args.port)
        return

    # ── Mode démarrage rapide (test local / Replit)
    print(f"\n{_b('═══════════════════════════════')}")
    print(_cy(_b("   NMAPPER — Démarrage serveur")))
    print(f"{_b('═══════════════════════════════')}\n")

    print(_b("1. Système"))
    _check_python()
    print(_g(f"✅ OS : {platform.system()} {platform.release()}"))

    print(f"\n{_b('2. Dépendances')}")
    if _check_packages():
        print(_g("✅ Dépendances déjà installées"))
    else:
        _pip_install()

    api_dir   = _find_api_dir()
    scans_dir = api_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    print(_g(f"✅ Répertoire : {api_dir}"))

    print(f"\n{_b('3. Clé API')}")
    key = _get_or_create_key(scans_dir)
    print(_g("✅ Clé API chargée/générée"))
    _print_key(key, scans_dir, args.port)

    if args.key_only or args.install_only:
        sys.exit(0)

    print(_b("4. Démarrage\n"))
    _print_usage(args.host, args.port, key, api_dir)

    os.environ["PORT"] = str(args.port)

    try:
        import uvicorn
    except ImportError:
        print(_r("❌ uvicorn non installé")); sys.exit(1)

    uvicorn.run(
        "main:asgi_app",
        app_dir=str(api_dir),
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
