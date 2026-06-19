#!/usr/bin/env python3
"""
NMAPPER — Script d'installation de l'agent de collecte
Exécuter UNE SEULE FOIS sur chaque machine à surveiller.

Usage :
    python3 installation/install-agent.py
    sudo python3 installation/install-agent.py   # avec création du service systemd
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── Couleurs terminal ─────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t
G  = lambda t: _c("32;1", t)   # green
C  = lambda t: _c("36;1", t)   # cyan
Y  = lambda t: _c("33;1", t)   # yellow
R  = lambda t: _c("31;1", t)   # red
DIM= lambda t: _c("2",    t)
B  = lambda t: _c("1",    t)   # bold

AGENT_DEST  = Path("/opt/nmapper-agent")
AGENT_PY    = AGENT_DEST / "agent.py"
CONFIG_FILE = AGENT_DEST / "config.json"
SERVICE_NAME= "nmapper-agent"
SERVICE_FILE= Path(f"/etc/systemd/system/{SERVICE_NAME}.service")


# ── Helpers ───────────────────────────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt}{hint} : ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(0)
    return val if val else default


def ask_yes(prompt: str, default: bool = True) -> bool:
    hint = "O/n" if default else "o/N"
    raw = ask(f"{prompt} ({hint})")
    if not raw:
        return default
    return raw.lower() in ("o", "y", "oui", "yes")


def hr(char="─", n=58):
    print(char * n)


def section(title: str):
    print()
    hr()
    print(C(B(f"  {title}")))
    hr()


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return socket.gethostname()


# ── Étapes d'installation ─────────────────────────────────────────────────────

def step_server(preset_ip: str = "", preset_port: int = 0) -> tuple[str, int]:
    """Demande l'adresse du serveur NMAPPER (préremplie si passée en argument)."""
    section("1/5  Adresse du serveur NMAPPER")
    print(DIM("  Entrez l'IP ou le nom d'hôte du serveur qui fait tourner NMAPPER."))
    if preset_ip:
        print(DIM(f"  (pré-rempli depuis la ligne de commande)"))
    print()

    default_ip = preset_ip or ""
    server_ip = ask("IP / hostname du serveur", default_ip)
    while not server_ip:
        print(R("  ⚠  Champ obligatoire."))
        server_ip = ask("IP / hostname du serveur", default_ip)

    default_port = str(preset_port) if preset_port else "25774"
    port = ask("Port du serveur", default_port)
    try:
        port = int(port)
    except ValueError:
        port = preset_port or 25774

    url = f"http://{server_ip}:{port}/scanner-api"
    print(f"\n  URL détectée : {Y(url)}")
    return server_ip, port


def step_key(server_ip: str, port: int, preset_key: str = "") -> str:
    """Demande la clé API / licence (préremplie si passée en argument)."""
    section("2/5  Clé API (licence)")
    print(DIM("  Récupérez la clé en lançant sur le serveur :"))
    print(DIM(f"      python3 installation/server.py --key-only"))
    print(DIM(f"  ou en lisant : python-api/scans/.apikey"))
    if preset_key:
        print(DIM(f"  (pré-remplie depuis la ligne de commande)"))
    print()

    key = ask("Clé API", preset_key)
    while not key:
        print(R("  ⚠  Clé obligatoire."))
        key = ask("Clé API", preset_key)

    # Test de connexion
    print(f"\n  Test de connexion vers {Y(f'http://{server_ip}:{port}/scanner-api')} …")
    ok = _test_connection(server_ip, port, key)
    if ok:
        print(G("  ✅ Connexion réussie — clé valide !"))
    else:
        print(Y("  ⚠  Connexion échouée (serveur injoignable ou clé incorrecte)."))
        if not ask_yes("  Continuer quand même l'installation ?", default=False):
            print(R("\nInstallation annulée."))
            sys.exit(1)

    return key


_CRITICALITY_INTERVALS = {
    "critical": (30 * 60,     "30 min  — DC, firewall, serveur de prod"),
    "high":     (60 * 60,     "1 h     — serveur applicatif, base de données"),
    "normal":   (3 * 60 * 60, "3 h     — serveur secondaire, NAS"),
    "low":      (6 * 60 * 60, "6 h     — poste de travail, imprimante"),
}


def step_options() -> dict:
    """Demande les options de collecte."""
    section("3/5  Criticité & options")

    print(DIM("  La criticité détermine la fréquence de scan et de peer-probe."))
    print(DIM("  Plus l'agent est critique, plus il est scanné souvent."))
    print()
    for i, (k, (secs, desc)) in enumerate(_CRITICALITY_INTERVALS.items(), 1):
        print(f"    {Y(str(i))}  {B(k):12s}  {DIM(desc)}")
    print()

    choice = ask("Criticité [1-4]", "3")
    criticality_keys = list(_CRITICALITY_INTERVALS.keys())
    try:
        criticality = criticality_keys[int(choice) - 1]
    except (ValueError, IndexError):
        criticality = "normal"

    interval_secs, desc = _CRITICALITY_INTERVALS[criticality]
    h, rem = divmod(interval_secs, 3600)
    m = rem // 60
    interval_str = f"{h}h{m:02d}m" if h else f"{m}min"
    print(f"\n  Criticité : {G(criticality)}  →  scan toutes les {Y(interval_str)}")

    verbose = ask_yes("\n  Mode verbose dans les logs systemd ?", default=False)

    return {"criticality": criticality, "interval": interval_secs, "verbose": verbose}


def step_copy(server_ip: str, port: int, key: str, opts: dict):
    """Copie agent.py et crée la configuration."""
    section("4/5  Copie des fichiers")

    # Trouver agent.py — cherche dans installation/ en premier (même dossier),
    # puis python-api/ (projet complet), puis déjà installé
    candidates = [
        Path(__file__).parent / "agent.py",                           # installation/agent.py
        Path(__file__).parent.parent / "python-api" / "agent.py",     # python-api/agent.py
        Path("/opt/nmapper-agent/agent.py"),                           # déjà installé
    ]
    src = next((p for p in candidates if p.exists()), None)

    if src is None:
        print(R("  ❌ agent.py introuvable."))
        print(DIM("  Assurez-vous que agent.py est dans le dossier installation/."))
        sys.exit(1)

    print(DIM(f"  Source : {src}"))

    # Créer le répertoire de destination
    AGENT_DEST.mkdir(parents=True, exist_ok=True)
    os.chmod(AGENT_DEST, 0o755)

    # Copier agent.py
    import shutil
    shutil.copy2(src, AGENT_PY)
    os.chmod(AGENT_PY, 0o755)
    print(G(f"  ✅ agent.py copié → {AGENT_PY}"))

    # Écrire la configuration
    cfg = {
        "server_ip":   server_ip,
        "port":        port,
        "key":         key,
        "criticality": opts.get("criticality", "normal"),
        "interval":    opts["interval"],
        "verbose":     opts["verbose"],
    }
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    os.chmod(CONFIG_FILE, 0o600)
    print(G(f"  ✅ Config sauvegardée → {CONFIG_FILE}"))


def step_systemd(server_ip: str, port: int, key: str, opts: dict) -> bool:
    """Crée et active le service systemd."""
    section("5/5  Service systemd")

    if not ask_yes("  Créer un service systemd (démarrage automatique) ?", default=True):
        print(DIM("  Service ignoré — lancement manuel :"))
        print(DIM(f"    python3 {AGENT_PY} --server-ip {server_ip} --port {port} --key <clé> --interval {opts['interval']}"))
        return False

    if os.geteuid() != 0:
        print(R("  ⚠  Droits root requis pour écrire dans /etc/systemd/system/."))
        print(DIM("  Relancez avec : sudo python3 installation/install-agent.py"))
        print(DIM(f"\n  Ou installez le service manuellement :"))
        _print_manual_service(server_ip, port, key, opts)
        return False

    verbose_flag = " --verbose" if opts["verbose"] else ""
    criticality  = opts.get("criticality", "normal")
    unit = f"""[Unit]
Description=NMAPPER Agent de collecte ({criticality})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={sys.executable} {AGENT_PY} \\
    --server-ip {server_ip} \\
    --port {port} \\
    --key {key} \\
    --criticality {criticality}{verbose_flag}
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    SERVICE_FILE.write_text(unit)
    print(G(f"  ✅ Service écrit → {SERVICE_FILE}"))

    # Activation
    cmds = [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", SERVICE_NAME],
        ["systemctl", "start",  SERVICE_NAME],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            print(R(f"  ❌ Erreur : {' '.join(cmd)}"))
            print(r.stderr.decode())
            return False
        print(G(f"  ✅ {' '.join(cmd)}"))

    return True


def _print_manual_service(server_ip, port, key, opts):
    verbose_flag = " --verbose" if opts["verbose"] else ""
    print(f"""
  Contenu de /etc/systemd/system/nmapper-agent.service :

  [Unit]
  Description=NMAPPER Agent de collecte
  After=network-online.target

  [Service]
  ExecStart={sys.executable} {AGENT_PY} \\
      --server-ip {server_ip} --port {port} \\
      --key {key} --interval {opts['interval']}{verbose_flag}
  Restart=always
  RestartSec=15

  [Install]
  WantedBy=multi-user.target

  Puis :
    sudo systemctl daemon-reload
    sudo systemctl enable --now nmapper-agent""")


def _test_connection(server_ip: str, port: int, key: str) -> bool:
    """Envoie un ping de test vers /monitor/push."""
    url = f"http://{server_ip}:{port}/scanner-api/monitor/push"
    payload = json.dumps({
        "agent_id": "install-test",
        "agent_hostname": platform.node(),
        "hosts": [],
    }).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "X-Agent-Key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            return True
    except urllib.error.HTTPError as e:
        return e.code not in (401, 403)   # 422 = payload vide = connexion OK quand même
    except Exception:
        return False


# ── Résumé final ──────────────────────────────────────────────────────────────

def summary(server_ip: str, port: int, opts: dict, systemd_ok: bool):
    print()
    hr("═")
    print(C(B("  ✅  NMAPPER AGENT INSTALLÉ")))
    hr("═")
    print(f"  Machine   : {G(platform.node())}  ({_get_local_ip()})")
    print(f"  Serveur   : {G(f'http://{server_ip}:{port}/scanner-api')}")
    print(f"  Intervalle: {G(str(opts['interval']) + 's')}")
    print(f"  Config    : {G(str(CONFIG_FILE))}")

    if systemd_ok:
        print(f"\n  Service systemd : {G('actif et activé au démarrage')}")
        print(DIM(f"\n  Commandes utiles :"))
        print(DIM(f"    sudo systemctl status {SERVICE_NAME}"))
        print(DIM(f"    sudo journalctl -u {SERVICE_NAME} -f"))
        print(DIM(f"    sudo systemctl stop {SERVICE_NAME}"))
    else:
        print(f"\n  {Y('Lancement manuel :')} python3 {AGENT_PY} \\")
        print(f"    --server-ip {server_ip} --port {port} \\")
        print(f"    --key <clé> --interval {opts['interval']}")

    hr("═")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="NMAPPER — Installation de l'agent de collecte",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python3 install-agent.py\n"
            "  sudo python3 install-agent.py --server-ip 10.0.0.10 --key abc123\n"
            "  sudo python3 install-agent.py --server-ip 10.0.0.10 --port 25774 --key abc123\n"
        ),
    )
    p.add_argument("--server-ip", default="",
                   help="IP ou hostname du serveur NMAPPER (pré-rempli dans le wizard)")
    p.add_argument("--port", type=int, default=0,
                   help="Port du serveur NMAPPER (défaut: 25774)")
    p.add_argument("--key", default="",
                   help="Clé API (pré-remplie dans le wizard)")
    return p.parse_args()


def main():
    args = _parse_args()

    print()
    hr("═")
    print(C(B("   NMAPPER — Installation de l'agent de collecte")))
    hr("═")
    print(DIM(f"  Machine : {platform.node()} | OS : {platform.system()} {platform.release()}"))
    print(DIM("  Ce script configure l'agent qui envoie des données à NMAPPER."))
    if args.server_ip:
        print(DIM(f"  Serveur cible : {args.server_ip}:{args.port or 25774}"))

    server_ip, port = step_server(preset_ip=args.server_ip, preset_port=args.port)
    key             = step_key(server_ip, port, preset_key=args.key)
    opts            = step_options()
    step_copy(server_ip, port, key, opts)
    systemd_ok      = step_systemd(server_ip, port, key, opts)
    summary(server_ip, port, opts, systemd_ok)


if __name__ == "__main__":
    main()
