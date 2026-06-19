#!/usr/bin/env python3
"""
NMAPPER Agent de collecte — v2.0
Déployer sur n'importe quelle machine du réseau cible.

L'agent :
  1. Scanne ses propres ports (auto-rapport)
  2. Sonde les agents pairs connus (uniquement leurs ports déclarés)
  3. Envoie la matrice de connectivité au serveur

Usage :
    python3 agent.py --server-ip 192.168.1.10 --key YOUR_KEY
    python3 agent.py --server-ip 192.168.1.10 --key KEY --criticality high
    python3 agent.py --server https://mon-nmapper.repl.co/scanner-api --key KEY --once
"""

import argparse
import json
import platform
import random
import socket
import sys
import threading
import time
import uuid
import urllib.request
import urllib.error
import concurrent.futures
import ipaddress

# ── Criticité → intervalle (secondes) ─────────────────────────────────────────
CRITICALITY_INTERVALS = {
    "critical": 5,   # 5 s
    "high":     5,   # 5 s
    "normal":   5,   # 5 s
    "low":      5,   # 5 s
}

# Jitter de démarrage par criticité (min, max) en secondes
# Évite que tous les agents démarrent en même temps après un reboot réseau
CRITICALITY_JITTER = {
    "critical": (0,  0),
    "high":     (0,  5),
    "normal":   (0, 10),
    "low":      (0, 30),
}

# ── Ports scannés sur soi-même (auto-rapport) ─────────────────────────────────
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
    443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 27017,
]

# Ports considérés à risque élevé
RISKY_PORTS = {21, 23, 69, 79, 161, 162, 502, 102, 44818, 47808, 20000}

# Identifiant stable de cet agent (basé sur l'adresse MAC)
AGENT_ID = str(uuid.UUID(int=uuid.getnode()))

# Verrou global : empêche deux cycles de tourner en même temps
_scan_lock = threading.Lock()


# ── Collecte locale ───────────────────────────────────────────────────────────

def get_local_ips() -> list[str]:
    """Retourne la liste des IPs locales IPv4 (hors loopback)."""
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
                if ip.version == 4 and not ip.is_loopback:
                    ips.append(str(ip))
            except ValueError:
                pass
    except Exception:
        pass

    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass

    return list(set(ips))


def detect_vlan(ip: str) -> str:
    """Infère le VLAN depuis l'IP (convention 10.x.VLAN.host etc.)."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            if parts[0] == "10":
                return "VLAN" + parts[2]
            if parts[0] == "192" and parts[1] == "168":
                return "VLAN" + parts[2]
            a, b = int(parts[0]), int(parts[1])
            if a == 172 and 16 <= b <= 31:
                return "VLAN" + parts[2]
    except Exception:
        pass
    return "Unknown"


def _guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        known = {
            80: "http", 443: "https", 22: "ssh", 21: "ftp", 23: "telnet",
            25: "smtp", 53: "dns", 3306: "mysql", 5432: "postgresql",
            1433: "mssql", 3389: "rdp", 6379: "redis", 27017: "mongodb",
            8080: "http-alt", 8443: "https-alt", 5900: "vnc",
        }
        return known.get(port, "unknown")


def _scan_port_fast(host: str, port: int, timeout: float = 0.5):
    """TCP connect rapide — utilisé pour l'auto-scan local."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "state": "open",
                    "service": _guess_service(port), "version": ""}
    except (ConnectionRefusedError, OSError):
        return None


def scan_host_self(ip: str) -> list:
    """
    Scanne les ports de la machine locale.
    Utilise un pool de threads car c'est sur soi-même → sans impact réseau.
    """
    results: list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_scan_port_fast, ip, p, 0.5): p for p in SCAN_PORTS}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
    results.sort(key=lambda x: x["port"])
    return results


def get_arp_hosts() -> list[str]:
    """Lit /proc/net/arp et retourne les IPs des voisins ARP actifs."""
    ips: list[str] = []
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, flags, mac = parts[0], parts[2], parts[3]
                if mac in ("00:00:00:00:00:00", "") or flags == "0x0":
                    continue
                ips.append(ip)
    except FileNotFoundError:
        pass
    return ips


def collect_host_data(verbose=False) -> list:
    """
    Auto-scan : collecte la machine locale + voisins ARP.
    Les voisins ARP sont scannés avec un pool réduit (max 4 threads) pour
    ne pas générer de trafic excessif sur le réseau.
    """
    local_ips = get_local_ips()
    hostname  = platform.node()
    hosts: list = []
    seen: set[str] = set()

    def _make_host(ip: str, h_name: str, is_local: bool) -> dict:
        if verbose:
            print(f"  Scan de {ip} {'(local)' if is_local else '(ARP)'} …", flush=True)
        if is_local:
            # Auto-scan : threads libres, c'est sur soi-même
            ports = scan_host_self(ip)
        else:
            # Voisin ARP : parallélisme limité à 4 threads, timeout plus long
            results: list = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futures = {ex.submit(_scan_port_fast, ip, p, 1.0): p for p in SCAN_PORTS}
                for fut in concurrent.futures.as_completed(futures):
                    r = fut.result()
                    if r:
                        results.append(r)
            results.sort(key=lambda x: x["port"])
            ports = results
        vlan = detect_vlan(ip)
        open_port_nums = {p["port"] for p in ports}
        return {
            "ip":       ip,
            "hostname": h_name,
            "vlan":     vlan,
            "ports":    ports,
            "os":       platform.system() + " " + platform.release(),
            "agent_id": AGENT_ID,
            "vulnerable": bool(open_port_nums & RISKY_PORTS),
        }

    for ip in local_ips:
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(_make_host(ip, hostname, is_local=True))

    for ip in get_arp_hosts():
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(_make_host(ip, "", is_local=False))

    return hosts


# ── Peer-probe (connectivité inter-agents) ─────────────────────────────────────
#
# Anti-DDOS / anti-surcharge :
#   - Probes SÉQUENTIELLES : jamais de parallélisme vers une machine externe
#   - Timeout : 1,5 s par port — connexion refusée = abandon immédiat
#   - Délai inter-port : 150–400 ms aléatoire
#   - Délai inter-peer : 500 ms–1,2 s aléatoire
#   - Max 10 peers par cycle (priorisés par last_seen)
#   - On ne teste QUE les ports déjà déclarés par le peer (zéro blind scan)
#   - On skip ses propres IPs

def _probe_one_port(ip: str, port: int) -> bool:
    """
    Tente une connexion TCP unique sur (ip, port).
    Retourne True si joignable, False sinon.
    Timeout court : 1,5 s. Connexion refusée = False immédiat.
    """
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def probe_peer_agents(server_url: str, api_key: str,
                      criticality: str = "normal", verbose=False) -> dict:
    """
    Récupère la liste des agents connus depuis /monitor/hosts puis sonde
    séquentiellement leurs ports déclarés.

    Retourne un dict :
      { peer_ip: { port: True/False, ... }, ... }
    """
    my_ips = set(get_local_ips())
    result: dict = {}

    # 1. Récupérer la liste des peers connus
    try:
        url = server_url.rstrip("/") + "/monitor/hosts"
        req = urllib.request.Request(url, headers={"X-Agent-Key": api_key})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        if verbose:
            print(f"  ⚠  probe_peers: impossible de récupérer /monitor/hosts — {e}", flush=True)
        return {}

    all_hosts = data.get("hosts", [])

    # 2. Filtrer : exclure soi-même + hôtes sans ports déclarés
    #    Prioriser par last_seen (les plus récents d'abord)
    peers = [
        h for h in all_hosts
        if h.get("ip") not in my_ips and h.get("ports")
    ]
    peers.sort(key=lambda h: h.get("last_seen", 0), reverse=True)
    peers = peers[:10]  # Max 10 peers par cycle

    if not peers and verbose:
        print("  ℹ  Aucun peer connu à sonder.", flush=True)
        return {}

    if verbose:
        print(f"  🔍 Sondage de {len(peers)} peer(s)…", flush=True)

    # 3. Sonde séquentielle
    for peer in peers:
        peer_ip    = peer["ip"]
        open_ports = [p["port"] for p in peer["ports"] if p.get("state") == "open"]
        if not open_ports:
            continue

        port_results: dict = {}
        for port in open_ports:
            reachable = _probe_one_port(peer_ip, port)
            port_results[port] = reachable
            if verbose:
                icon = "✅" if reachable else "🔒"
                print(f"    {icon} {peer_ip}:{port}", flush=True)
            # Délai inter-port : 150–400 ms (aléatoire pour lisser le trafic)
            time.sleep(random.uniform(0.15, 0.40))

        result[peer_ip] = port_results
        # Délai inter-peer : 500 ms–1,2 s
        time.sleep(random.uniform(0.50, 1.20))

    return result


# ── Envoi vers NMAPPER ─────────────────────────────────────────────────────────

def push_to_server(server_url: str, api_key: str, hosts: list,
                   criticality: str = "normal", verbose=False) -> bool:
    """Envoie les données d'auto-scan vers /monitor/push."""
    url     = server_url.rstrip("/") + "/monitor/push"
    payload = json.dumps({
        "agent_id":       AGENT_ID,
        "agent_hostname": platform.node(),
        "criticality":    criticality,
        "hosts":          hosts,
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "X-Agent-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            if verbose:
                print(f"  ✅ Push hosts : {body}", flush=True)
            return True
    except urllib.error.HTTPError as e:
        print(f"  ❌ HTTP {e.code} : {e.read().decode()}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"  ❌ Connexion impossible ({url}) : {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"  ❌ Erreur inattendue : {e}", file=sys.stderr)
    return False


def push_connectivity(server_url: str, api_key: str, matrix: dict,
                      verbose=False) -> bool:
    """Envoie la matrice de connectivité vers /monitor/connectivity."""
    if not matrix:
        return True
    url     = server_url.rstrip("/") + "/monitor/connectivity"
    payload = json.dumps({
        "from_agent": AGENT_ID,
        "from_ip":    (get_local_ips() or ["unknown"])[0],
        "matrix":     matrix,
        "ts":         time.time(),
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "X-Agent-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            if verbose:
                print(f"  ✅ Push connectivity : {body}", flush=True)
            return True
    except Exception as e:
        if verbose:
            print(f"  ⚠  push_connectivity : {e}", flush=True)
    return False


# ── Cycle complet ──────────────────────────────────────────────────────────────

def run_cycle(server_url: str, api_key: str,
              criticality: str = "normal", verbose=False) -> None:
    """
    Un cycle complet : auto-scan + peer-probe.
    Protégé par un verrou — si le cycle précédent n'est pas terminé, on skip.
    """
    if not _scan_lock.acquire(blocking=False):
        print("  ⏭  Cycle précédent encore en cours — skip.", flush=True)
        return
    try:
        # ── Auto-scan ────────────────────────────────────────────────────────
        print(f"[{time.strftime('%H:%M:%S')}] Auto-scan…", flush=True)
        hosts      = collect_host_data(verbose=verbose)
        open_total = sum(len(h["ports"]) for h in hosts)
        vuln_total = sum(1 for h in hosts if h["vulnerable"])
        print(f"  {len(hosts)} hôte(s) | {open_total} port(s) | {vuln_total} vulnérable(s)")
        push_to_server(server_url, api_key, hosts, criticality, verbose)

        # ── Liens ARP (voisins ayant communiqué au niveau L2) ────────────────
        arp_neighbors = get_arp_hosts()
        local_ips     = get_local_ips()
        arp_matrix    = {
            ip: {0: True}           # port 0 = marqueur "vu dans la table ARP"
            for ip in arp_neighbors
            if ip not in local_ips  # exclure ses propres IPs
        }
        if arp_matrix:
            print(f"  {len(arp_matrix)} voisin(s) ARP détecté(s) → push connectivité")
            push_connectivity(server_url, api_key, arp_matrix, verbose)

        # ── Peer-probe ───────────────────────────────────────────────────────
        print(f"[{time.strftime('%H:%M:%S')}] Peer-probe…", flush=True)
        matrix = probe_peer_agents(server_url, api_key, criticality, verbose)
        if matrix:
            reachable = sum(v for ports in matrix.values() for v in ports.values())
            total     = sum(len(ports) for ports in matrix.values())
            print(f"  {len(matrix)} peer(s) sondé(s) | {reachable}/{total} port(s) joignables")
            push_connectivity(server_url, api_key, matrix, verbose)
        else:
            print("  Aucun peer à sonder.")
    finally:
        _scan_lock.release()


# ── Point d'entrée ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NMAPPER Agent de collecte v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--server-ip", metavar="IP",
                     help="IP du serveur NMAPPER — ex: 192.168.1.10")
    src.add_argument("--server",    metavar="URL",
                     help="URL complète — ex: https://mon-nmapper.repl.co/scanner-api")

    parser.add_argument("--port",        type=int, default=25774,
                        help="Port du serveur si --server-ip (défaut: 25774)")
    parser.add_argument("--key",         required=True,
                        help="Clé API NMAPPER")
    parser.add_argument("--criticality", default="normal",
                        choices=["critical", "high", "normal", "low"],
                        help="Criticité de cet agent (définit l'intervalle de scan)")
    parser.add_argument("--interval",    type=int, default=None,
                        help="Override manuel de l'intervalle en secondes (ignoré si --criticality)")
    parser.add_argument("--once",        action="store_true",
                        help="Effectuer un seul cycle et quitter")
    parser.add_argument("--verbose",     action="store_true",
                        help="Afficher les détails")
    parser.add_argument("--no-jitter",   action="store_true",
                        help="Désactiver le jitter de démarrage (tests uniquement)")

    args = parser.parse_args()

    server_url = (f"http://{args.server_ip}:{args.port}/scanner-api"
                  if args.server_ip else args.server)

    # Intervalle : criticité ou override manuel
    interval = (args.interval if args.interval is not None
                else CRITICALITY_INTERVALS[args.criticality])

    print(f"🤖 NMAPPER Agent v2.0 — ID: {AGENT_ID}")
    print(f"   Serveur      : {server_url}")
    print(f"   Hôte         : {platform.node()}")
    print(f"   IPs          : {', '.join(get_local_ips()) or 'aucune détectée'}")
    print(f"   Criticité    : {args.criticality}")
    if not args.once:
        h, m = divmod(interval, 3600)
        m //= 60
        print(f"   Intervalle   : {interval}s ({h}h{m:02d}m)" if h else
              f"   Intervalle   : {interval}s ({interval//60}min)")
    print()

    # Jitter de démarrage (sauf --once ou --no-jitter)
    if not args.once and not args.no_jitter:
        j_min, j_max = CRITICALITY_JITTER[args.criticality]
        jitter = random.randint(j_min, j_max)
        if jitter > 0:
            print(f"  ⏱  Jitter de démarrage : {jitter}s …", flush=True)
            time.sleep(jitter)

    while True:
        run_cycle(server_url, args.key, args.criticality, args.verbose)

        if args.once:
            break

        print(f"  ⏳ Prochain cycle dans {interval}s…\n", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
