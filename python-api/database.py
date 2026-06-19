"""
NMAPPER — Couche de persistance SQLite.
Remplace les dicts/listes in-memory de main.py et le fichier JSON d'activity_log.
sqlite3 est intégré à Python, aucune dépendance supplémentaire.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

_DB_PATH = Path(__file__).parent / "scans" / "nmapper.db"
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db() -> None:
    """Crée les tables si elles n'existent pas encore et migre le schéma."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as c:
        # Migrations ALTER TABLE (idempotentes — ignorées si colonne déjà présente)
        _migrations = [
            "ALTER TABLE monitor_agents ADD COLUMN criticality TEXT DEFAULT 'normal'",
            "ALTER TABLE monitor_hosts ADD COLUMN criticality TEXT DEFAULT NULL",
        ]
        for sql in _migrations:
            try:
                c.execute(sql)
            except Exception:
                pass   # colonne déjà présente → on ignore

        c.executescript("""
            CREATE TABLE IF NOT EXISTS monitor_hosts (
                ip          TEXT PRIMARY KEY,
                hostname    TEXT DEFAULT '',
                vlan        TEXT DEFAULT '',
                os          TEXT DEFAULT '',
                ports_json  TEXT DEFAULT '[]',
                vulnerable  INTEGER DEFAULT 0,
                agent_id    TEXT DEFAULT '',
                last_seen   REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS monitor_agents (
                agent_id    TEXT PRIMARY KEY,
                hostname    TEXT DEFAULT '',
                ip          TEXT DEFAULT '',
                criticality TEXT DEFAULT 'normal',
                last_seen   REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS connectivity_matrix (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                from_agent  TEXT,
                from_ip     TEXT,
                to_ip       TEXT,
                port        INTEGER,
                reachable   INTEGER DEFAULT 0,
                ts          REAL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_conn_unique
                ON connectivity_matrix(from_agent, to_ip, port);

            CREATE TABLE IF NOT EXISTS monitor_events (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT,
                level   TEXT,
                message TEXT
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT,
                action  TEXT,
                target  TEXT,
                status  TEXT,
                detail  TEXT
            );
        """)


# ── Monitor Hosts ─────────────────────────────────────────────────────────────

def upsert_host(h: dict) -> None:
    with _lock, _conn() as c:
        c.execute("""
            INSERT INTO monitor_hosts (ip, hostname, vlan, os, ports_json, vulnerable, agent_id, last_seen)
            VALUES (:ip, :hostname, :vlan, :os, :ports_json, :vulnerable, :agent_id, :last_seen)
            ON CONFLICT(ip) DO UPDATE SET
                hostname   = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
                vlan       = excluded.vlan,
                os         = excluded.os,
                ports_json = excluded.ports_json,
                vulnerable = excluded.vulnerable,
                agent_id   = excluded.agent_id,
                last_seen  = excluded.last_seen
        """, {
            "ip":         h.get("ip", ""),
            "hostname":   h.get("hostname", ""),
            "vlan":       h.get("vlan", ""),
            "os":         h.get("os", ""),
            "ports_json": json.dumps(h.get("ports", [])),
            "vulnerable": 1 if h.get("vulnerable") else 0,
            "agent_id":   h.get("agent_id", ""),
            "last_seen":  h.get("last_seen", time.time()),
        })


def get_host(ip: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM monitor_hosts WHERE ip=?", (ip,)).fetchone()
    if not row:
        return None
    return _host_row(row)


def get_all_hosts() -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM monitor_hosts ORDER BY last_seen DESC"
        ).fetchall()
    return [_host_row(r) for r in rows]


def clear_hosts() -> None:
    with _lock, _conn() as c:
        c.execute("DELETE FROM monitor_hosts")
        c.execute("DELETE FROM monitor_agents")
        c.execute("DELETE FROM monitor_events")


def _host_row(row) -> dict:
    d = dict(row)
    d["ports"] = json.loads(d.pop("ports_json", "[]"))
    d["vulnerable"] = bool(d["vulnerable"])
    return d


# ── Monitor Agents ────────────────────────────────────────────────────────────

def upsert_agent(a: dict) -> bool:
    """Retourne True si c'est un nouvel agent."""
    with _lock, _conn() as c:
        existing = c.execute(
            "SELECT agent_id FROM monitor_agents WHERE agent_id=?", (a["agent_id"],)
        ).fetchone()
        c.execute("""
            INSERT INTO monitor_agents (agent_id, hostname, ip, criticality, last_seen)
            VALUES (:agent_id, :hostname, :ip, :criticality, :last_seen)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname    = excluded.hostname,
                ip          = excluded.ip,
                criticality = excluded.criticality,
                last_seen   = excluded.last_seen
        """, {
            "agent_id":    a.get("agent_id", ""),
            "hostname":    a.get("hostname", ""),
            "ip":          a.get("ip", ""),
            "criticality": a.get("criticality", "normal"),
            "last_seen":   a.get("last_seen", time.time()),
        })
        return existing is None


def get_all_agents() -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM monitor_agents ORDER BY last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Connectivity matrix ───────────────────────────────────────────────────────

def upsert_connectivity(from_agent: str, from_ip: str,
                        matrix: dict, ts: float) -> None:
    """
    Enregistre la matrice de connectivité d'un agent.
    matrix = { to_ip: { port: bool, ... }, ... }
    Remplace les entrées précédentes pour ce from_agent+to_ip+port.
    """
    with _lock, _conn() as c:
        for to_ip, ports in matrix.items():
            for port, reachable in ports.items():
                c.execute("""
                    INSERT INTO connectivity_matrix
                        (from_agent, from_ip, to_ip, port, reachable, ts)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(from_agent, to_ip, port) DO UPDATE SET
                        from_ip   = excluded.from_ip,
                        reachable = excluded.reachable,
                        ts        = excluded.ts
                """, (from_agent, from_ip, to_ip, int(port),
                      1 if reachable else 0, ts))


def get_connectivity(max_age_s: float = 0) -> list:
    """
    Retourne toutes les entrées de connectivité.
    Si max_age_s > 0, filtre les entrées plus anciennes que max_age_s secondes.
    """
    with _conn() as c:
        if max_age_s > 0:
            cutoff = time.time() - max_age_s
            rows = c.execute(
                "SELECT * FROM connectivity_matrix WHERE ts >= ? ORDER BY ts DESC",
                (cutoff,)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM connectivity_matrix ORDER BY ts DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def get_connectivity_summary() -> list:
    """
    Retourne un résumé agrégé par (from_ip, to_ip) :
    { from_ip, to_ip, total_ports, reachable_ports, last_ts }
    Utile pour dessiner les arêtes du graphe.
    """
    with _conn() as c:
        rows = c.execute("""
            SELECT
                from_ip,
                to_ip,
                COUNT(*) AS total_ports,
                SUM(reachable) AS reachable_ports,
                MAX(ts) AS last_ts
            FROM connectivity_matrix
            GROUP BY from_ip, to_ip
            ORDER BY last_ts DESC
        """).fetchall()
    return [dict(r) for r in rows]


# ── Monitor Events ────────────────────────────────────────────────────────────

_MAX_EVENTS = 1000


def add_event(level: str, message: str) -> None:
    ts = time.strftime("%H:%M:%S")
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO monitor_events (ts, level, message) VALUES (?,?,?)",
            (ts, level, message),
        )
        c.execute(f"""
            DELETE FROM monitor_events
            WHERE id NOT IN (
                SELECT id FROM monitor_events ORDER BY id DESC LIMIT {_MAX_EVENTS}
            )
        """)


def get_events(limit: int = 200) -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT ts, level, message FROM monitor_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"time": r["ts"], "level": r["level"], "message": r["message"]} for r in rows]


# ── Activity Logs ─────────────────────────────────────────────────────────────

_MAX_LOGS = 1000


def add_log(
    action: str,
    target: str = "",
    status: str = "info",
    detail: str = "",
) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO activity_logs (ts, action, target, status, detail) VALUES (?,?,?,?,?)",
            (ts, action[:64], (target or "")[:200], status, (detail or "")[:300]),
        )
        c.execute(f"""
            DELETE FROM activity_logs
            WHERE id NOT IN (
                SELECT id FROM activity_logs ORDER BY id DESC LIMIT {_MAX_LOGS}
            )
        """)


def get_logs(limit: int = 200, action_prefix: Optional[str] = None) -> list:
    with _conn() as c:
        if action_prefix:
            rows = c.execute(
                "SELECT * FROM activity_logs WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                (action_prefix + "%", limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def clear_logs_db() -> None:
    with _lock, _conn() as c:
        c.execute("DELETE FROM activity_logs")


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    """Agrège les KPIs monitoring pour le tableau de bord."""
    with _conn() as c:
        now = time.time()
        agents_total  = c.execute("SELECT COUNT(*) FROM monitor_agents").fetchone()[0]
        agents_online = c.execute(
            "SELECT COUNT(*) FROM monitor_agents WHERE last_seen > ?", (now - 120,)
        ).fetchone()[0]
        hosts_total = c.execute("SELECT COUNT(*) FROM monitor_hosts").fetchone()[0]
        hosts_vuln  = c.execute(
            "SELECT COUNT(*) FROM monitor_hosts WHERE vulnerable=1"
        ).fetchone()[0]
        events_total = c.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0]
        top_vuln = c.execute(
            "SELECT ip, hostname, ports_json FROM monitor_hosts "
            "WHERE vulnerable=1 ORDER BY last_seen DESC LIMIT 5"
        ).fetchall()
        recent_events = c.execute(
            "SELECT ts, level, message FROM monitor_events ORDER BY id DESC LIMIT 5"
        ).fetchall()

    return {
        "agents_total":  agents_total,
        "agents_online": agents_online,
        "hosts_total":   hosts_total,
        "hosts_vuln":    hosts_vuln,
        "events_total":  events_total,
        "top_vuln": [
            {
                "ip":       r["ip"],
                "hostname": r["hostname"],
                "ports":    len(json.loads(r["ports_json"] or "[]")),
            }
            for r in top_vuln
        ],
        "recent_events": [dict(r) for r in recent_events],
    }


# ── Criticité par hôte ────────────────────────────────────────────────────────

def update_host_criticality(ip: str, criticality: str) -> bool:
    """Définit la criticité explicite d'un hôte (écrase l'héritage agent)."""
    valid = {"critical", "high", "normal", "low"}
    if criticality not in valid:
        return False
    with _lock, _conn() as c:
        c.execute("UPDATE monitor_hosts SET criticality=? WHERE ip=?", (criticality, ip))
        return c.rowcount > 0


def update_agent_criticality(agent_id: str, criticality: str) -> bool:
    """Met à jour la criticité d'un agent."""
    valid = {"critical", "high", "normal", "low"}
    if criticality not in valid:
        return False
    with _lock, _conn() as c:
        c.execute(
            "UPDATE monitor_agents SET criticality=? WHERE agent_id=?",
            (criticality, agent_id),
        )
        return c.rowcount > 0


def get_agent_by_ip(ip: str) -> Optional[dict]:
    """Retourne l'agent correspondant à une IP, ou None."""
    with _conn() as c:
        row = c.execute("SELECT * FROM monitor_agents WHERE ip=?", (ip,)).fetchone()
    return dict(row) if row else None
