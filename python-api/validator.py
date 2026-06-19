import ipaddress
import os
import re
from typing import Optional

# ── Configuration ────────────────────────────────────────────
_raw_nets = os.getenv("ALLOWED_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
ALLOWED_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network(n.strip()) for n in _raw_nets.split(",") if n.strip()
]

MAX_PREFIX_LEN: int = int(os.getenv("MAX_SCAN_PREFIX", "16"))
MAX_TARGETS_PER_REQUEST: int = int(os.getenv("MAX_TARGETS_PER_REQUEST", "50"))

# VLAN name: alphanumeric + safe separators, max 64 chars
_VLAN_RE = re.compile(r"^[a-zA-Z0-9\-_.]{1,64}$")

# nmap range syntax: 192.168.1.1-50
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def _check_allowed(network: ipaddress.IPv4Network) -> None:
    """Lève ValueError si le réseau n'est pas dans la liste blanche."""
    if not ALLOWED_NETWORKS:
        return
    if not any(network.subnet_of(allowed) for allowed in ALLOWED_NETWORKS):
        raise ValueError("Réseau non autorisé pour ce déploiement")


def _reject_special(network: ipaddress.IPv4Network, label: str) -> None:
    """Bloque loopback / link-local / multicast — inconditionnel, même
    si ALLOWED_NETWORKS est vide. S'applique aux IP, CIDR et plages."""
    if network.is_loopback:
        raise ValueError(f"Les adresses loopback sont interdites : '{label}'")
    if network.is_link_local:
        raise ValueError(f"Les adresses link-local sont interdites : '{label}'")
    if network.is_multicast:
        raise ValueError(f"Les adresses multicast sont interdites : '{label}'")


def _validate_one_target(raw: str) -> str:
    """Valide une cible unique : IP, CIDR ou plage nmap (x.x.x.x-y)."""
    target = raw.strip()
    if not target:
        raise ValueError("Cible vide")

    # Plage nmap : 192.168.1.1-50
    m = _RANGE_RE.match(target)
    if m:
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            raise ValueError(f"Plage d'hôtes invalide : '{target}'")
        try:
            ipaddress.ip_address(f"{prefix}{start}")
        except ValueError:
            raise ValueError(f"Adresse IP invalide dans : '{target}'")
        # Bloque loopback/link-local/multicast puis vérifie la liste blanche
        # sur le /24 contenant la plage
        range_net = ipaddress.ip_network(f"{prefix}0/24", strict=False)
        _reject_special(range_net, target)
        _check_allowed(range_net)
        return target

    # IP seule ou CIDR
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError(
            f"Cible invalide : '{target}' — attendu une IP, un CIDR ou une plage x.x.x.x-y"
        )

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(f"Seules les adresses IPv4 sont supportées : '{target}'")

    _reject_special(network, target)

    if network.prefixlen < MAX_PREFIX_LEN:
        raise ValueError(f"Plage réseau trop large (max /{MAX_PREFIX_LEN} configuré)")

    _check_allowed(network)
    return str(network)


def validate_target(targets_raw: str) -> str:
    """
    Accepte une ou plusieurs cibles séparées par virgule, point-virgule ou saut de ligne.
    Retourne une chaîne space-jointe au format nmap (ex: '192.168.1.0/24 10.0.0.1').
    """
    parts = re.split(r"[\n,;]+", targets_raw.strip())
    parts = [p.strip() for p in parts if p.strip()]

    if not parts:
        raise ValueError("Aucune cible fournie")
    if len(parts) > MAX_TARGETS_PER_REQUEST:
        raise ValueError(f"Maximum {MAX_TARGETS_PER_REQUEST} cibles par requête")

    validated: list[str] = []
    seen: set[str] = set()
    for part in parts:
        v = _validate_one_target(part)
        if v not in seen:
            seen.add(v)
            validated.append(v)

    return " ".join(validated)


def validate_ports(ports: Optional[str]) -> Optional[str]:
    """Parse et valide sans regex pour éviter tout risque de ReDoS."""
    if ports is None:
        return None

    ports = ports.strip()
    if not ports:
        return None

    if len(ports) > 500:
        raise ValueError("Spécification de ports trop longue (max 500 caractères)")

    for chunk in ports.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise ValueError(f"Entrée de port vide dans la liste : '{ports}'")

        if "-" in chunk:
            parts = chunk.split("-", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise ValueError(f"Plage de ports invalide : '{chunk}'")
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"Valeur non numérique dans la plage : '{chunk}'")
            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                raise ValueError(f"Port hors plage 0-65535 : '{chunk}'")
            if start > end:
                raise ValueError(f"Plage invalide (début > fin) : '{chunk}'")
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"Port non numérique : '{chunk}'")
            if not (0 <= port <= 65535):
                raise ValueError(f"Port hors plage 0-65535 : {port}")

    return ports


def validate_vlan_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    name = name.strip()
    if not _VLAN_RE.match(name):
        raise ValueError(
            "Nom VLAN invalide. "
            "Caractères autorisés : lettres, chiffres, tiret, underscore, point (max 64)."
        )
    return name
