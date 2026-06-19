# Infrastructure de test NMAPPER

Environnement Docker simulant un réseau d'entreprise réaliste avec 27 hôtes répartis sur 4 VLANs. Conçu pour être scanné avec nmap et visualisé dans NMAPPER.

---

## Démarrage rapide

```bash
cd test-infra
docker compose build
docker compose up -d
```

Attendre ~20 secondes que tous les services soient prêts, puis lancer les scans nmap (un par VLAN) et importer les XML dans NMAPPER.

---

## Architecture réseau

### VLAN 10 — Corporate `192.168.10.0/24`
Postes de travail Windows simulés (Samba + socat pour les ports Windows).

| IP | Hôte | Ports ouverts |
|----|------|---------------|
| 192.168.10.10 | WIN-DC01 (Contrôleur de domaine) | 88 Kerberos, 135 RPC, 139/445 SMB, 389 LDAP, 636 LDAPS, 3268 GC, 3389 RDP |
| 192.168.10.11 | WIN-WS001 (Poste 1) | 135 RPC, 139/445 SMB, 3389 RDP |
| 192.168.10.12 | WIN-WS002 (Poste 2) | 135 RPC, 139/445 SMB, 3389 RDP |
| 192.168.10.20 | WIN-LAPTOP01 (Laptop) | 139/445 SMB, 3389 RDP |

---

### VLAN 20 — Serveurs `192.168.20.0/24`
Infrastructure applicative, certains services délibérément mal configurés.

| IP | Hôte | Service | Ports | Vuln |
|----|------|---------|-------|------|
| 192.168.20.10 | web-srv-01 | Nginx | 80, 443 | |
| 192.168.20.11 | db-mysql-01 | MySQL 8 | 3306 | Mot de passe root vide |
| 192.168.20.12 | db-postgres-01 | PostgreSQL 15 | 5432 | |
| 192.168.20.13 | cache-redis-01 | Redis | 6379 | Sans authentification |
| 192.168.20.14 | db-mongo-01 | MongoDB 6 | 27017 | Sans authentification |
| 192.168.20.15 | elk-es-01 | Elasticsearch 7 | 9200, 9300 | Sans TLS ni auth |
| 192.168.20.16 | ftp-srv-01 | vsftpd | 21 | Accès anonyme activé |
| 192.168.20.17 | ssh-srv-01 | OpenSSH | 22 | Auth par mot de passe |
| 192.168.20.18 | mail-srv-01 | SMTP/IMAP | 25, 143, 465, 587, 993, 110, 995 | |
| 192.168.20.19 | fs-samba-01 | Samba (SMB) | 139, 445 | Partages accessibles en guest |

---

### VLAN 30 — IoT / OT `192.168.30.0/24`
Équipements connectés et systèmes industriels.

| IP | Hôte | Type | Ports |
|----|------|------|-------|
| 192.168.30.10 | ipcam-hvk-01 | Caméra Hikvision | 80, 554 RTSP, 8080, 8554 |
| 192.168.30.11 | ipcam-dah-02 | Caméra Dahua | 80, 554 RTSP, 8080, 8554 |
| 192.168.30.12 | ipcam-axis-03 | Caméra Axis | 80, 554 RTSP, 8080, 8554 |
| 192.168.30.20 | printer-hp-01 | Imprimante HP LaserJet | 161/udp SNMP, 515 LPD, 631 IPP, 9100 JetDirect |
| 192.168.30.21 | printer-epson-01 | Imprimante Epson | 161/udp SNMP, 515 LPD, 631 IPP, 9100 JetDirect |
| 192.168.30.30 | plc-modbus-01 | Automate Modbus TCP | **502** Modbus ⚠️, 80, 161/udp |
| 192.168.30.31 | plc-siemens-01 | Automate Siemens S7 | **102** S7comm ⚠️, 80 |
| 192.168.30.32 | opcua-gateway-01 | Passerelle OPC-UA | **4840** OPC-UA ⚠️, 8080 |
| 192.168.30.40 | iot-mqtt-hub | Broker MQTT | **1883** sans auth ⚠️ |
| 192.168.30.50 | sw-core-01 | Switch manageable | 23 Telnet, 161/udp SNMP (community "public") |
| 192.168.30.60 | smarttv-room101 | Smart TV | 7080, 8080, 1900/udp UPnP |

⚠️ = port industriel critique, déclenche une alerte de vulnérabilité dans NMAPPER

---

### VLAN 40 — DMZ `192.168.40.0/24`
Services exposés publiquement et hôtes volontairement vulnérables.

| IP | Hôte | Type | Ports | Vuln |
|----|------|------|-------|------|
| 192.168.40.10 | dmz-web-01 | Nginx multi-ports | 80, 443, 8080, 8443 | |
| 192.168.40.11 | dvwa-server | DVWA | 80 | App web délibérément vulnérable |
| 192.168.40.20 | legacy-telnet-01 | Hôte legacy | **23 Telnet** ⚠️, 22 SSH | Telnet = critique NMAPPER |
| 192.168.40.21 | legacy-ftp-01 | FTP legacy | 21 | Accès anonyme |
| 192.168.40.30 | vpn-gw-01 | Passerelle VPN | 443, 500/udp, 1194/udp, 1701/udp, 1723 | |
| 192.168.40.40 | exposed-srv-01 | Hôte sur-exposé | 21, 22, 23, 80, 443, 3306, 5900 VNC, 6379, 8080, 8443, 9200, 161/udp | 12 ports ouverts → vulnérable NMAPPER |

---

## Commandes nmap recommandées

Scanner chaque VLAN dans un fichier XML séparé — un fichier = un "réseau" dans NMAPPER.

```bash
# VLAN 10 - Corporate
nmap -sV -T4 192.168.10.0/24 -oX vlan10_corp.xml

# VLAN 20 - Serveurs
nmap -sV -T4 192.168.20.0/24 -oX vlan20_servers.xml

# VLAN 30 - IoT/OT
nmap -sV -sU -T4 192.168.30.0/24 -oX vlan30_iot.xml

# VLAN 40 - DMZ
nmap -sV -T4 192.168.40.0/24 -oX vlan40_dmz.xml
```

> **Note** : les réseaux Docker sont accessibles directement depuis la machine hôte. Si ce n'est pas le cas (WSL2, Docker Desktop sur Mac/Windows), il faut ajouter des port-mappings dans le compose ou scanner depuis un conteneur sur le même réseau.

---

## Import dans NMAPPER

1. Glisser-déposer les 4 fichiers `.xml` dans NMAPPER (ou utiliser "Sélectionner des fichiers")
2. Chaque fichier apparaît comme un VLAN distinct dans la vue réseau
3. Le nom du fichier devient le nom du VLAN (`vlan10_corp`, `vlan20_servers`, etc.)

---

## Arrêt

```bash
docker compose down
```
