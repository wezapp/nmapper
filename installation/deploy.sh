#!/usr/bin/env bash
# =============================================================
#  NMAPPER — Déploiement multi-machines (1 serveur + 2 agents)
#  Usage : bash installation/deploy.sh
#          bash installation/deploy.sh --dry-run   (simulation)
# =============================================================
set -euo pipefail

# ── ✏️  CONFIGURATION — à adapter ────────────────────────────
SERVER_IP="10.1.0.10"          # Machine qui héberge NMAPPER
SERVER_PORT=25774               # Port du backend
SERVER_USER="root"              # Utilisateur SSH sur le serveur

declare -A AGENTS               # IP => utilisateur SSH
AGENTS["10.1.1.10"]="root"
AGENTS["10.1.2.10"]="root"

SSH_KEY=""                      # Laisser vide pour utiliser ~/.ssh/id_rsa
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=8"
REMOTE_TMP="/tmp/nmapper-deploy"
# ─────────────────────────────────────────────────────────────

# Couleurs
G="\033[32;1m"; C="\033[36;1m"; Y="\033[33;1m"
R="\033[31;1m"; D="\033[2m";    B="\033[1m"; N="\033[0m"

DRY=false
[[ "${1:-}" == "--dry-run" ]] && DRY=true

# Répertoire racine du projet (parent de installation/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Helpers ───────────────────────────────────────────────────

log()     { echo -e "${B}[deploy]${N} $*"; }
ok()      { echo -e "${G}  ✅ $*${N}"; }
warn()    { echo -e "${Y}  ⚠  $*${N}"; }
err()     { echo -e "${R}  ❌ $*${N}"; }
section() { echo -e "\n${C}${B}── $* ──${N}"; }

ssh_cmd() {
    local user="$1" ip="$2"; shift 2
    local key_opt=""
    [[ -n "$SSH_KEY" ]] && key_opt="-i $SSH_KEY"
    if $DRY; then
        echo -e "  ${D}[DRY] ssh ${user}@${ip} '$*'${N}"
    else
        # shellcheck disable=SC2086
        ssh $SSH_OPTS $key_opt "${user}@${ip}" "$@"
    fi
}

scp_cmd() {
    local src="$1" user="$2" ip="$3" dst="$4"
    local key_opt=""
    [[ -n "$SSH_KEY" ]] && key_opt="-i $SSH_KEY"
    if $DRY; then
        echo -e "  ${D}[DRY] scp -r ${src} ${user}@${ip}:${dst}${N}"
    else
        # shellcheck disable=SC2086
        scp -r $SSH_OPTS $key_opt "$src" "${user}@${ip}:${dst}"
    fi
}

check_ssh() {
    local user="$1" ip="$2" label="$3"
    log "Test connexion SSH → ${ip} …"
    if ssh_cmd "$user" "$ip" "echo ok" &>/dev/null || $DRY; then
        ok "$label ($ip) accessible"
        return 0
    else
        err "Impossible de joindre $ip — vérifiez SSH / clé / IP"
        return 1
    fi
}

# ── Étape 1 : copier les fichiers ──────────────────────────────

copy_files() {
    local user="$1" ip="$2"
    log "Copie des sources vers ${user}@${ip}:${REMOTE_TMP} …"
    ssh_cmd "$user" "$ip" "rm -rf ${REMOTE_TMP} && mkdir -p ${REMOTE_TMP}"
    scp_cmd "${SCRIPT_DIR}"   "$user" "$ip" "${REMOTE_TMP}/installation"
    scp_cmd "${PROJECT_DIR}/python-api" "$user" "$ip" "${REMOTE_TMP}/python-api"
    ok "Fichiers copiés"
}

# ── Étape 2 : installer le serveur ────────────────────────────

deploy_server() {
    section "Serveur NMAPPER → ${SERVER_IP}"
    check_ssh "$SERVER_USER" "$SERVER_IP" "Serveur" || return 1
    copy_files "$SERVER_USER" "$SERVER_IP"

    log "Installation dans /opt/nmapper/ …"
    ssh_cmd "$SERVER_USER" "$SERVER_IP" \
        "cd ${REMOTE_TMP} && python3 installation/server.py --install --port ${SERVER_PORT}"

    ok "Serveur installé et démarré sur ${SERVER_IP}:${SERVER_PORT}"
}

# ── Étape 3 : récupérer la clé API ────────────────────────────

fetch_api_key() {
    log "Lecture de la clé API sur le serveur …"
    if $DRY; then
        API_KEY="DRY_RUN_FAKE_KEY"
        echo -e "  ${D}[DRY] clé = ${API_KEY}${N}"
    else
        API_KEY=$(ssh_cmd "$SERVER_USER" "$SERVER_IP" \
            "cat /opt/nmapper/scans/.apikey 2>/dev/null || cat /tmp/nmapper-deploy/python-api/scans/.apikey 2>/dev/null")
        if [[ -z "$API_KEY" ]]; then
            err "Clé API introuvable — déployez d'abord le serveur"
            exit 1
        fi
    fi
    ok "Clé API récupérée : ${API_KEY:0:16}…"
}

# ── Étape 4 : installer les agents ────────────────────────────

deploy_agent() {
    local ip="$1" user="$2"
    section "Agent → ${ip}"
    check_ssh "$user" "$ip" "Agent" || return 1
    copy_files "$user" "$ip"

    log "Installation silencieuse de l'agent …"
    ssh_cmd "$user" "$ip" "
        cd ${REMOTE_TMP} && \
        python3 installation/install-agent.py <<EOF
${SERVER_IP}
${SERVER_PORT}
${API_KEY}
30
n
o
EOF
    " 2>&1 | grep -E "(✅|❌|⚠|Installé|Connexion|copié)" || true

    ok "Agent installé sur ${ip}"
}

# ── Main ──────────────────────────────────────────────────────

main() {
    echo -e "\n${B}══════════════════════════════════════════════${N}"
    echo -e "${C}${B}   NMAPPER — Déploiement multi-machines${N}"
    echo -e "${B}══════════════════════════════════════════════${N}"
    $DRY && warn "Mode DRY-RUN — aucune commande réelle exécutée"
    echo -e "  Serveur  : ${G}${SERVER_IP}:${SERVER_PORT}${N}"
    for ip in "${!AGENTS[@]}"; do
        echo -e "  Agent    : ${Y}${ip}${N}  (user: ${AGENTS[$ip]})"
    done
    echo

    # 1. Déployer le serveur
    deploy_server

    # 2. Récupérer la clé API générée
    fetch_api_key

    # 3. Déployer les agents
    for ip in "${!AGENTS[@]}"; do
        deploy_agent "$ip" "${AGENTS[$ip]}"
    done

    # 4. Résumé
    echo -e "\n${B}══════════════════════════════════════════════${N}"
    echo -e "${G}${B}  ✅  DÉPLOIEMENT TERMINÉ${N}"
    echo -e "${B}══════════════════════════════════════════════${N}"
    echo -e "  Serveur : ${G}http://${SERVER_IP}:${SERVER_PORT}/scanner-api${N}"
    echo -e "  Clé API : ${Y}${API_KEY:0:20}…${N}"
    echo -e "  Agents  :"
    for ip in "${!AGENTS[@]}"; do
        echo -e "    ${Y}${ip}${N} → journalctl -u nmapper-agent -f"
    done
    echo -e "\n  ${D}Ouvrez NMAPPER → onglet Monitoring pour voir les données${N}\n"
}

main
