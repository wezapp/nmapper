#!/bin/bash
# NMAPPER — Script d'installation serveur
# Usage : sudo bash installation/install.sh [--port 8080] [--host 0.0.0.0]
set -e

BOLD="\033[1m"
GREEN="\033[32;1m"
CYAN="\033[36;1m"
RED="\033[31;1m"
DIM="\033[2m"
RESET="\033[0m"

echo ""
echo -e "${BOLD}══════════════════════════════════════${RESET}"
echo -e "${CYAN}${BOLD}   NMAPPER — Installation serveur${RESET}"
echo -e "${BOLD}══════════════════════════════════════${RESET}"
echo ""

# ── Droits root ───────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ Ce script doit être lancé en root.${RESET}"
  echo -e "${DIM}   Relancez avec : sudo bash installation/install.sh${RESET}"
  exit 1
fi

# ── Détection du gestionnaire de paquets ──────────────────
if command -v apt-get &>/dev/null; then
  PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
  PKG_MANAGER="yum"
else
  echo -e "${RED}❌ Aucun gestionnaire de paquets reconnu (apt/dnf/yum).${RESET}"
  exit 1
fi

echo -e "${BOLD}1. Python 3${RESET}"
if command -v python3 &>/dev/null; then
  PYVER=$(python3 --version 2>&1)
  echo -e "${GREEN}✅ $PYVER déjà installé${RESET}"
else
  echo "   Installation de Python 3..."
  case $PKG_MANAGER in
    apt) apt-get update -qq && apt-get install -y python3 ;;
    dnf) dnf install -y python3 ;;
    yum) yum install -y python3 ;;
  esac
  echo -e "${GREEN}✅ Python 3 installé${RESET}"
fi

echo ""
echo -e "${BOLD}2. Module venv Python${RESET}"
# Teste si le module venv est déjà disponible (évite les 404 apt sur Debian Trixie)
if python3 -c "import venv" 2>/dev/null; then
  echo -e "${GREEN}✅ Module venv déjà disponible${RESET}"
else
  echo "   Module venv absent — tentative d'installation..."
  case $PKG_MANAGER in
    apt)
      apt-get update -qq 2>/dev/null || true
      apt-get install -y python3-venv 2>/dev/null || \
      apt-get install -y --fix-missing python3-venv 2>/dev/null || true
      ;;
    dnf) dnf install -y python3-devel 2>/dev/null || true ;;
    yum) yum install -y python3-devel 2>/dev/null || true ;;
  esac
  if python3 -c "import venv" 2>/dev/null; then
    echo -e "${GREEN}✅ Module venv installé${RESET}"
  else
    echo -e "${DIM}   ⚠ venv non disponible via apt — utilisation de get-pip.py en fallback${RESET}"
  fi
fi

echo ""
echo -e "${BOLD}3. nginx${RESET}"
if command -v nginx &>/dev/null; then
  echo -e "${GREEN}✅ nginx déjà installé${RESET}"
else
  case $PKG_MANAGER in
    apt)
      echo "   Ajout du dépôt officiel nginx.org..."
      # Installer gnupg2 si absent (sans curl ni wget)
      apt-get install -y gnupg2 2>/dev/null || true
      # Télécharger la clé GPG via Python3 (toujours disponible, évite curl/wget)
      python3 - << 'PYEOF'
import urllib.request, ssl, sys
url = "https://nginx.org/keys/nginx_signing.key"
ctx = ssl.create_default_context()
try:
    with urllib.request.urlopen(url, context=ctx) as r:
        data = r.read()
    with open("/tmp/nginx_signing.key", "wb") as f:
        f.write(data)
    print("   Clé nginx téléchargée")
except Exception as e:
    print(f"   ❌ Erreur téléchargement clé : {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
      gpg --dearmor < /tmp/nginx_signing.key > /usr/share/keyrings/nginx-archive-keyring.gpg
      rm -f /tmp/nginx_signing.key
      # Dépôt stable nginx (compatible Debian bookworm/trixie)
      echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
https://nginx.org/packages/debian bookworm nginx" \
        > /etc/apt/sources.list.d/nginx.list
      apt-get update -qq
      apt-get install -y nginx
      ;;
    dnf) dnf install -y nginx ;;
    yum) yum install -y nginx ;;
  esac
  echo -e "${GREEN}✅ nginx installé${RESET}"
fi

echo ""
echo -e "${BOLD}4. Installation NMAPPER${RESET}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/server.py" --install "$@"

# ── Frontend : copie des fichiers statiques ────────────────────────────────────
echo ""
echo -e "${BOLD}5. Déploiement du frontend${RESET}"

FRONTEND_SRC="$SCRIPT_DIR/../artifacts/nmapper"
FRONTEND_DST="/var/www/nmapper"

if [ -d "$FRONTEND_SRC" ]; then
  mkdir -p "$FRONTEND_DST"
  cp "$FRONTEND_SRC/index.html" "$FRONTEND_DST/"
  cp -r "$FRONTEND_SRC/public/"* "$FRONTEND_DST/" 2>/dev/null || true
  echo -e "${GREEN}✅ Frontend copié → $FRONTEND_DST${RESET}"
else
  echo -e "${DIM}   (dossier artifacts/nmapper/ absent — frontend non déployé)${RESET}"
fi

# ── Configuration nginx ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}6. Configuration nginx${RESET}"

LOCAL_IP=$(python3 -c "import socket; s=socket.socket(); s.connect(('8.8.8.8',80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || hostname -I | awk '{print $1}')

if ! command -v nginx &>/dev/null; then
  echo -e "${RED}❌ nginx non installé — configuration ignorée${RESET}"
  echo -e "${DIM}   Relancez le script pour réessayer l'installation de nginx${RESET}"
else

  # nginx.org utilise conf.d/, Debian utilise sites-available/
  if [ -d /etc/nginx/sites-available ]; then
    NGINX_CONF=/etc/nginx/sites-available/nmapper
  else
    NGINX_CONF=/etc/nginx/conf.d/nmapper.conf
  fi

  cat > "$NGINX_CONF" << NGINX
server {
    listen 80;
    server_name _;

    root /var/www/nmapper;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /scanner-api {
        proxy_pass http://127.0.0.1:25774;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NGINX

  # Activer le site si sites-enabled existe (style Debian)
  if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/nmapper
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  fi
  # Supprimer le site default de nginx.org (conf.d/default.conf)
  rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

  nginx -t && systemctl enable --now nginx && systemctl reload nginx
  echo -e "${GREEN}✅ nginx configuré → http://${LOCAL_IP}/${RESET}"
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════${RESET}"
echo -e "${CYAN}${BOLD}   ✅  NMAPPER PRÊT${RESET}"
echo -e "${BOLD}══════════════════════════════════════${RESET}"
echo -e "   Interface web : ${GREEN}http://${LOCAL_IP}/${RESET}"
echo -e "   API backend   : ${GREEN}http://${LOCAL_IP}/scanner-api${RESET}"
echo -e "${BOLD}══════════════════════════════════════${RESET}"
