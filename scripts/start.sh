#!/usr/bin/env bash
# ============================================================
# start.sh – Lance la stack ToolboxV8 complète via Docker
# Usage : ./scripts/start.sh [--dev | --prod | --stop | --logs | --status | --version]
#
# Le compte admin (admin / admin123) est créé automatiquement après
# démarrage si absent (voir ensure_admin plus bas).
# ============================================================

set -euo pipefail

TOOLBOX_VERSION="1.2.2"

COMPOSE_FILE="docker/docker-compose.yml"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[ToolboxV8]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---- Vérifications préalables ----
check_deps() {
  for cmd in docker; do
    if ! command -v "$cmd" &>/dev/null; then
      err "$cmd n'est pas installé."
      exit 1
    fi
  done
  if ! docker compose version &>/dev/null; then
    err "Docker Compose (plugin) n'est pas disponible."
    exit 1
  fi
}

# ---- Génération .env si absent ----
init_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    warn ".env absent, création depuis .env.example"
    cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"

    # Génération automatique des clés
    SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")
    FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo "FERNET_KEY_A_GENERER")

    sed -i "s/changeme-in-production-use-openssl-rand-hex-32/$SECRET_KEY/" "$ENV_FILE"
    sed -i "s/changeme-generate-with-fernet/$FERNET_KEY/" "$ENV_FILE"
    ok ".env généré avec des clés aléatoires"
  fi
}

# ---- Démarrage ----
start() {
  local mode="${1:-prod}"
  log "Démarrage ToolboxV8 en mode : $mode"
  cd "$PROJECT_ROOT"
  init_env

  if [[ "$mode" == "dev" ]]; then
    docker compose -f "$COMPOSE_FILE" up --build
  else
    docker compose -f "$COMPOSE_FILE" up -d --build
    echo ""
    ok "Stack démarrée !"
    echo ""
    echo -e "  ${CYAN}Interface web HTTPS${NC}  : https://localhost/login   (recommandé, via Caddy)"
    echo -e "  ${CYAN}Interface web HTTP${NC}   : http://localhost:3000/login   (fallback dev)"
    echo -e "  ${CYAN}API Swagger${NC}          : http://localhost:8000/api/docs"
    echo -e "  ${CYAN}Kibana (SIEM)${NC}        : http://localhost:5601"
    echo -e "  ${CYAN}MinIO Console${NC}        : http://localhost:9001"
    echo ""
    log "Attente que l'API soit prête..."
    for i in $(seq 1 30); do
      if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        ok "API prête !"
        break
      fi
      sleep 2
    done
    log "Attente que le site web soit prêt..."
    for i in $(seq 1 30); do
      if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        ok "Web prêt !"
        break
      fi
      sleep 2
    done

    ensure_admin
  fi
}

# ---- Création automatique d'un compte (helper interne) ----
ensure_user() {
  local user="$1"
  local pass="$2"
  local email="$3"
  local role="$4"

  local login_resp
  login_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "http://localhost:8000/api/auth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" || echo "000")
  if [[ "$login_resp" == "200" ]]; then
    ok "Compte '$user' déjà existant."
    return
  fi

  local register_resp
  register_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "http://localhost:8000/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"email\":\"$email\",\"password\":\"$pass\",\"role\":\"$role\"}" || echo "000")
  if [[ "$register_resp" == "201" || "$register_resp" == "200" ]]; then
    ok "Compte '$user' créé ($role)."
  else
    warn "Création du compte '$user' impossible (HTTP $register_resp)."
  fi
}

# ---- Création automatique des 3 comptes par défaut (RBAC) ----
ensure_admin() {
  log "Vérification / création des 3 comptes par défaut (RBAC)..."
  ensure_user "admin"   "admin123"   "admin@toolboxv8.fr"   "admin"
  ensure_user "analyst" "analyst123" "analyst@toolboxv8.fr" "analyst"
  ensure_user "reader"  "reader123"  "reader@toolboxv8.fr"  "reader"
  echo ""
  echo -e "  ${YELLOW}Comptes seedés (RBAC)${NC} :"
  echo -e "    admin   / admin123   ${YELLOW}(admin   — tout faire)${NC}"
  echo -e "    analyst / analyst123 ${YELLOW}(analyst — lancer scans)${NC}"
  echo -e "    reader  / reader123  ${YELLOW}(reader  — lecture seule)${NC}"
  echo ""
}

# ---- Arrêt ----
stop() {
  log "Arrêt de la stack..."
  cd "$PROJECT_ROOT"
  docker compose -f "$COMPOSE_FILE" down
  ok "Stack arrêtée."
}

# ---- Logs ----
show_logs() {
  cd "$PROJECT_ROOT"
  docker compose -f "$COMPOSE_FILE" logs -f --tail=100
}

# ---- Statut ----
status() {
  cd "$PROJECT_ROOT"
  docker compose -f "$COMPOSE_FILE" ps
}

# ---- Main ----
check_deps

case "${1:-start}" in
  --dev)     start dev ;;
  --prod)    start prod ;;
  --stop)    stop ;;
  --logs)    show_logs ;;
  --status)  status ;;
  --version) echo "ToolboxV8 v$TOOLBOX_VERSION" ;;
  start)     start prod ;;
  *)
    echo "Usage: $0 [--dev | --prod | --stop | --logs | --status | --version]"
    exit 1
    ;;
esac
