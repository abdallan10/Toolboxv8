#!/usr/bin/env bash
# ============================================================
# push_gitlab.sh – Initialise le dépôt Git et pousse sur GitLab
# Usage : ./scripts/push_gitlab.sh <gitlab_url> [branche]
#
# Exemple :
#   ./scripts/push_gitlab.sh https://gitlab.com/mongroupe/toolbox-pentest.git
#   ./scripts/push_gitlab.sh https://gitlab.com/mongroupe/toolbox-pentest.git develop
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[push_gitlab]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---- Arguments ----
GITLAB_URL="${1:-}"
BRANCH="${2:-main}"

if [[ -z "$GITLAB_URL" ]]; then
  err "URL GitLab manquante. Usage : $0 <gitlab_url> [branche]"
fi

cd "$PROJECT_ROOT"

# ---- Vérifier git ----
command -v git &>/dev/null || err "git n'est pas installé."

# ---- Init git si nécessaire ----
if [[ ! -d ".git" ]]; then
  log "Initialisation du dépôt Git..."
  git init
  ok "Dépôt initialisé"
fi

# ---- Configurer .gitignore ----
if [[ ! -f ".gitignore" ]]; then
  warn ".gitignore absent (normalement déjà créé)"
fi

# ---- Remote ----
if git remote get-url origin &>/dev/null; then
  warn "Remote 'origin' existant, mise à jour vers $GITLAB_URL"
  git remote set-url origin "$GITLAB_URL"
else
  log "Ajout du remote origin : $GITLAB_URL"
  git remote add origin "$GITLAB_URL"
fi

# ---- Vérification .env non inclus ----
if git ls-files --error-unmatch .env &>/dev/null 2>&1; then
  warn ".env est tracké par git ! Suppression du tracking..."
  git rm --cached .env
fi

# ---- Staging ----
log "Ajout des fichiers..."
git add \
  backend/ \
  frontend/ \
  docker/ \
  siem/ \
  docs/ \
  scripts/ \
  .claude/ \
  .env.example \
  .gitignore \
  pyproject.toml \
  README.md

# ---- Commit initial ----
if git diff --cached --quiet; then
  warn "Aucun changement à committer."
else
  COMMIT_MSG="feat: initialisation complète du projet PentestBox

- Backend FastAPI avec modules offensifs et défensifs
- Intégration ELK Stack (SIEM) + Snort (IDS)
- Interface web Jinja2 + dashboard KPIs
- Reporting PDF/HTML/CSV automatisé
- Stack Docker Compose complète
- Documentation technique complète (docs/)
- Conformité cadre pédagogique Mastère Cybersécurité"

  log "Création du commit initial..."
  git commit -m "$COMMIT_MSG"
  ok "Commit créé"
fi

# ---- Branche ----
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "")
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
  log "Création/bascule sur la branche '$BRANCH'..."
  git checkout -B "$BRANCH"
fi

# ---- Push ----
log "Push vers $GITLAB_URL (branche : $BRANCH)..."
git push -u origin "$BRANCH"

echo ""
ok "Code poussé sur GitLab !"
echo -e "  ${CYAN}Dépôt${NC} : $GITLAB_URL"
echo -e "  ${CYAN}Branche${NC} : $BRANCH"
echo ""
log "Prochaines étapes :"
echo "  1. Configurer les variables CI/CD dans GitLab (Settings > CI/CD > Variables)"
echo "  2. Vérifier le pipeline .gitlab-ci.yml"
echo "  3. Créer les branches : develop, staging, main"
