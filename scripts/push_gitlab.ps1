# ============================================================
# push_gitlab.ps1 – Initialise le dépôt Git et pousse sur GitLab
# Usage : .\scripts\push_gitlab.ps1 -GitlabUrl <url> [-Branch <branche>]
#
# Exemple :
#   .\scripts\push_gitlab.ps1 -GitlabUrl https://gitlab.com/mongroupe/toolbox-pentest.git
#   .\scripts\push_gitlab.ps1 -GitlabUrl https://gitlab.com/mongroupe/toolbox-pentest.git -Branch develop
# ============================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$GitlabUrl,

    [string]$Branch = "main"
)

# Fix encodage UTF-8 console Windows
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Log   { param($msg) Write-Host "[push_gitlab] $msg" -ForegroundColor Cyan }
function Ok    { param($msg) Write-Host "[OK] $msg"          -ForegroundColor Green }
function Warn  { param($msg) Write-Host "[WARN] $msg"        -ForegroundColor Yellow }
function Err   { param($msg) Write-Host "[ERROR] $msg"       -ForegroundColor Red; exit 1 }

# ---- Vérifier git ----
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Err "git n'est pas installé ou absent du PATH."
}

Set-Location $ProjectRoot

# ---- Init git si nécessaire ----
if (-not (Test-Path (Join-Path $ProjectRoot ".git"))) {
    Log "Initialisation du dépôt Git..."
    git init
    Ok "Dépôt initialisé"
}

# ---- Vérifier .gitignore ----
if (-not (Test-Path (Join-Path $ProjectRoot ".gitignore"))) {
    Warn ".gitignore absent (normalement déjà créé)"
}

# ---- Remote ----
$remoteExists = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0) {
    Warn "Remote 'origin' existant, mise à jour vers $GitlabUrl"
    git remote set-url origin $GitlabUrl
} else {
    Log "Ajout du remote origin : $GitlabUrl"
    git remote add origin $GitlabUrl
}

# ---- Vérification .env non inclus ----
git ls-files --error-unmatch .env 2>$null
if ($LASTEXITCODE -eq 0) {
    Warn ".env est tracké par git ! Suppression du tracking..."
    git rm --cached .env
}

# ---- Staging ----
Log "Ajout des fichiers..."
$itemsToAdd = @(
    "backend",
    "frontend",
    "docker",
    "siem",
    "docs",
    "scripts",
    ".claude",
    ".env.example",
    ".gitignore",
    "README.md"
)

foreach ($item in $itemsToAdd) {
    $fullPath = Join-Path $ProjectRoot $item
    if (Test-Path $fullPath) {
        git add $item
    } else {
        Warn "Introuvable, ignoré : $item"
    }
}

# pyproject.toml à la racine backend
if (Test-Path (Join-Path $ProjectRoot "backend\pyproject.toml")) {
    git add "backend\pyproject.toml"
}

# ---- Commit ----
$diffOutput = git diff --cached --quiet 2>&1
if ($LASTEXITCODE -eq 0) {
    Warn "Aucun changement à committer."
} else {
    $commitMsg = @"
feat: initialisation complete du projet PentestBox

- Backend FastAPI avec modules offensifs et defensifs
- Integration ELK Stack (SIEM) + Snort (IDS)
- Interface web Jinja2 + dashboard KPIs
- Reporting PDF/HTML/CSV automatise
- Stack Docker Compose complete
- Documentation technique complete (docs/)
- Conformite cadre pedagogique Mastere Cybersecurite
"@
    Log "Création du commit initial..."
    git commit -m $commitMsg
    Ok "Commit créé"
}

# ---- Branche ----
$currentBranch = git branch --show-current 2>$null
if ($currentBranch -ne $Branch) {
    Log "Création/bascule sur la branche '$Branch'..."
    git checkout -B $Branch
}

# ---- Push ----
Log "Push vers $GitlabUrl (branche : $Branch)..."
git push -u origin $Branch

Write-Host ""
Ok "Code poussé sur GitLab !"
Write-Host "  Dépôt   : " -NoNewline; Write-Host $GitlabUrl -ForegroundColor Cyan
Write-Host "  Branche : " -NoNewline; Write-Host $Branch    -ForegroundColor Cyan
Write-Host ""
Log "Prochaines étapes :"
Write-Host "  1. Configurer les variables CI/CD dans GitLab (Settings > CI/CD > Variables)"
Write-Host "  2. Vérifier le pipeline .gitlab-ci.yml"
Write-Host "  3. Créer les branches : develop, staging, main"
