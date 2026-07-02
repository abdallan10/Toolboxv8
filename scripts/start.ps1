param(
    [ValidateSet("dev", "prod", "stop", "logs", "status", "rebuild")]
    [string]$Mode = "prod"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$ProjectRoot  = Split-Path -Parent $PSScriptRoot
$ComposeFile  = Join-Path $ProjectRoot "docker\docker-compose.yml"
$EnvFile      = Join-Path $ProjectRoot ".env"
$EnvExample   = Join-Path $ProjectRoot ".env.example"

function Log    { param($msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Ok     { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Warn   { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Err    { param($msg) Write-Host "  [-] $msg" -ForegroundColor Red; exit 1 }

function Show-Banner {
    Write-Host ""
    Write-Host "  ====================================" -ForegroundColor Red
    Write-Host "       ToolboxV8 v1.0.0" -ForegroundColor Red
    Write-Host "    Toolbox de tests d intrusion" -ForegroundColor Red
    Write-Host "      Mastere Cybersecurite" -ForegroundColor Red
    Write-Host "  ====================================" -ForegroundColor Red
    Write-Host ""
}

function Check-Deps {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Err "Docker n est pas installe ou absent du PATH."
    }
    $null = docker compose version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Err "Docker Compose (plugin) n est pas disponible."
    }
}

function Ensure-DockerRunning {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $dockerRunning = docker info 2>&1 | Select-String "Server Version"
    $ErrorActionPreference = $prevEap
    if (-not $dockerRunning) {
        Warn "Docker Desktop n est pas lance. Demarrage..."
        $dockerPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerPath) {
            Start-Process $dockerPath
        } else {
            Err "Docker Desktop introuvable."
        }
        Log "Attente de Docker Engine..."
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 3
            $ErrorActionPreference = "Continue"
            $check = docker info 2>&1 | Select-String "Server Version"
            $ErrorActionPreference = $prevEap
            if ($check) {
                Ok "Docker Engine demarre."
                return
            }
            Write-Host "." -NoNewline
        }
        Write-Host ""
        Err "Docker Engine n a pas demarre dans les 90 secondes."
    } else {
        Ok "Docker Engine actif."
    }
}

function Init-Env {
    if (-not (Test-Path $EnvFile)) {
        if (Test-Path $EnvExample) {
            Warn ".env absent, creation depuis .env.example"
            Copy-Item $EnvExample $EnvFile
            $secretKey = -join ((0..63) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
            (Get-Content $EnvFile) `
                -replace 'changeme-in-production-use-openssl-rand-hex-32', $secretKey |
                Set-Content $EnvFile
            Ok ".env genere."
        }
    } else {
        Ok "Fichier .env present."
    }
}

function Wait-Api {
    Log "Attente que l API soit prete..."
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($r.StatusCode -eq 200) {
                Ok "API operationnelle."
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Warn "L API ne repond pas encore."
    return $false
}

function Wait-Caddy {
    # Verifie que Caddy repond en HTTPS sur :443 (cert auto-signe accepte).
    Log "Attente que Caddy soit pret..."
    # Ignore le warning de cert auto-signe (CA Caddy interne)
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                                       WebRequest req, int problem) { return true; }
}
"@ -ErrorAction SilentlyContinue
    try { [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy } catch {}
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    for ($i = 0; $i -lt 20; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "https://localhost/login" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($r.StatusCode -eq 200) {
                Ok "Caddy HTTPS pret."
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Warn "Caddy ne repond pas en HTTPS, ouverture du navigateur quand meme."
    return $false
}

function Create-User {
    param(
        [string]$Username,
        [string]$Password,
        [string]$Email,
        [string]$Role
    )
    # Tente de se connecter d'abord ; si echec, cree le compte.
    try {
        $body = "username=$Username&password=$Password"
        $null = Invoke-WebRequest -Uri "http://localhost:8000/api/auth/token" `
            -Method POST `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -ErrorAction SilentlyContinue
        Ok "Compte '$Username' existant."
    } catch {
        try {
            $data = @{
                username = $Username
                email    = $Email
                password = $Password
                role     = $Role
            } | ConvertTo-Json
            $null = Invoke-WebRequest -Uri "http://localhost:8000/api/auth/register" `
                -Method POST `
                -ContentType "application/json" `
                -Body $data `
                -UseBasicParsing `
                -TimeoutSec 5 `
                -ErrorAction SilentlyContinue
            Ok "Compte '$Username' cree ($Role)."
        } catch {
            Warn "Impossible de creer le compte '$Username' (deja existant avec un autre mdp ?)."
        }
    }
}

function Create-Admin {
    Log "Verification / creation des 3 comptes par defaut (RBAC)..."
    Create-User -Username "admin"   -Password "admin123"   -Email "admin@toolboxv8.fr"   -Role "admin"
    Create-User -Username "analyst" -Password "analyst123" -Email "analyst@toolboxv8.fr" -Role "analyst"
    Create-User -Username "reader"  -Password "reader123"  -Email "reader@toolboxv8.fr"  -Role "reader"
}

function Start-Stack {
    param([string]$mode)
    Log "Mode : $mode"
    Set-Location $ProjectRoot
    Init-Env

    if ($mode -eq "dev") {
        Log "Demarrage en mode dev (logs en direct)..."
        docker compose -f $ComposeFile up --build
    } else {
        Log "Build et demarrage des conteneurs..."
        docker compose -f $ComposeFile up -d --build
        if ($LASTEXITCODE -ne 0) { Err "Echec du demarrage Docker." }

        $apiReady = Wait-Api
        if ($apiReady) { Create-Admin }
        $caddyReady = Wait-Caddy

        Write-Host ""
        Write-Host "  ===== Stack ToolboxV8 lancee ! =====" -ForegroundColor Green
        Write-Host ""
        Write-Host "  App web HTTPS : " -NoNewline -ForegroundColor White
        Write-Host "https://localhost" -ForegroundColor Cyan -NoNewline
        Write-Host "  (recommande)" -ForegroundColor DarkGray
        Write-Host "  App web HTTP  : " -NoNewline -ForegroundColor White
        Write-Host "http://localhost:3000" -ForegroundColor DarkGray -NoNewline
        Write-Host "  (fallback dev)" -ForegroundColor DarkGray
        Write-Host "  SIEM          : " -NoNewline -ForegroundColor White
        Write-Host "https://localhost/siem" -ForegroundColor Cyan
        Write-Host "  API Docs      : " -NoNewline -ForegroundColor White
        Write-Host "http://localhost:8000/api/docs" -ForegroundColor Cyan
        Write-Host "  Kibana        : " -NoNewline -ForegroundColor White
        Write-Host "http://localhost:5601" -ForegroundColor Cyan
        Write-Host "  MinIO         : " -NoNewline -ForegroundColor White
        Write-Host "http://localhost:9001" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Comptes seedes (RBAC):" -ForegroundColor Yellow
        Write-Host "    admin   / admin123   (admin   - tout faire)" -ForegroundColor Yellow
        Write-Host "    analyst / analyst123 (analyst - lancer scans)" -ForegroundColor Yellow
        Write-Host "    reader  / reader123  (reader  - lecture seule)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Commandes utiles :" -ForegroundColor DarkGray
        Write-Host "    .\scripts\start.ps1 -Mode stop" -ForegroundColor DarkGray
        Write-Host "    .\scripts\start.ps1 -Mode logs" -ForegroundColor DarkGray
        Write-Host "    .\scripts\start.ps1 -Mode status" -ForegroundColor DarkGray
        Write-Host "    .\scripts\start.ps1 -Mode rebuild" -ForegroundColor DarkGray
        Write-Host ""

        # Ouverture du navigateur : HTTPS si Caddy repond, sinon fallback HTTP
        if ($caddyReady) {
            Log "Ouverture du navigateur (HTTPS via Caddy)..."
            Start-Process "https://localhost/login"
        } else {
            Log "Caddy non pret, ouverture du navigateur en HTTP direct (port 3000)..."
            Start-Process "http://localhost:3000/login"
        }
    }
}

function Rebuild-Stack {
    Log "Rebuild complet (no-cache)..."
    Set-Location $ProjectRoot
    docker compose -f $ComposeFile down
    docker compose -f $ComposeFile build --no-cache
    if ($LASTEXITCODE -ne 0) { Err "Echec du build." }
    Start-Stack "prod"
}

function Stop-Stack {
    Log "Arret de la stack..."
    Set-Location $ProjectRoot
    docker compose -f $ComposeFile down
    Ok "Stack arretee."
}

function Show-Logs {
    Set-Location $ProjectRoot
    docker compose -f $ComposeFile logs -f --tail=100
}

function Show-Status {
    Set-Location $ProjectRoot
    Write-Host ""
    Log "Etat des conteneurs :"
    Write-Host ""
    docker compose -f $ComposeFile ps
    Write-Host ""
    Log "Sante des services :"
    try {
        $null = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        Ok "API : OK"
    } catch { Warn "API : non accessible" }
    try {
        $null = Invoke-WebRequest -Uri "http://localhost:9200/_cluster/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        Ok "Elasticsearch : OK"
    } catch { Warn "Elasticsearch : non accessible" }
    try {
        $null = Invoke-WebRequest -Uri "http://localhost:5601/api/status" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        Ok "Kibana : OK"
    } catch { Warn "Kibana : non accessible" }
    Write-Host ""
}

# ---- Main ----
Show-Banner
Check-Deps
Ensure-DockerRunning

switch ($Mode) {
    "dev"     { Start-Stack "dev"  }
    "prod"    { Start-Stack "prod" }
    "stop"    { Stop-Stack         }
    "logs"    { Show-Logs          }
    "status"  { Show-Status        }
    "rebuild" { Rebuild-Stack      }
    default   { Start-Stack "prod" }
}
