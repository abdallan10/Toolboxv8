# ToolboxV8

[![CI](https://github.com/Vyuob/toolbox-m1/actions/workflows/ci.yml/badge.svg)](https://github.com/Vyuob/toolbox-m1/actions/workflows/ci.yml)

**Toolbox automatisée de tests d'intrusion**. Mastère Cybersécurité 2025/2026.

Plateforme web qui automatise les étapes d'un pentest (**reconnaissance passive OSINT**, reconnaissance active, scan de vulnérabilités, exploitation, analyse web) et produit des rapports PDF structurés, prêts à livrer au client. L'ergonomie est pensée pour un analyste, pas pour un développeur : un seul formulaire, un choix de profil, un clic.

---

## Démarrage rapide

```bash
# 1. Cloner le projet
git clone https://github.com/Vyuob/toolbox-m1.git
cd toolbox-m1

# 2. Copier la configuration (les clés sont générées automatiquement)
cp .env.example .env

# 3. Lancer la stack complète
./scripts/start.sh        # Linux / macOS
.\scripts\start.ps1       # Windows (PowerShell)

# 4. Ouvrir l'interface (HTTPS via Caddy)
open https://localhost/login
```

Comptes par défaut seedés automatiquement (RBAC à 3 rôles) :

| Compte | Mot de passe | Rôle | Permissions |
|---|---|---|---|
| `admin`   | `admin123`   | admin   | Tout : lance les scans, génère les rapports, **gère les utilisateurs** (page `/admin/users`) |
| `analyst` | `analyst123` | analyst | Lance les scans, consulte et génère les rapports |
| `reader`  | `reader123`  | reader  | Consultation seule des rapports et logs |

> 💡 **HTTPS local** : Caddy génère un certificat auto-signé via sa CA interne.
> Pour éviter le warning navigateur, importer la CA une seule fois :
> ```powershell
> docker cp pentest_caddy:/data/caddy/pki/authorities/local/root.crt .
> certutil -user -addstore "ROOT" root.crt   # Windows
> ```
> (Linux : `sudo cp root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`)

---

## Interfaces disponibles

| Service | URL | Rôle |
|---------|-----|------|
| **App web (HTTPS)** | https://localhost | Login, dashboard, modules, rapports, SIEM (recommandé) |
| **App web (HTTP)** | http://localhost:3000 | Accès direct au service web (dev / fallback) |
| **API Swagger** | http://localhost:8000/api/docs | Documentation REST pour clients externes |
| **Kibana** | http://localhost:5601 | Vue avancée des logs SIEM |
| **MinIO Console** | http://localhost:9001 | Stockage S3 des rapports |
| **Elasticsearch** | http://localhost:9200 | Backend SIEM (logs) |

---

## Architecture

Stack **dockerisée** : 3 services applicatifs + infra + cibles vulnérables intégrées pour les démos :

```
Navigateur ── 443 (HTTPS) ── Caddy ─┐
              80  → 301 redirect    │
                                    ▼
                        web (FastAPI, Jinja2) ─┬─ pages /login /dashboard /modules /reports /siem
                                               └─ proxy /api/* ─► api (FastAPI) ─► PostgreSQL
                                                                                └─► Redis ─► worker (Celery + Kali)
                                                                                                ├─► outils pentest
                                                                                                └─► cibles internes :
                                                                                                     • zap:8080 (OWASP ZAP)
                                                                                                     • target:2222 (SSH faible)

ELK (Elasticsearch + Logstash + Kibana)   MinIO (rapports S3)
```

| Service | Rôle |
|---------|------|
| **caddy** | Reverse proxy HTTPS, cert auto-signé via CA interne (Let's Encrypt en prod en 1 ligne) |
| **web** (FastAPI, port 3000) | Sert les pages HTML, gère l'auth via formulaire + cookie HttpOnly, proxifie `/api/*` |
| **api** (FastAPI, port 8000) | Endpoints REST pur `/api/*`, accessible pour intégrations externes |
| **worker** (Celery + Kali Rolling) | Exécute les scans offensifs avec tous les outils préinstallés |
| **db** PostgreSQL 16, **redis** 7, **minio**, **elasticsearch+logstash+kibana** | Infra |
| **zap** (OWASP ZAP daemon) | API REST sur :8080, polling auto par le module web_scan |
| **target** (linuxserver/openssh-server) | Cible vulnérable réutilisable pour les démos Hydra (`pentest_user:toor` sur :2222) |

---

## Modules pentest

| Module | Outils intégrés | Type |
|--------|-----------------|------|
| **passive_recon** | Google / Bing / DuckDuckGo Dorks (24 templates en 3 catégories : Mot-clé, Réseaux sociaux, Domaine) | Offensif (OSINT) |
| **recon** | Nmap, DNS (résolution), whois, WhatWeb | Offensif |
| **scan** | Nmap NSE (`--script=vuln`), Nikto, SSLyze (avec pré-check TCP IPv4/IPv6) | Offensif |
| **exploit** | SQLmap, Hydra, John the Ripper (jumbo, 304 formats), Metasploit (\*) | Offensif |
| **web_scan** | OWASP ZAP (Spider + Active avec polling + récup. alertes), Gobuster, Dependency-Check | Offensif |
| **siem** | Elasticsearch + Logstash + Kibana (déployés) | Défensif |
| **ids** | Snort 3 (règles préparées, conteneur non déployé, cf. limites rapport) | Défensif |
| **response** | Blocage iptables, isolation host, alertes SIEM | Défensif |
| **forensic** | ClamAV, VirusTotal API | Défensif (bonus) |

(\*) Metasploit : module codé, mais `msfrpcd` doit être démarré manuellement (cf. limites).

Chaque outil expose des **profils par chips** (Quick / Standard / Full / …) qui mappent vers la vraie ligne de commande. Il n'y a pas de textarea éditable à remplir. Le retour est la sortie CLI brute, rendue telle quelle dans le rapport PDF.

📋 **Guide pratique** : configs validées pour chaque outil dans [`docs/guide_test_outils.txt`](docs/guide_test_outils.txt).

---

## Fonctionnalités clés

### Sécurité
- **HTTPS** via reverse proxy Caddy (CA interne en dev, Let's Encrypt en prod)
- **Auth par formulaire web** + cookie HttpOnly (JWT signé côté backend) ; `POST /api/auth/token` reste utilisable pour les clients externes
- **RBAC** à 3 rôles : `admin`, `analyst`, `reader`
- **Création auto des 3 comptes** (`admin` / `analyst` / `reader`) au premier démarrage
- **Page de gestion des utilisateurs** `/admin/users` (admin uniquement) : créer, modifier le rôle, désactiver, supprimer
- **Chiffrement Fernet** pour les secrets stockés
- **Audit logs** : login, lancement de scan, génération de rapport, blocage IP. Table append-only PostgreSQL

### UX
- **Profils chips** sur tous les outils : Nmap NSE (Quick/Standard/Full/Safe), Nikto (Quick/Standard/Full/Evasion), SSLyze (Cert/Standard/Full), SQLmap (Quick/Standard/Aggressive/Dump), ZAP (Spider/Active × Quick/Standard/Full), Gobuster (Quick/Standard/Full)
- **Catalogue de dorks** (passive_recon) : 24 templates à cocher + dorks personnalisés, ouverture multi-onglets
- **Toggles indépendants** dans Scan et Web/API. Chaque outil est activable séparément, les désactivés sont masqués du rapport
- **Validation cible adaptative** : stricte pour les modules réseau, libre pour passive_recon / Hydra / John (champs avec hostnames Docker, hashes, mots-clés OSINT acceptés)
- **Timeouts adaptés par profil** : Nikto (10/15/30/60 min), SQLmap (5/10/15/30 min), ZAP polling jusqu'à 8 min

### Outils & wordlists
- **Upload de wordlists** personnelles via `POST /api/modules/wordlist` (volume partagé api↔worker)
- **Hydra** : 3 sources au choix (fichier uploadé, liste manuelle dans une modale, rockyou.txt par défaut)
- **John the Ripper jumbo** : bcrypt, sha512crypt, NTLM, argon2, keepass, zip… (304 formats)
- **SSLyze** : pré-check TCP avec fallback IPv4/IPv6 + messages d'erreur clairs si la cible n'a pas de TLS
- **SQLmap Dump** : ciblé (current-db + 8 tables sensibles + 5 lignes max + boolean-based + 10 threads)
- **ZAP Active** : polling automatique jusqu'à 100% + récupération des alertes via API, agrégées par sévérité

### Reporting
- **Rapport PDF** (ReportLab) : charte professionnelle (header bleu, encart CODIR orange, tableau synthétique), sortie CLI brute préservée par outil
- **Palette propre** : texte sombre sur fond clair avec bordure subtile, lisible sur toutes les pages (y compris overflow)
- **Vue HTML** alignée sur le PDF pour cohérence visualiser/télécharger
- **SIEM** : collecte via Logstash, visualisation dans la page `/siem` (Chart.js)

### CI/CD
- **GitHub Actions** ([.github/workflows/ci.yml](.github/workflows/ci.yml)), actif sur le repo
- **GitLab CI** ([.gitlab-ci.yml](.gitlab-ci.yml)), équivalent pour conformité cahier des charges
- 3 stages : lint (ruff) → tests pytest (avec services PostgreSQL + Redis) → build des images Docker

---

## Stack technique

- **Backend** : Python 3.11, FastAPI, SQLAlchemy 2.0, Celery 5, Pydantic v2
- **Frontend** : HTML/CSS/JS (Jinja2, Lucide icons, Chart.js), sans framework JS
- **Base de données** : PostgreSQL 16
- **File de tâches** : Redis 7 + Celery 5 (concurrency=4)
- **Stockage objet** : MinIO (S3-compatible)
- **SIEM** : Elasticsearch 8.13 + Logstash + Kibana
- **IDS** : Snort 3 (règles préparées dans `siem/snort/local.rules`)
- **Worker pentest** : **Kali Linux Rolling** (image officielle), build multi-stage
- **Reverse proxy TLS** : Caddy 2 (`caddy:2-alpine`)
- **Scanner web** : OWASP ZAP 2.17 (`zaproxy/zap-stable`)
- **Cible vulnérable** : `linuxserver/openssh-server`
- **Conteneurisation** : Docker + Docker Compose v2
- **CI/CD** : GitHub Actions + GitLab CI
- **PDF** : ReportLab 4 (HTML/CSV optionnels)

---

## Documentation

Dossier [docs/](docs/README.md) :

- [Rapport final groupe (PDF)](docs/PE-2526_M1CSD_NASR_BEN-RACHED_AKA-A-MFOULA.pdf) : **document technique principal** (architecture, modules, KPIs, REX, politiques de sécurité, conclusion)
- [Guide de test des outils](docs/guide_test_outils.txt) : **configs validées** pour chaque outil (cibles, profils, résultats attendus)
- [Architecture](docs/architecture.md) : split api/web, flux d'auth, orchestration Celery
- [Installation](docs/installation.md) : prérequis, `.env`, commandes Docker
- [Utilisation](docs/usage.md) : parcours utilisateur, captures de l'UI
- [Modules](docs/modules.md) : détail de chaque outil, profils, options
- [API REST](docs/api.md) : référence des endpoints, exemples curl
- [Sécurité](docs/securite.md) : auth, RBAC, chiffrement, audit
- [Livrables](docs/livrables.md) : correspondance avec le cadre pédagogique

---

## Équipe

- **Étudiant 1** : Architecte / Back-end (FastAPI, Celery, Docker, sécurité)
- **Étudiant 2** : Intégration offensive / QA (modules pentest, tests, validation)
- **Étudiant 3** : Interface & Reporting (Jinja2, PDF ReportLab, UX)

---

> Projet réalisé dans un cadre pédagogique.
> **Utilisation uniquement sur des systèmes autorisés.**
> Cibles de test légales recommandées : `scanme.nmap.org`, `testasp.vulnweb.com`, `badssl.com`, et les conteneurs internes `target` et `zap` (cf. [guide de test](docs/guide_test_outils.txt)).
