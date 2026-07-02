# Architecture technique - ToolboxV8

## 1. Vue d'ensemble

ToolboxV8 est une plateforme **dockerisée** composée d'un reverse proxy HTTPS, de deux services FastAPI séparés (web et api), d'un worker Celery basé sur Kali Rolling, et d'une stack de supports (DB, cache, SIEM, stockage).

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                NAVIGATEUR                                  │
│                        https://localhost/login                             │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTPS (443)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      CADDY (reverse proxy, :80/:443)                       │
│  • Termine le TLS (CA interne en dev, Let's Encrypt en prod)               │
│  • Redirige :80 → :443                                                     │
│  • Proxifie tout vers le service web sur le réseau Docker interne          │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTP interne + cookie HttpOnly
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    Service WEB (FastAPI, port 3000)                        │
│  • Pages Jinja2 : /login, /dashboard, /modules, /reports, /siem,           │
│                   /admin/users                                              │
│  • POST /login  → appelle l'API en interne, pose un cookie signé           │
│  • POST /logout → efface le cookie                                         │
│  • Proxy /api/* → réinjecte `Authorization: Bearer <cookie>` vers api      │
│  • Filtre les routes selon le rôle (reader bloque /modules, etc.)          │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTP interne (réseau pentest_net)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    Service API (FastAPI, port 8000)                        │
│  Routes /api/auth /api/users /api/modules /api/reports /api/dashboard      │
│         /api/defensive                                                     │
│  Swagger : /api/docs  (utilisable par des clients externes avec Bearer)    │
└──────┬──────────────────────┬──────────────────────────┬─────────────────┘
       │                      │                          │
       ▼                      ▼                          ▼
┌──────────────┐      ┌───────────────┐        ┌────────────────────────┐
│ PostgreSQL   │      │ Redis (queue) │        │   Celery worker(s)     │
│ users, jobs, │      │  Celery broker│◄──────►│   image Kali Rolling   │
│ reports,     │      │  + résultats  │        │   + nmap, nikto, john, │
│ audit_log    │      └───────────────┘        │   hydra, sqlmap, msf   │
└──────────────┘                               └──────────┬─────────────┘
                                                          │
                                                          ▼
                                               ┌──────────────────────────┐
                                               │  Volume /tmp/wordlists   │
                                               │  (partagé avec l'API     │
                                               │   pour uploads Hydra)    │
                                               └──────────────────────────┘

              ┌───────────────────────────┐      ┌─────────────────────────┐
              │   ELK Stack (SIEM)         │      │      MinIO Storage      │
              │   Elasticsearch : 9200     │      │  Rapports PDF (S3)      │
              │   Logstash                 │      │  Console : 9001         │
              │   Kibana       : 5601      │      └─────────────────────────┘
              └───────────────────────────┘
                           ▲
                           │
                 ┌─────────┴────────┐
                 │    Snort 3 IDS    │
                 │  local.rules      │
                 └──────────────────┘
```

## 2. Pourquoi deux services FastAPI ?

Splitter `web` et `api` permet :

1. **Isoler les interfaces** : l'API `/api/*` peut rester joignable publiquement (Swagger, intégrations tierces) sans exposer les pages HTML, et inversement.
2. **Centraliser l'auth web** : le cookie HttpOnly n'existe qu'au niveau du service `web`. L'API, elle, accepte aussi bien le cookie (relayé par le proxy) que l'en-tête `Authorization: Bearer` pour les clients externes.
3. **Réduire la surface d'attaque** : un client qui veut parler à l'API doit le faire explicitement avec un token. Il ne peut pas "tomber" sur une page web par erreur.
4. **Séparer les dépendances** : le service web n'a besoin que de `httpx` + `jinja2` ; l'API porte les accès DB et la logique métier.

Le proxy du service web, défini dans [backend/app/web/proxy.py](../backend/app/web/proxy.py), fait transiter toutes les requêtes `GET/POST/PUT/DELETE/PATCH /api/*` du navigateur vers l'API interne en :
- lisant le cookie `access_token` du navigateur,
- l'injectant en `Authorization: Bearer <token>` dans la requête sortante,
- filtrant les en-têtes hop-by-hop (Host, Cookie, Connection),
- renvoyant la réponse telle quelle au navigateur.

## 3. Flux d'authentification

```
1. GET  /login                        → web renvoie login.html
2. POST /login (form: user+pass)      → web appelle POST http://api:8000/api/auth/token
3. api valide les credentials         → renvoie {access_token: "<JWT>"}
4. web pose cookie access_token       → HttpOnly, SameSite=Lax, Secure (HTTPS), Max-Age=3600
5. Redirection 303 → /dashboard       → le cookie est automatiquement envoyé
6. /dashboard → page HTML servie, user contexte dérivé du JWT (sub, role)
7. JS interne fait fetch('/api/...')  → passe par le proxy, arrive à l'API authentifié
```

**Clients externes** (CI, scripts) : ils peuvent toujours appeler directement l'API sur `:8000/api/*` avec un `Authorization: Bearer <token>` obtenu via `POST /api/auth/token`. Aucun changement pour eux.

## 4. Reverse proxy HTTPS (Caddy)

Le conteneur `caddy:2-alpine` agit comme frontal TLS :

- Lit `/etc/caddy/Caddyfile` (fichier déclaratif court)
- Génère son propre certificat via une CA interne en local (`tls internal`)
- Pour passer en production : remplacer `tls internal` par le nom de domaine, Caddy obtient automatiquement un certificat Let's Encrypt
- Redirige automatiquement `:80` vers `:443`

## 5. Comptes seedés au démarrage

Les scripts `scripts/start.sh` et `scripts/start.ps1` créent automatiquement trois comptes au premier lancement :

| Compte | Mot de passe | Rôle |
|--------|--------------|------|
| `admin` | `admin123` | admin |
| `analyst` | `analyst123` | analyst |
| `reader` | `reader123` | reader |

La création utilise l'endpoint `POST /api/auth/register` puis met à jour le rôle via SQL si nécessaire. Les emails sont en `@toolboxv8.fr` (Pydantic v2 valide strictement le TLD, `.local` est rejeté).

## 6. Composants Backend

| Fichier | Rôle |
|---------|------|
| `app/main.py` | Entrée du service API (port 8000), routes `/api/*` |
| `app/web_main.py` | Entrée du service WEB (port 3000), Jinja2 + proxy |
| `app/web/proxy.py` | Proxy HTTP transparent vers l'API interne |
| `app/core/config.py` | Settings Pydantic (`SECRET_KEY`, `INTERNAL_API_URL`, `ALLOWED_HOSTS`) |
| `app/core/security.py` | JWT (create/decode), bcrypt, Fernet |
| `app/core/auth.py` | Dépendances FastAPI : `get_current_user`, `require_admin`, `require_analyst` |
| `app/core/database.py` | SQLAlchemy engine + session |
| `app/models/` | ORM : `User`, `ScanJob`, `Report`, `AuditLog` |
| `app/api/routes/` | `auth.py`, `users.py`, `modules.py`, `reports.py`, `dashboard.py`, `defensive.py`, `pages.py` |
| `app/modules/offensive/` | `passive_recon.py`, `recon.py`, `scan.py`, `exploit.py`, `web_scan.py`, `post_exploit.py` |
| `app/modules/defensive/` | `siem.py`, `ids.py`, `response.py`, `forensic.py` |
| `app/tasks/` | `scan_tasks.py`, `report_tasks.py`, `celery_app.py` |
| `app/reporting/generator.py` | Génération PDF (ReportLab) + HTML (Jinja2) |

## 7. Modèle de données

```
User       (id, username, email, hashed_pwd, role, is_active, created_at, last_login)
  │
  ├─► ScanJob  (id, task_id, module, target, options, status, result, created_by, created_at)
  │
  ├─► Report   (id, title, scan_job_id, format, file_path, created_by, created_at)
  │
  └─► AuditLog (id, user_id, action, detail, ip_address, timestamp)
```

`ScanJob.result` est un JSON stockant `{data: {...}, logs: [{time, msg}]}`. Le champ `data` contient les résultats normalisés par outil : `{command, output, stderr, profile, credentials, cracked}`.

`AuditLog.detail` est un champ Text (string) contenant une description lisible de l'action (ex. `created user 'bob' with role 'analyst'`).

## 8. RBAC (rôles)

| Rôle | Droits |
|------|--------|
| `admin` | Gestion des utilisateurs via `/admin/users`, accès à tous les jobs et rapports, accès SIEM |
| `analyst` | Lancer des scans, générer des rapports, uploader des wordlists |
| `reader` | Consultation seule des rapports |

Le rôle est inscrit dans le JWT (`role` claim) et vérifié via les dépendances `require_admin` / `require_analyst`.

**Trois couches de protection** :
1. **Backend (API)** : chaque endpoint sensible utilise `Depends(require_admin)` ou `Depends(require_analyst)`
2. **Backend (pages)** : les routes `pages.py` redirigent vers `/dashboard` si le rôle est insuffisant (`/admin/users` admin only, `/siem` admin only, `/modules` bloqué pour `reader`)
3. **Frontend (UI)** : `loadUserInfo()` dans `app.js` cache les éléments avec les classes `nav-admin-only` et `nav-not-reader` selon le rôle décodé du token

## 9. Orchestration Celery

Chaque lancement de scan depuis l'UI :

```
POST /api/modules/launch {module, target, options}
  │
  ▼
api.routes.modules.launch_module
  │  valide target/options, crée ScanJob pending
  │  envoie tasks.run_<module> sur Redis
  ▼
worker pentest_worker (Kali)
  │  importe app.modules.offensive.<Module>
  │  exécute l'outil (subprocess.run)
  │  collecte stdout/stderr + parse éventuel
  │  update_state(PROGRESS, {percent, step, logs})
  ▼
retour Celery → ScanJob.status = done, ScanJob.result = {data, logs}
```

La progression en temps réel est en polling depuis le front (`GET /api/modules/jobs/{id}`). Pas de WebSocket pour rester simple.

## 10. Image Kali (worker)

Le `Dockerfile.celery` est un **build multi-stage** :

- **Stage 1** : `python:3.11-slim-bookworm` + Poetry → exporte `requirements.txt` (évite les frictions PEP 668 de Kali).
- **Stage 2** : `kalilinux/kali-rolling` → `apt install` des outils offensifs (**nmap, nikto, sqlmap, hydra, john + wordlists, metasploit-framework, whois, dnsutils**) + installation des deps Python dans `/opt/venv` à partir du `requirements.txt` exporté.

Le binaire `john` est en version **jumbo** (304 formats de hash supportés). `rockyou.txt` est décompressé automatiquement pour Hydra/John.

## 11. Volume partagé wordlists

Pour permettre à l'utilisateur d'uploader ses propres listes d'users / passwords / wordlists depuis l'UI (Hydra, John), un volume Docker **`wordlists_data`** est monté en `/tmp/wordlists` dans `api` et dans `worker`.

- `POST /api/modules/wordlist` (multipart) : l'API sauve le fichier dans le volume.
- Le chemin absolu `/tmp/wordlists/<uuid>_<nom>` est renvoyé au client.
- Lors d'un scan Hydra/John, le client passe ce chemin dans `user_file`, `pass_file` ou `wordlist_file`, le worker le lit dans le même volume.

## 12. Cible vulnérable intégrée

Pour les démos sans VM externe, le compose inclut un conteneur `target` (image `linuxserver/openssh-server`) avec un compte SSH faible :

- Hostname interne : `target`
- Port exposé : `2222`
- Credentials : `pentest_user` / `toor`

Ce conteneur est utilisé en démo pour montrer Hydra trouvant le mot de passe sur le réseau Docker (cible `target:2222`).

## 13. Rapport PDF

Le générateur [app/reporting/generator.py](../backend/app/reporting/generator.py) construit le PDF avec **ReportLab** :

- Header : eyebrow + titre + sous-titre + tableau métadonnées 4 colonnes
- Encart CODIR orange (synthèse exécutive)
- Bloc statistiques 3 colonnes
- **Déroulé technique par outil** : erreur / commande / sortie console (monospace préformaté) / résultats (liste si credentials cassés) / stderr / détails
- Tableau synthétique
- Recommandations + annexes + footer paginé

La fonction `_build_tools_sections(result)` normalise les résultats de chaque outil pour que le même template serve PDF et HTML.

## 14. Flux attaque → détection

```
1. Analyst → /modules → choisit "Scan de vulnérabilités" → lance
2. API crée ScanJob → Celery exécute nmap --script=vuln + nikto
3. Résultats stockés en DB (JSON)
4. Snort détecte le scan (local.rules) → /var/log/snort/alert
5. Logstash ingère /var/log/snort/alert → Elasticsearch
6. /siem affiche les alertes (Chart.js)
7. Analyst → /reports → génère un PDF → stocké dans MinIO
```

## 15. Sécurité en bref

- **HTTPS** : Caddy en frontal, certificat auto-signé en local, Let's Encrypt en prod
- **Auth** : JWT signé HS256 (SECRET_KEY env), bcrypt pour les mots de passe
- **Cookie web** : `HttpOnly`, `SameSite=Lax`, `Secure` automatique en HTTPS
- **RBAC** : 3 rôles, 3 comptes seedés, page de gestion `/admin/users`
- **Chiffrement** : Fernet pour les secrets stockés
- **Audit** : `AuditLog` horodaté pour login, lancement de scan, génération de rapport, actions sur les utilisateurs
- **TrustedHost + CORS** : middlewares activés sur les deux services
- **Isolation** : les outils pentest tournent dans le worker Kali, pas dans l'API (moins de surface)

## 16. Évolutivité

- **Ajouter un module** : créer un fichier dans `app/modules/offensive/` + une tâche Celery dans `app/tasks/scan_tasks.py` + un entry dans `MODULES` dans `routes/modules.py` + éventuellement une fiche UI dans `modules.html`.
- **Scalabilité** : plusieurs workers Celery possibles (augmenter `concurrency` ou lancer des replicas Docker).
- **API versionnée** : le préfixe `/api/` facilite un futur `/api/v2`.
- **Plugins** : le pattern est volontairement simple (dict de modules) pour rester extensible sans framework complexe.
