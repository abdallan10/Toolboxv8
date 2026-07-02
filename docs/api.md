# Référence API REST - ToolboxV8

> Documentation Swagger interactive : `http://localhost:8000/api/docs`

## Authentification

Toutes les routes (sauf `/health` et `/api/auth/token`) nécessitent un JWT.

L'API accepte **deux méthodes** d'authentification équivalentes :

- En-tête HTTP `Authorization: Bearer <access_token>` (clients externes, scripts, CI)
- Cookie `access_token=<jwt>` (utilisé automatiquement par le service **web** sur le port 3000, posé en `HttpOnly` lors du login)

```
Authorization: Bearer <access_token>
```

---

## Auth `/api/auth`

### POST `/api/auth/token`
Obtenir un token JWT.

**Body** (form-data) :
```
username=admin
password=admin123
```

> Les 3 comptes par défaut seedés au démarrage : `admin/admin123`, `analyst/analyst123`, `reader/reader123`. Ils doivent être changés avant toute mise en production.

**Réponse 200** :
```json
{"access_token": "eyJ...", "token_type": "bearer"}
```

---

### POST `/api/auth/register`
Créer un compte utilisateur. Ouvert par défaut (peut être restreint en production).

**Body** (JSON) :
```json
{
  "username": "alice",
  "email": "alice@toolboxv8.fr",
  "password": "SecurePass1!",
  "role": "analyst"
}
```

**Réponse 201** :
```json
{"id": 4, "username": "alice", "email": "alice@toolboxv8.fr", "role": "analyst", "is_active": true}
```

---

### GET `/api/auth/me`
Profil de l'utilisateur connecté.

**Réponse 200** :
```json
{"id": 1, "username": "admin", "email": "admin@toolboxv8.fr", "role": "admin", "is_active": true}
```

---

## Utilisateurs `/api/users` (admin uniquement)

Endpoints de gestion des comptes accessibles uniquement avec le rôle `admin`. Toutes les actions sont tracées dans `audit_logs`.

### GET `/api/users/`
Lister tous les comptes.

**Réponse 200** :
```json
[
  {"id": 1, "username": "admin", "email": "admin@toolboxv8.fr", "role": "admin", "is_active": true},
  {"id": 2, "username": "analyst", "email": "analyst@toolboxv8.fr", "role": "analyst", "is_active": true},
  {"id": 3, "username": "reader", "email": "reader@toolboxv8.fr", "role": "reader", "is_active": true}
]
```

---

### POST `/api/users/`
Créer un compte.

**Body** (JSON) :
```json
{
  "username": "bob",
  "email": "bob@toolboxv8.fr",
  "password": "BobSecure1!",
  "role": "analyst"
}
```

**Réponse 201** : objet utilisateur (sans le mot de passe).

---

### PATCH `/api/users/{id}`
Modifier le rôle, le mot de passe ou l'état d'un compte.

**Body** (JSON, tous les champs optionnels) :
```json
{
  "role": "reader",
  "password": "NouveauMdp2!",
  "is_active": false
}
```

**Garde-fous** : un admin ne peut pas se rétrograder ni se désactiver lui-même (renvoie `400`).

---

### DELETE `/api/users/{id}`
Supprimer un compte.

**Garde-fou** : un admin ne peut pas se supprimer lui-même (renvoie `400`).

**Réponse 204** : aucun contenu.

---

## Modules `/api/modules`

### GET `/api/modules/`
Lister les modules disponibles.

**Réponse 200** :
```json
{
  "modules": [
    {"name": "passive_recon", "description": "Reconnaissance OSINT par dorks Google/Bing/DuckDuckGo"},
    {"name": "recon",         "description": "Reconnaissance active (Nmap, DNS, whois, WhatWeb)"},
    {"name": "scan",          "description": "Scan de vulnérabilités (Nmap NSE, Nikto, SSLyze)"},
    {"name": "exploit",       "description": "Exploitation (SQLmap, Hydra, John, Metasploit)"},
    {"name": "web_scan",      "description": "Analyse Web/API (OWASP ZAP, Gobuster, Dependency-Check)"},
    {"name": "response",      "description": "Réponse active défensive (blocage IP, alertes SIEM)"}
  ]
}
```

---

### POST `/api/modules/launch`
Lancer un module. Rôle requis : `analyst` ou `admin`.

**Body** :
```json
{
  "module": "recon",
  "target": "192.168.1.100",
  "options": {
    "whois": true,
    "nmap_args": "-sV -T4 --top-ports 100"
  }
}
```

**Réponse 202** :
```json
{
  "id": 5,
  "task_id": "a1b2c3d4-...",
  "module": "recon",
  "target": "192.168.1.100",
  "status": "pending"
}
```

---

### GET `/api/modules/jobs`
Lister ses jobs (admin voit tous les jobs).

### GET `/api/modules/jobs/{job_id}`
Détail d'un job avec état Celery en temps réel.

---

### POST `/api/modules/wordlist`
Uploader une wordlist custom (utilisable ensuite par les modules **Hydra** et **John**). Rôle requis : `analyst` ou `admin`.

Le fichier est stocké dans le volume Docker partagé `wordlists_data` (monté sur `/tmp/wordlists` côté `api` et côté `worker`).

**Requête** : `multipart/form-data`

| Champ | Type | Description |
|-------|------|-------------|
| `file` | file | Fichier texte (un mot par ligne) |

**Exemple curl** :
```bash
curl -X POST http://localhost:8000/api/modules/wordlist \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@./passwords.txt"
```

**Réponse 201** :
```json
{
  "path": "/tmp/wordlists/passwords.txt",
  "filename": "passwords.txt",
  "size": 10240,
  "lines": 1337
}
```

Le champ `path` renvoyé peut être passé aux modules Hydra / John comme wordlist source.

---

## Rapports `/api/reports`

### POST `/api/reports/generate`
Générer un rapport. Rôle requis : `analyst` ou `admin`.

**Body** :
```json
{
  "scan_job_id": 5,
  "title": "Audit réseau 2026",
  "format": "pdf"
}
```

**Réponse 202** :
```json
{"task_id": "...", "message": "Génération du rapport lancée"}
```

---

### GET `/api/reports/`
Lister ses rapports (admin et reader voient tous les rapports).

### GET `/api/reports/{id}/download`
Télécharger un rapport (PDF, HTML ou CSV).

### GET `/api/reports/{id}/view`
Obtenir le rendu HTML du rapport (alignement visuel avec le PDF).

### DELETE `/api/reports/{id}`
Supprimer un rapport. Rôle requis : `analyst` ou `admin`.

---

## Défensif `/api/defensive`

### GET `/api/defensive/siem/events`
Lister les événements indexés dans Elasticsearch. Rôle requis : `admin`.

### GET `/api/defensive/siem/stats`
Statistiques agrégées (par type, par sévérité, par jour). Rôle requis : `admin`.

---

## Dashboard `/api/dashboard`

### GET `/api/dashboard/stats`
KPIs JSON pour le dashboard.

**Réponse 200** :
```json
{
  "total_jobs": 12,
  "done_jobs": 10,
  "error_jobs": 1,
  "total_reports": 7
}
```

---

## Codes d'erreur

| Code | Description |
|------|-------------|
| 400 | Données invalides (module inconnu, email déjà pris, action interdite sur soi-même) |
| 401 | Token absent ou expiré |
| 403 | Rôle insuffisant |
| 404 | Ressource introuvable |
| 422 | Erreur de validation Pydantic (ex. email invalide) |
| 500 | Erreur interne serveur |
