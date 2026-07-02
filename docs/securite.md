# Sécurité & Conformité - ToolboxV8

## 1. Authentification et autorisation

### JWT (JSON Web Tokens)
- Algorithme : **HS256**
- Signature via `SECRET_KEY` chargée depuis une **variable d'environnement** (jamais commit en dur)
- Expiration configurable (`ACCESS_TOKEN_EXPIRE_MINUTES`, défaut 60 min)
- Pas de session serveur (stateless) ; révocation possible via blacklist Redis (à implémenter en production)

### Stockage du token côté navigateur
- Le service **web** (port 3000) pose le JWT dans un **cookie `HttpOnly`** nommé `access_token` lors du `POST /login`
- Flags du cookie : `HttpOnly=true` (inaccessible en JavaScript, anti-XSS), `SameSite=Lax` (anti-CSRF de base), `Secure=true` en HTTPS
- Ce choix remplace l'ancien stockage `localStorage` : même en cas de faille XSS, le token ne peut pas être exfiltré par du JS tiers
- Les clients externes (API, CLI, CI) continuent d'utiliser l'en-tête `Authorization: Bearer <jwt>` classique

### RBAC (Role-Based Access Control)

Trois rôles sont définis. Les trois comptes correspondants sont **créés automatiquement au premier démarrage** par les scripts `start.sh` / `start.ps1` :

| Rôle | Compte seedé | Permissions |
|------|-------------|-------------|
| `admin` | `admin` / `admin123` | Tout accès, gestion des utilisateurs via la page `/admin/users`, lancement des scans, génération des rapports, accès SIEM |
| `analyst` | `analyst` / `analyst123` | Lancer des scans, générer et consulter les rapports |
| `reader` | `reader` / `reader123` | Lecture seule des rapports |

**Filtrage de l'interface par rôle** :
- Le menu latéral est filtré côté frontend (`app.js`, classes `nav-admin-only` et `nav-not-reader`)
- Les routes protégées (`/admin/users`, `/siem`, `/modules`) redirigent vers `/dashboard` si le rôle est insuffisant
- Les endpoints API `/api/users/*` renvoient `403` si l'appelant n'est pas admin

**Gestion des utilisateurs** (admin uniquement) :
- Page `/admin/users` avec formulaire de création, table des comptes, actions modifier rôle / mot de passe / désactiver / supprimer
- Endpoints REST `/api/users/` (GET, POST, PATCH, DELETE) protégés par `require_admin`
- Garde-fous : l'admin connecté ne peut pas se rétrograder, se désactiver ni se supprimer
- Toutes les actions sont tracées dans la table `audit_logs`

### Mots de passe
- Hachage : **bcrypt** (coût adaptatif, salage automatique, résistant aux attaques par dictionnaire et rainbow tables)
- Politique minimale recommandée en production : 12 caractères, majuscule + chiffre + symbole
- **Les mots de passe par défaut (`admin123`, `analyst123`, `reader123`) doivent être changés avant toute mise en production**, idéalement via la page `/admin/users`

---

## 2. Chiffrement

### Données en transit
- **HTTPS activé en local** via le reverse proxy **Caddy 2** (`caddy:2-alpine`) avec certificat auto-signé issu d'une CA interne (`/data/caddy/pki/authorities/local/root.crt`)
- En production : bascule sur Let's Encrypt en modifiant une ligne du `Caddyfile` (`tls internal` à remplacer par le domaine public)
- HSTS recommandé en production : `Strict-Transport-Security: max-age=31536000`
- Le port HTTP `:80` est automatiquement redirigé en `:443`

### Données au repos
- Chiffrement des données sensibles avec **Fernet** (AES-128-CBC + HMAC-SHA256)
- Clé générée via `cryptography.fernet.Fernet.generate_key()`
- En production : stocker la clé dans un gestionnaire de secrets (HashiCorp Vault, AWS SSM, Azure Key Vault)

---

## 3. Protection de l'API

### Middlewares actifs
- `TrustedHostMiddleware` : rejette les requêtes avec Host header invalide, activé sur les deux services (`api` port 8000 et `web` port 3000)
- `CORSMiddleware` : origines autorisées configurables, activé sur les deux services
- Rate limiting recommandé (à ajouter via `slowapi` ou au niveau Caddy)

### Injection
- Toutes les entrées utilisateur validées via **Pydantic v2** (validation stricte, EmailStr avec vérification du TLD)
- Requêtes SQL via **SQLAlchemy ORM** (pas de SQL brut)
- Échappement automatique dans les templates Jinja2 (`autoescape=True`)

### Dépendances
- Scan régulier avec `safety check` ou `pip-audit`
- Dependency-Check (OWASP) intégré comme module dans `web_scan`

---

## 4. Audit et journalisation

### Audit Log
Toutes les actions sensibles sont enregistrées dans la table `audit_logs` :
- Connexion / déconnexion
- Lancement de modules
- Génération de rapports
- Création / modification / suppression d'utilisateurs
- Erreurs d'authentification

La table est en append-only (aucun endpoint d'update ni de delete), avec horodatage et IP.

### SIEM (ELK Stack)
- Tous les événements de scan indexés dans Elasticsearch
- Alertes IDS (Snort) ingérées via Logstash
- Visualisation dans la page `/siem` (graphiques Chart.js) et dans Kibana
- Rétention des logs : 90 jours (configurable dans ILM Elasticsearch)

---

## 5. Conformité RGPD

| Exigence RGPD | Implémentation |
|---------------|----------------|
| Minimisation des données | Seules les données nécessaires sont collectées (username, email, rôle) |
| Droit à l'effacement | Endpoint `DELETE /api/users/{id}` côté admin |
| Sécurité des traitements | Chiffrement Fernet, RBAC strict, audit log append-only |
| Journaux d'accès | AuditLog horodaté avec IP |
| Consentement | Réservé à des cibles autorisées (contrat de prestation) |

> **Important** : ToolboxV8 ne doit être utilisé que dans le cadre de tests d'intrusion autorisés par écrit par le propriétaire de la cible.

---

## 6. Cadre légal

- Utilisation soumise à la loi n°88-19 du 5 janvier 1988 (CNIL) et au RGPD
- Chaque test doit faire l'objet d'une **lettre de mission signée**
- Les résultats doivent être traités comme **confidentiels**
- Interdiction d'utilisation sur des systèmes non autorisés

