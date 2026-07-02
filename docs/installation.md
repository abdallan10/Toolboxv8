# Guide d'Installation - ToolboxV8

## Prérequis

| Outil | Version minimale | Vérification |
|-------|-----------------|--------------|
| Docker | 24.x | `docker --version` |
| Docker Compose | 2.x | `docker compose version` |
| Git | 2.x | `git --version` |
| (optionnel) Python | 3.11+ | `python --version` |
| (optionnel) Poetry | 1.8+ | `poetry --version` |

> L'installation via Docker ne nécessite **pas** Python sur l'hôte.

---

## Installation rapide (Docker)

### 1. Cloner le dépôt

```bash
git clone https://gitlab.com/<votre-groupe>/toolbox-pentest.git
cd toolbox-pentest
```

### 2. Configurer l'environnement

```bash
cp .env.example .env
```

Modifier `.env` selon votre environnement :

```env
SECRET_KEY=<générer avec : openssl rand -hex 32>
FERNET_KEY=<générer avec : python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
VIRUSTOTAL_API_KEY=<optionnel>
```

### 3. Lancer la stack

```bash
./scripts/start.sh
```

Ou manuellement :

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

### 4. Vérifier que tout tourne

```bash
docker compose -f docker/docker-compose.yml ps
```

Tous les services doivent être en état `running` ou `healthy`.

La stack comprend désormais **3 services applicatifs** :

- **api** (FastAPI, port **8000**) : expose l'API REST (`/api/*`)
- **web** (FastAPI, port **3000**) : sert les pages HTML et agit comme proxy `/api/*` vers l'api, pose le cookie HttpOnly d'authentification
- **worker** (Celery, image **Kali Rolling**) : exécute les modules offensifs

Le worker Celery est basé sur `kalilinux/kali-rolling` (Dockerfile multi-stage) avec tous les outils offensifs préinstallés : nmap, nikto, sqlmap, hydra, john-jumbo, sslyze, msfconsole, ainsi que la wordlist `rockyou.txt`.

Volumes Docker persistés :

- `postgres_data` : données PostgreSQL
- `minio_data` : stockage objet des rapports
- `wordlists_data:/tmp/wordlists` : volume **partagé entre `api` et `worker`** pour les wordlists uploadées via `POST /api/modules/wordlist`

### 5. Créer le premier administrateur

> **Note** : si tu as démarré la stack avec `scripts/start.sh` ou `scripts/start.ps1`, les **3 comptes par défaut** sont créés automatiquement :
>
> | Compte | Mot de passe | Rôle |
> |---|---|---|
> | `admin`   | `admin123`   | admin (tout faire, gestion utilisateurs) |
> | `analyst` | `analyst123` | analyst (lancer scans) |
> | `reader`  | `reader123`  | reader (lecture seule) |
>
> Tu peux sauter l'étape ci-dessous et te connecter directement.

Sinon, crée-le manuellement :

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@pentestbox.com","password":"admin123","role":"admin"}'
```

Puis connecte-toi sur http://localhost:3000/login avec `admin` / `admin123`.

⚠️ **En production**, change immédiatement ce mot de passe (créé un autre compte, supprime celui-là, ou update en DB).

---

## Installation locale (développement)

### 1. Installer les dépendances

```bash
cd backend
poetry install
```

### 2. Démarrer les services tiers

```bash
docker compose -f docker/docker-compose.yml up -d db redis minio elasticsearch
```

### 3. Configurer la DB

```bash
# Dans le dossier backend/
DATABASE_URL=postgresql://pentest:pentest@localhost:5432/pentestdb \
  python -c "from app.core.database import engine, Base; from app.models import user, scan; Base.metadata.create_all(bind=engine)"
```

### 4. Lancer l'API

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Lancer le worker Celery

```bash
cd backend
celery -A app.tasks.celery_app worker --loglevel=info
```

---

## Accès aux interfaces

| Service | URL | Identifiants par défaut |
|---------|-----|------------------------|
| Interface Web / Login | http://localhost:3000/login | Créer via `/api/auth/register` |
| API REST | http://localhost:8000/api/ | (token Bearer) |
| Swagger UI | http://localhost:8000/api/docs | (token Bearer) |
| Kibana (SIEM) | http://localhost:5601 | elastic / changeme |
| MinIO Console | http://localhost:9001 | minioadmin / minioadmin |

---

## Résolution de problèmes

### La DB ne démarre pas

```bash
docker compose -f docker/docker-compose.yml logs db
```

Vérifier que le port 5432 n'est pas déjà utilisé.

### Celery ne se connecte pas à Redis

```bash
docker compose -f docker/docker-compose.yml logs worker
```

Vérifier `REDIS_URL` dans `.env`.

### Modules nmap/nikto non disponibles

Ces outils doivent être installés **dans le conteneur**. Vérifier le `Dockerfile.celery`.

Pour un test local sans Docker, les installer sur l'hôte :

```bash
# Debian/Ubuntu
sudo apt-get install nmap nikto
```
