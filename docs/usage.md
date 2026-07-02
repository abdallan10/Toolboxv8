# Guide d'Utilisation - ToolboxV8

## 1. Connexion

Accéder à : `https://localhost/dashboard` (redirige vers `/login` si non authentifié).

> Le service web est exposé en HTTPS via Caddy (port 443). Une CA interne génère le certificat ; pour éviter le warning navigateur, importer le certificat racine une fois (cf. README).

Trois comptes seedés au premier démarrage :

| Compte | Mot de passe | Rôle |
|--------|--------------|------|
| `admin` | `admin123` | Tout, y compris gestion des utilisateurs |
| `analyst` | `analyst123` | Lancement de scans et génération de rapports |
| `reader` | `reader123` | Consultation seule des rapports |

Se connecter avec ses identifiants via le formulaire du service **web**. Celui-ci effectue `POST /login` qui appelle en interne `POST /api/auth/token` et **pose le JWT dans un cookie `HttpOnly`** (`access_token=...`).

> Le cookie HttpOnly n'est pas accessible en JavaScript côté navigateur : c'est volontairement plus sûr que l'ancien stockage en `localStorage`, car cela bloque l'exfiltration en cas de faille XSS.

Pour les **clients externes** (scripts, CI, Postman), il reste toujours possible de récupérer un JWT classique avec `POST /api/auth/token` et de l'envoyer via l'en-tête `Authorization: Bearer <token>`.

---

## 2. Dashboard

Le dashboard affiche :

- **KPIs** : nombre de scans totaux, terminés, en erreur, rapports générés
- **Derniers jobs** : liste des 10 dernières tâches avec statut en temps réel
- **Derniers rapports** : accès direct au téléchargement

La barre latérale est filtrée selon le rôle :
- `reader` : voit uniquement Dashboard et Rapports
- `analyst` : voit aussi Modules
- `admin` : voit aussi SIEM, Utilisateurs et la section Défensif

---

## 3. Lancer un module

### Via l'interface

1. Aller sur **Modules** dans la barre latérale (visible pour `analyst` et `admin`)
2. Sélectionner le module voulu
3. Renseigner la cible (mot-clé OSINT, IP, domaine ou URL selon le module)
4. Choisir un profil via les chips ou activer les toggles d'outils
5. Cliquer sur **Lancer**

Le job s'exécute en arrière-plan. Son statut se met à jour automatiquement.

### Modules disponibles

| Module | Cible | Profils / outils |
|--------|-------|------------------|
| `passive_recon` | Mot-clé, entreprise, domaine | Catalogue de 24 dorks (Google, Bing, DuckDuckGo) en 3 catégories : Mot-clé, Réseaux sociaux, Domaine. Ouverture multi-onglets, dorks personnalisés possibles. |
| `recon` | IP, domaine | Nmap (Quick / Standard / Full TCP / Stealth), DNS, whois, WhatWeb |
| `scan` | IP, domaine | Nmap NSE (Quick / Standard / Full / Safe), Nikto (Quick / Standard / Full / Evasion), SSLyze (Cert / Standard / Full) |
| `exploit` | URL, IP, hash | SQLmap (Quick / Standard / Aggressive / Dump), Hydra, John, Metasploit (handler / EternalBlue / PortScan / SMB) |
| `web_scan` | URL | OWASP ZAP Spider (Quick / Standard / Deep), ZAP Active (Quick / OWASP / Full), Gobuster, Dependency-Check |
| `response` | IP | Blocage iptables, isolation host, alerte SIEM |

### Profils par chips

Les modules offensifs proposent des **profils prédéfinis sous forme de chips**, plus besoin d'éditer la ligne de commande. Il suffit de cliquer sur la chip correspondante pour charger les bons paramètres.

### Wordlists custom (Hydra / John)

Les modules **Hydra** et **John** acceptent 3 sources de wordlist au choix :

1. Un **fichier uploadé** via `POST /api/modules/wordlist` (stocké dans le volume partagé `wordlists_data`)
2. Une **liste manuelle** (saisie dans une modale, un mot par ligne)
3. La **rockyou.txt** préinstallée dans l'image worker Kali

### Via l'API

```bash
# Obtenir un token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/token \
  -d "username=admin&password=admin123" | jq -r .access_token)

# Lancer une reconnaissance
curl -X POST http://localhost:8000/api/modules/launch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "recon", "target": "192.168.1.1", "options": {"whois": true}}'
```

---

## 4. Suivre un job

```bash
# Lister ses jobs
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/modules/jobs

# Détail d'un job (résultat + état Celery)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/modules/jobs/1
```

---

## 5. Générer un rapport

```bash
# Générer un rapport PDF depuis un job terminé (ReportLab)
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_job_id": 1, "title": "Rapport audit 192.168.1.1", "format": "pdf"}'

# Télécharger
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/reports/1/download -o rapport.pdf
```

> Les rapports sont générés en **PDF** via **ReportLab**, avec une vue HTML alignée sur le PDF pour la prévisualisation dans le navigateur.

---

## 6. Gestion des utilisateurs (admin)

La page `/admin/users` (réservée au rôle `admin`) permet :

- Créer un compte avec rôle au choix
- Modifier le rôle ou le mot de passe d'un compte existant
- Activer ou désactiver un compte
- Supprimer un compte

Toutes ces actions sont tracées dans la table `audit_logs`. Un admin ne peut pas se rétrograder, se désactiver ni se supprimer lui-même.

L'équivalent en API :

```bash
# Lister les comptes
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/users/

# Créer un compte
curl -X POST http://localhost:8000/api/users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@toolboxv8.fr","password":"BobSecure1!","role":"analyst"}'
```

---

## 7. SIEM avec Kibana

1. Accéder à `http://localhost:5601`
2. Aller dans **Discover**
3. Créer un index pattern : `pentest-logs-*`
4. Visualiser les événements de scan, alertes IDS, actions de réponse

Une vue simplifiée intégrée est aussi disponible dans l'app sur `/siem` (admin uniquement), avec des graphiques Chart.js.

Dashboards recommandés à créer dans Kibana :
- Vue chronologique des scans
- Alertes Snort par classification
- Actions de réponse (blocages IP)

---

## 8. Réponse active

```bash
# Bloquer une IP suspecte
curl -X POST http://localhost:8000/api/modules/launch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "response", "target": "10.0.0.5", "options": {"action": "block_ip", "reason": "bruteforce SSH détecté"}}'
```

---

## 9. Forensique (bonus)

```bash
# Scanner un fichier suspect
curl -X POST http://localhost:8000/api/modules/launch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "forensic", "target": "/uploads/fichier_suspect.exe", "options": {}}'
```
