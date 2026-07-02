# Documentation ToolboxV8

Bienvenue dans la documentation complète de **ToolboxV8**, la toolbox automatisée de tests d'intrusion développée dans le cadre du Mastère Cybersécurité 2025/2026.

---

## 📌 Documents principaux (juin 2026)

Ces documents sont la **source de vérité** sur l'état réel du projet :

| Document | Description |
|----------|-------------|
| 📘 **[Rapport final de groupe (PDF)](PE-2526_M1CSD_NASR_BEN-RACHED_AKA-A-MFOULA.pdf)** | Rapport technique complet : architecture, modules, KPIs réels, REX, politiques de sécurité, conclusion. **Document principal à lire.** |
| 📋 **[guide_test_outils.txt](guide_test_outils.txt)** | Guide pratique : configs validées pour chaque outil avec cibles, profils et résultats attendus. **Pour reproduire les démos.** |
| 📝 [Rendu individuel Titouan (PDF)](PE-2526_M1CSD_AKA-A-MFOULA_Titouan.pdf) | Analyse personnelle, perspectives, compétences développées |
| 📝 [Rendu individuel Ayoub (PDF)](PE-2526_M1CSD_BEN-RACHED_Ayoub.pdf) | Analyse personnelle, perspectives, compétences développées |
| 📝 [Rendu individuel Abdallah (PDF)](PE-2526_M1CSD_NASR_Abdallah.pdf) | Analyse personnelle, perspectives, compétences développées |

---

## 📂 Documents techniques détaillés

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | Architecture (split api/web, Caddy HTTPS, flux d'auth, orchestration Celery, RBAC) |
| [installation.md](installation.md) | Guide d'installation pas à pas (Docker, configuration, comptes seedés) |
| [usage.md](usage.md) | Guide d'utilisation de l'interface et de l'API |
| [modules.md](modules.md) | Description détaillée de chaque module (passive_recon, recon, scan, exploit, web_scan, defensive) |
| [api.md](api.md) | Référence complète de l'API REST (endpoints auth, users, modules, reports, defensive) |
| [securite.md](securite.md) | Authentification, RBAC à 3 rôles, chiffrement, audit, conformité |
| [livrables.md](livrables.md) | Livrables pédagogiques et correspondance avec le cadre |

> 💡 **Pour le détail complet avec KPIs et REX**, voir [le rapport final de groupe (PDF)](PE-2526_M1CSD_NASR_BEN-RACHED_AKA-A-MFOULA.pdf) :
> - §1.4 équipe, §3.2 sprints (S1 à S10), §4 solution technique
> - §5 modules pentest (5 offensifs + 4 défensifs), §6 KPIs réels mesurés
> - §7 sécurité (incluant §7.6 Caddy HTTPS et §7.7 politiques), §8 SIEM
> - §9 REX, §10 conclusion et limites, §11 annexes

---

## Vue d'ensemble

ToolboxV8 est une plateforme web modulaire qui automatise les étapes d'un pentest :

```
OSINT → Reconnaissance → Scan de vulnérabilités → Exploitation → Scan Web/API
  ↑                                                                    ↓
SIEM ←──────────── Visualisation Elasticsearch ──────────────────────  ┘
  ↓
Snort (IDS, règles préparées)
  ↓
Response (iptables, isolation)
```

Le parcours utilisateur tient en 3 clics : **choisir le module, saisir la cible, cliquer sur Lancer**. Le rapport PDF est généré automatiquement et reprend la sortie CLI de chaque outil.

### Technologies principales

- **Backend** : Python 3.11 + FastAPI (2 services : api + web) + Celery
- **Frontend** : Jinja2 + HTML/CSS vanilla + Lucide icons
- **Base de données** : PostgreSQL 16
- **File de tâches** : Redis 7 + Celery 5
- **SIEM** : ELK Stack (Elasticsearch 8.13 + Logstash + Kibana)
- **IDS** : Snort 3 (règles préparées, conteneur non déployé, cf. §10.2)
- **Stockage** : MinIO (S3-compatible)
- **Worker pentest** : Kali Linux Rolling (image officielle, multi-stage build)
- **Reverse proxy TLS** : Caddy 2 (HTTPS auto via CA interne, Let's Encrypt en prod)
- **Scanner web** : OWASP ZAP 2.17 (daemon API intégré au compose)
- **Cible vulnérable** : conteneur SSH faible (`pentest_target` pour les démos Hydra)
- **Reporting** : ReportLab (PDF) + Jinja2 (HTML optionnel)
- **CI/CD** : GitHub Actions + GitLab CI (lint, tests, build Docker)
- **Conteneurisation** : Docker + Docker Compose

### Liens rapides

- **Interface web HTTPS** (recommandé) : `https://localhost`
- **Interface web HTTP** (fallback dev) : `http://localhost:3000`
- **API Swagger** (clients externes) : `http://localhost:8000/api/docs`
- **Kibana** (explorer brut des logs SIEM) : `http://localhost:5601`
- **MinIO Console** (stockage des rapports) : `http://localhost:9001`
