# Livrables Pédagogiques - Mastère Cybersécurité

## Rappel des livrables exigés

Selon le cadre pédagogique (Projet d'Études - CS - 2025), deux livrables principaux sont à rendre **6 mois après le kick-off** :

---

## Livrable 1 - Vidéo MVP (15-20 minutes)

### Objectif
Démontrer le MVP en action devant un jury.

### Contenu attendu

| Partie | Durée estimée | Ce à montrer |
|--------|--------------|--------------|
| Présentation de l'équipe et du contexte | 2 min | Membres, rôles, problématique client |
| Analyse du problème | 2 min | Pourquoi automatiser les pentests ? |
| Organisation & méthodologie | 2 min | Sprints, outils, répartition |
| Démonstration technique | 10-12 min | Voir ci-dessous |
| Conclusion & perspectives | 1-2 min | Ce qui reste à faire |

### Scénario de démo recommandé

```
1. Connexion sur l'interface ToolboxV8 (https://localhost/dashboard, rôle analyst)
2. Lancer un module Recon sur une VM cible (ex: Metasploitable2)
3. Voir les résultats en temps réel sur le dashboard
4. Simuler une attaque (scan vuln + exploit SQLmap)
5. Montrer les alertes Snort dans Kibana (SIEM)
6. Déclencher une réponse active (blocage IP)
7. Générer un rapport PDF de l'audit
8. Télécharger et montrer le rapport
```

### Format de livraison

**Option 1 - ZIP** :
```
PE_2526_codepromo_noms.zip
└── PE-2526_codepromo_NomPrenom.mp4
```

**Option 2 - YouTube** :
```
PE_2526_codepromo_noms.txt (contient le lien YouTube non répertorié)
```

### Conseils
- Soigner l'audio (micro de qualité, pas d'écho)
- Utiliser des dashboards Kibana visibles à l'écran
- Chaque membre doit prendre la parole
- Préparer un environnement de démo stable (VM isolée)

---

## Livrable 2 - Document Technique Final

### Rendu Groupe (PDF)

#### Structure recommandée

**1. Présentation du projet**
- Contexte client et enjeux
- Équipe et rôles
- Planning (diagramme Gantt ou backlog Scrum)

**2. Analyse**
- Surfaces d'attaque identifiées
- Menaces ciblées (DDoS, phishing, RCE, SQLi, bruteforce…)
- Matrice de risques

**3. Organisation & Méthodologie**
- Méthode Agile (sprints, vélocité)
- Outils de gestion (Jira/Trello/Notion)
- Git workflow

**4. Solution Technique**
- Architecture (reprendre `docs/architecture.md`)
- Modules implémentés et justification des choix technologiques
- Intégration SIEM / IDS
- Sécurité de l'outil lui-même (reprendre `docs/securite.md`)
- Résultats des tests (reprendre les rapports générés)
- REX incidents (problèmes rencontrés et solutions)

#### Annexes suggérées
- Diagramme d'architecture
- Captures d'écran de l'interface
- Extraits de logs Kibana
- Rapport d'un scan de test
- Backlog Scrum
- Résultats des tests unitaires

### Rendu Individuel

Chaque membre rédige **séparément** :
- Analyse critique de son travail et de l'équipe
- Compétences développées (liste des blocs de compétences)
- Perspectives d'amélioration
- Réflexion personnelle sur la posture professionnelle

### Format de livraison

```
PE_2526_codepromo_noms.zip
├── rendu_groupe.pdf
└── rendu_individuel_NomPrenom.pdf  (un par membre)
```

---

## Grille d'évaluation (indicative)

| Critère | Points |
|---------|--------|
| Fonctionnement du MVP | 20 |
| Qualité technique (code, archi, sécurité) | 20 |
| Couverture des modules (offensif + défensif) | 15 |
| SIEM & détection (ELK + Snort) | 10 |
| Reporting automatisé | 10 |
| Documentation | 10 |
| Présentation & posture professionnelle | 10 |
| Rendu individuel | 5 |
| **Total** | **100** |

---

## Correspondance modules / cours

| Élément ToolboxV8 | Cours associés |
|---------------------|----------------|
| Modules offensifs (Nmap, SQLmap, Hydra) | Sécurité offensive, Cryptologie |
| ELK Stack + Snort | SIEM, DevSecOps |
| IAM / JWT / RBAC | IAM, Management Sécurité |
| Module forensique | Forensique, Reverse Engineering |
| CI/CD + Docker | DevSecOps, PRA/PCA |
| Reporting & Documentation | Management Sécurité |
