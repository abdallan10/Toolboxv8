import logging
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────────

def _progress(task, pct: int, step: str, logs: list):
    logs.append({"time": datetime.now(timezone.utc).strftime("%H:%M:%S"), "msg": step})
    task.update_state(
        state="PROGRESS",
        meta={"percent": pct, "step": step, "logs": list(logs)},
    )


# ── Reconnaissance ─────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_recon")
def run_recon(self, target: str, options: dict) -> dict:
    logs = []
    p = lambda pct, msg: _progress(self, pct, msg, logs)

    p(2,  f"Initialisation du module Reconnaissance sur {target}...")
    p(5,  "Chargement des dépendances et configuration du module...")
    p(8,  "Vérification de la connectivité réseau vers la cible...")

    from app.modules.offensive.recon import ReconModule
    module = ReconModule()

    p(12, f"Résolution DNS de {target}...")
    p(15, "Récupération des enregistrements A, MX, NS, TXT...")
    dns = module._dns_lookup(target)
    p(20, f"DNS résolu : {dns.get('ip', 'N/A') if isinstance(dns, dict) else str(dns)[:60]}")

    p(25, "Préparation du scan Nmap...")
    nmap_args = options.get("nmap_args", "-sV -O -Pn --top-ports 1000")
    p(30, f"Lancement Nmap avec les options : {nmap_args}")
    p(35, "Détection des ports ouverts en cours (TCP SYN scan)...")
    p(42, "Fingerprinting des services et versions...")
    p(50, "Détection du système d'exploitation (TTL, TCP/IP stack)...")
    nmap = module._nmap_scan(target, options)
    p(60, "Nmap terminé — analyse des résultats...")

    if options.get("whois"):
        p(65, f"Requête Whois pour {target}...")
        p(70, "Récupération des informations d'enregistrement du domaine...")
        whois = module._whois(target)
        p(75, "Whois récupéré : organisation, dates d'enregistrement, contacts...")
    else:
        p(68, "Whois désactivé (option non sélectionnée).")
        whois = ""

    whatweb = {}
    if options.get("whatweb"):
        p(78, "WhatWeb : fingerprinting des technologies web (CMS, frameworks, serveur)...")
        p(82, "WhatWeb : analyse des en-têtes HTTP, cookies et balises meta...")
        whatweb = module._whatweb(target, options)
        p(86, "WhatWeb terminé — technologies identifiées.")
    else:
        p(76, "WhatWeb désactivé (option non sélectionnée).")

    p(88, "Consolidation des données DNS, Nmap, Whois et WhatWeb...")
    p(92, "Analyse des services exposés et des vecteurs d'attaque potentiels...")
    p(96, "Génération du résumé de reconnaissance...")
    result = {"target": target, "dns": dns, "nmap": nmap, "whois": whois, "whatweb": whatweb}

    p(95, "Finalisation et mise en forme des résultats...")
    p(100, "Reconnaissance terminée avec succès.")
    return {
        "status": "done",
        "result": result,
        "logs": logs,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Reconnaissance passive (OSINT / Dorking) ───────────────────────────────

@celery_app.task(bind=True, name="tasks.run_passive_recon")
def run_passive_recon(self, target: str, options: dict) -> dict:
    logs = []
    p = lambda pct, msg: _progress(self, pct, msg, logs)

    p(5,  f"Initialisation OSINT — Reconnaissance passive sur {target}...")
    p(15, "Normalisation du domaine cible...")
    p(25, "Sélection des Google Dorks et du moteur de recherche...")

    from app.modules.offensive.passive_recon import PassiveReconModule
    module = PassiveReconModule()

    p(45, "Génération des requêtes de dorking prêtes à lancer...")
    result = module.run(target, options)
    count = result.get("count", 0)
    engine = result.get("engine_label", "Google")

    p(70, f"{count} dork(s) généré(s) pour {engine}.")
    p(85, "Construction des URLs de recherche...")
    p(95, "Reconnaissance passive terminée — liens prêts à ouvrir.")
    p(100, f"OSINT terminé : {count} recherche(s) disponible(s).")

    return {
        "status": "done",
        "result": result,
        "logs": logs,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Scan Vulnérabilités ────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_scan")
def run_scan(self, target: str, options: dict) -> dict:
    logs = []
    p = lambda pct, msg: _progress(self, pct, msg, logs)

    p(2,  f"Initialisation du scan de vulnérabilités sur {target}...")
    p(5,  "Chargement de la base de données CVE locale...")
    p(8,  "Vérification de la disponibilité de la cible (ping/TCP)...")

    from app.modules.offensive.scan import ScanModule
    module = ScanModule()

    nmap_vuln = {}
    if options.get("nmap_vuln", True):
        p(12, "Chargement des scripts Nmap NSE (vuln, safe, default)...")
        p(15, "Lancement du scan Nmap avec scripts de détection de vulnérabilités...")
        p(20, "Vérification CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell)...")
        p(28, "Analyse des services SMB, FTP, SSH, HTTP pour failles connues...")
        p(35, "Nmap NSE : vérification des certificats SSL expirés ou faibles...")
        nmap_vuln = module._nmap_vuln(target, options)
        p(42, f"Nmap NSE terminé — {len(nmap_vuln) if isinstance(nmap_vuln, (list, dict)) else 0} résultat(s) trouvé(s).")
    else:
        p(25, "Nmap NSE désactivé.")

    nikto_result = {}
    if options.get("nikto", True):
        p(45, "Connexion à Nikto pour l'analyse du serveur web...")
        p(50, "Nikto : scan des en-têtes HTTP (X-Frame-Options, CSP, HSTS)...")
        p(55, "Nikto : détection des fichiers sensibles exposés (.env, .git, backup)...")
        p(60, "Nikto : vérification des CVE web (Apache, Nginx, IIS, PHP)...")
        p(65, "Nikto : test des méthodes HTTP dangereuses (PUT, DELETE, TRACE)...")
        nikto_result = module._nikto(target, options)
        p(70, "Nikto terminé — analyse des vulnérabilités web.")
    else:
        p(52, "Nikto désactivé.")

    ssl_result = {}
    if options.get("sslyze"):
        p(72, "Lancement de SSLyze — audit de la configuration TLS/SSL...")
        p(75, "Vérification du protocole : TLS 1.0/1.1 (deprecated), TLS 1.2/1.3...")
        p(78, "Analyse des suites de chiffrement (RC4, DES, 3DES — faibles)...")
        p(82, "Vérification du certificat : validité, CN, SAN, chaîne de confiance...")
        ssl_result = module._sslyze(target)
        p(86, "SSLyze terminé.")
    else:
        p(74, "SSLyze désactivé.")

    p(88, "Consolidation et déduplication des vulnérabilités détectées...")
    p(92, "Classification par criticité (Critical / High / Medium / Low)...")
    p(96, "Génération des recommandations de remédiation...")
    result = {"target": target, "nmap_vuln": nmap_vuln, "nikto": nikto_result, "sslyze": ssl_result}

    p(98, "Mise en forme du rapport de scan...")
    p(100, "Scan de vulnérabilités terminé.")
    return {
        "status": "done",
        "result": result,
        "logs": logs,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Exploitation ───────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_exploit")
def run_exploit(self, target: str, options: dict) -> dict:
    logs = []
    p = lambda pct, msg: _progress(self, pct, msg, logs)
    mode = options.get("mode", "sqlmap")

    p(2,  f"Initialisation du module Exploitation (mode: {mode}) sur {target}...")
    p(5,  "Vérification des prérequis et outils disponibles...")
    p(8,  "Analyse préliminaire de la surface d'attaque...")

    from app.modules.offensive.exploit import ExploitModule
    module = ExploitModule()

    if mode == "sqlmap":
        p(12, "SQLmap : détection du SGBD (MySQL, PostgreSQL, MSSQL, Oracle)...")
        p(18, "SQLmap : identification des paramètres GET/POST injectables...")
        p(25, f"SQLmap : lancement du scan (level={options.get('level', 1)}, risk={options.get('risk', 1)})...")
        p(32, "SQLmap : test des injections booléennes (Boolean-based blind)...")
        p(40, "SQLmap : test des injections temporelles (Time-based blind)...")
        p(48, "SQLmap : test des injections UNION SELECT...")
        p(55, "SQLmap : test des injections basées sur les erreurs (Error-based)...")
        p(62, "SQLmap : tentative d'extraction des noms de bases de données...")
        p(70, "SQLmap : extraction des tables et colonnes si vulnérable...")
        result_data = module._sqlmap(target, options)
        p(80, "SQLmap : analyse des injections trouvées et évaluation du risque...")

    elif mode == "hydra":
        service = options.get("service", "ssh")
        p(12, f"Hydra : préparation du brute-force sur le service {service.upper()}...")
        p(20, "Hydra : chargement de la wordlist (top 1000 mots de passe)...")
        p(28, f"Hydra : connexion au service {service.upper()} sur {target}...")
        p(38, "Hydra : tentatives d'authentification en cours (par lot de 16)...")
        p(50, "Hydra : rotation des credentials — attaque par dictionnaire active...")
        p(62, "Hydra : vérification des réponses du serveur (succès/échec)...")
        p(72, "Hydra : analyse des résultats positifs...")
        result_data = module._hydra(target, options)
        p(85, "Hydra : compilation des credentials trouvés...")

    elif mode == "msf":
        exploit_module = options.get("exploit", "exploit/multi/handler")
        p(12, "Metasploit : connexion au serveur MSFRPC...")
        p(20, "Metasploit : authentification et démarrage de la console...")
        p(30, f"Metasploit : chargement du module {exploit_module}...")
        p(38, "Metasploit : configuration des options (RHOSTS, RPORT, PAYLOAD)...")
        p(45, "Metasploit : sélection du payload adapté à la cible...")
        p(55, "Metasploit : lancement de l'exploit...")
        p(65, "Metasploit : attente de la connexion du payload...")
        p(72, "Metasploit : analyse de la réponse de la cible...")
        result_data = module._metasploit(target, options)
        p(85, "Metasploit : récupération du résultat de l'exploitation...")

    elif mode == "john":
        fmt      = options.get("format") or "auto"
        wordlist = options.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
        p(12, f"John the Ripper : préparation du cassage (format={fmt})...")
        p(18, f"John : chargement de la wordlist {wordlist}...")
        p(26, "John : détection automatique du format de hash...")
        p(34, "John : normalisation des hashes (suppression sel/UID)...")
        p(42, "John : lancement du mode wordlist (mots + règles de mutation)...")
        p(52, "John : essai des mots de passe du dictionnaire...")
        p(62, "John : application des règles de transformation (leetspeak, suffixes)...")
        p(72, "John : vérification des hashes cassés via --show...")
        result_data = module._john(target, options)
        p(82, "John : compilation des credentials cassés...")

    else:
        result_data = {"error": f"Mode inconnu : {mode}"}
        p(85, f"Mode {mode} non reconnu.")

    p(88, "Consolidation du rapport d'exploitation...")
    p(92, "Évaluation de l'impact et classification CVSS...")
    p(96, "Génération des recommandations de remédiation...")
    result = {"target": target, "mode": mode, **result_data}

    p(98, "Mise en forme du rapport...")
    p(100, "Module Exploitation terminé.")
    return {
        "status": "done",
        "result": result,
        "logs": logs,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Web / API Scan ─────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_web_scan")
def run_web_scan(self, target: str, options: dict) -> dict:
    logs = []
    p = lambda pct, msg: _progress(self, pct, msg, logs)
    scan_type = options.get("scan_type", "spider")

    p(2,  f"Initialisation du scan Web/API sur {target}...")
    p(5,  "Vérification de l'accessibilité de la cible (HTTP/HTTPS)...")
    p(8,  "Détection du serveur web (Apache, Nginx, IIS, frameworks)...")

    from app.modules.offensive.web_scan import WebScanModule
    module = WebScanModule()

    if options.get("zap", True):
        p(12, "Connexion à OWASP ZAP (Zed Attack Proxy)...")
        p(15, "ZAP : démarrage du proxy et configuration de la session...")

        if scan_type == "spider":
            p(20, "ZAP Spider passif : découverte des URLs et endpoints...")
            p(28, "ZAP Spider : analyse des liens, formulaires et paramètres...")
            p(35, "ZAP Spider : cartographie de l'application web...")
            p(42, "ZAP Spider : détection des endpoints API (REST/GraphQL)...")
            p(48, "ZAP : scan passif des réponses HTTP (en-têtes, cookies)...")
        else:
            p(18, "ZAP Spider actif : crawl complet de l'application...")
            p(25, "ZAP Spider : exploration des formulaires et inputs...")
            p(32, "ZAP Active Scan : fuzzing des paramètres GET/POST...")
            p(40, "ZAP : test d'injection XSS (reflected, stored, DOM-based)...")
            p(47, "ZAP : test d'injection SQL via les formulaires web...")
            p(53, "ZAP : test CSRF, SSRF, Open Redirect...")
            p(58, "ZAP : vérification des headers de sécurité manquants...")

        zap_result = module._zap_scan(target, options)
        p(65, "ZAP : récupération et classification des alertes (High/Medium/Low)...")
        p(72, "ZAP : analyse OWASP Top 10 — corrélation des vulnérabilités...")
        p(76, "ZAP : génération du rapport d'alertes...")
    else:
        p(30, "ZAP désactivé.")
        zap_result = {}

    gobuster_result = {}
    if options.get("gobuster"):
        p(78, "Gobuster : énumération de répertoires et fichiers cachés...")
        p(82, "Gobuster : brute-force des chemins HTTP (wordlist)...")
        gobuster_result = module._gobuster(target, options)
        found = gobuster_result.get("paths_found", 0) if isinstance(gobuster_result, dict) else 0
        p(86, f"Gobuster terminé — {found} entrée(s) dans la sortie.")
    else:
        p(76, "Gobuster désactivé (option non sélectionnée).")

    dep_result = {}
    if options.get("dep_check"):
        p(88, "OWASP Dependency-Check : analyse des dépendances du projet...")
        p(82, "Dependency-Check : téléchargement de la base CVE NVD...")
        p(86, "Dependency-Check : vérification des bibliothèques tierces (npm, pip, maven)...")
        p(90, "Dependency-Check : détection des CVE dans les dépendances...")
        dep_result = module._dependency_check(options.get("project_path", "."))
        p(93, "Dependency-Check terminé.")
    else:
        p(80, "Dependency-Check désactivé.")

    p(88, "Corrélation et classification des vulnérabilités web...")
    p(93, "Génération du plan de remédiation OWASP Top 10...")
    p(96, "Calcul du score de risque global de l'application...")
    result = {"target": target, "zap": zap_result, "gobuster": gobuster_result, "dependency_check": dep_result}

    p(98, "Mise en forme du rapport Web/API...")
    p(100, "Scan Web/API terminé.")
    return {
        "status": "done",
        "result": result,
        "logs": logs,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
