# Modules ToolboxV8 - Référence

Tous les outils offensifs sont **préinstallés dans l'image Kali Rolling** du worker Celery (voir [architecture.md §8](architecture.md)). Le retour de chaque outil est normalisé :

```python
{
  "command":   "nmap -sV --top-ports 100 192.168.1.1",   # commande réellement exécutée
  "profile":   "standard",                                 # si le module utilise des profils
  "output":    "<stdout CLI brut, tel qu'en terminal>",
  "stderr":    "…",
  "credentials": [...]   # optionnel, si l'outil produit une liste (hydra / john)
}
```

Le rapport PDF reprend ces champs un par un.

---

## Modules offensifs

### 1. Reconnaissance passive (`passive_recon`)

**Fichier** : [backend/app/modules/offensive/passive_recon.py](../backend/app/modules/offensive/passive_recon.py)

**Outils** : génération et ouverture de **Google Dorks**, **Bing Dorks** et **DuckDuckGo Dorks** dans le navigateur. Aucun trafic réseau direct vers la cible : on interroge uniquement les moteurs de recherche.

**Catalogue de 24 templates** organisé en 3 catégories :

| Catégorie | Exemples de dorks |
|-----------|-------------------|
| Mot-clé | `intitle:"<cible>"`, `inurl:"<cible>"`, `"<cible>" filetype:pdf`, `"<cible>" intext:password`, `"<cible>" ext:log` |
| Réseaux sociaux | `site:linkedin.com/in "<cible>"`, `site:twitter.com "<cible>"`, `site:github.com "<cible>"`, `site:pastebin.com "<cible>"`, `site:reddit.com "<cible>"` |
| Domaine | `site:<cible>`, `site:<cible> filetype:pdf`, `site:<cible> intitle:"index of"`, `site:<cible> inurl:admin`, `site:<cible> ext:env OR ext:bak` |

**Options UI** :

| Option | Type | Description |
|--------|------|-------------|
| `target` | string | Mot-clé, nom d'entreprise, personne ou domaine |
| `dorks` | array | Liste des templates cochés (et/ou dorks personnalisés saisis manuellement) |
| `engine` | enum | `google` (défaut), `bing` ou `duckduckgo` |

**Comportement** : à la soumission, chaque dork est ouvert dans un onglet séparé. Les requêtes sont aussi loggées dans le job pour générer un rapport PDF avec la liste exacte des dorks utilisés.

> Ce module est **passif** : il ne touche jamais la cible, seulement les moteurs de recherche. Idéal pour de l'OSINT en amont d'un pentest sans laisser de trace côté cible.

---

### 2. Reconnaissance active (`recon`)

**Fichier** : [backend/app/modules/offensive/recon.py](../backend/app/modules/offensive/recon.py)

**Outils** : `nmap`, `whois`, résolution DNS native.

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `nmap_args` | string | `-sV -O -Pn --top-ports 1000` | Arguments Nmap (utilisés tels quels). `-Pn` permet de scanner les hosts qui bloquent ICMP (firewall Windows, gateways). |
| `whois` | bool | `false` | Activer le lookup whois |

**Presets Nmap disponibles (UI)** :

| Profil | Arguments |
|--------|-----------|
| Quick | `-sS -Pn --top-ports 100 -T4` |
| Standard | `-sV -O -Pn --top-ports 1000` |
| Full TCP | `-sS -sV -O -Pn -p- -T4 --script=default` |
| Stealth | `-sS -Pn -T2 -f --top-ports 1000` |

**Post-traitement** :

- Les blocs `==NEXT SERVICE FINGERPRINT==` dumpés par nmap pour les services inconnus sont filtrés de la sortie (inutiles dans un rapport).
- Whois retombe automatiquement sur le domaine racine si le sous-domaine est rejeté (`scanme.nmap.org` → `nmap.org`).

**Retour (exemple)** :

```json
{
  "target": "192.168.1.1",
  "dns":    {"command": "resolve 192.168.1.1", "output": "; Résolution DNS…\n;; ANSWER SECTION:\n192.168.1.1. IN A 192.168.1.1", "resolved_ip": "192.168.1.1"},
  "nmap":   {"command": "nmap -sV -O -Pn --top-ports 1000 192.168.1.1", "output": "Starting Nmap 7.99…\nPORT  STATE…", "stderr": ""},
  "whois":  "…"
}
```

---

### 3. Scan de vulnérabilités (`scan`)

**Fichier** : [backend/app/modules/offensive/scan.py](../backend/app/modules/offensive/scan.py)

**Outils** : `nmap --script=<catégorie>`, `nikto`, `sslyze` (binaire Kali).

**Profils Nmap NSE** (chips UI) : catégorie de scripts appliquée :

| Profil | Scripts |
|--------|---------|
| Quick | `--script=default -Pn` |
| Standard | `--script=vuln -Pn` (détection CVE, défaut) |
| Full | `--script=vuln,exploit,auth -Pn` |
| Safe | `--script=safe -Pn` (non destructif) |

Timeout fixé à **20 minutes** (cible un port précis avec l'option `port` si ta cible a beaucoup de ports ouverts).

**Profils Nikto** (chips UI) : timeout Python adapté par profil :

| Profil | Tuning | Timeout |
|--------|--------|---------|
| Quick | `-Tuning x` (tests de base) | 10 min |
| Standard | `-Tuning x6` (CGI + fichiers + config + injection) | 30 min |
| Full | `-Tuning 0123456789abc` (tous les modules) | 60 min |
| Evasion | `-Tuning x -evasion 1` | 15 min |

**Profils SSLyze** (chips UI) : sslyze ≥ 5.x, `--regular` a disparu, on passe les scans individuellement ou via `--mozilla_config` :

| Profil | Arguments |
|--------|-----------|
| Certificat | `--certinfo` |
| Standard | `--mozilla_config intermediate --certinfo --http_headers --elliptic_curves` |
| Full | `--certinfo --elliptic_curves --http_headers --tlsv1_2 --tlsv1_3 --tlsv1_1 --tlsv1 --sslv2 --sslv3 --compression --reneg --resum --heartbleed --robot --openssl_ccs --fallback --ems --early_data` |

**Options UI** :

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `nmap_vuln` | bool | `true` | Activer Nmap NSE |
| `nikto` | bool | `true` | Activer Nikto |
| `sslyze` | bool | `false` | Activer SSLyze |
| `port` | string | `"80,443"` | Port(s) web testé(s). Accepte `80`, `80,443`, `1-1000` |
| `nmap_vuln_profile` | enum | `standard` | Profil Nmap NSE (`quick` / `standard` / `full` / `safe`) |
| `nikto_profile` | enum | `standard` | Profil Nikto |
| `sslyze_profile` | enum | `standard` | Profil SSLyze |

---

### 4. Exploitation (`exploit`)

**Fichier** : [backend/app/modules/offensive/exploit.py](../backend/app/modules/offensive/exploit.py)

**Outils** : `sqlmap`, `hydra`, `john the ripper` (version jumbo, 304 formats), `Metasploit` (via MSFRPC).

Le dropdown **Outil d'exploitation** sélectionne un sous-module (`mode`) :

#### 4.1 SQLmap (`mode=sqlmap`)

| Profil | Arguments (batch + --output-dir=/tmp/sqlmap imposés) |
|--------|------|
| Quick | `--level=1 --risk=1` |
| Standard | `--level=3 --risk=2 --random-agent --threads=4` |
| Aggressive | `--level=5 --risk=3 --random-agent --threads=10 --tamper=space2comment` |
| Dump DB | `--level=1 --risk=1 --dbs --tables --dump` |

Option : `sqlmap_profile` (enum, défaut `standard`).

#### 4.2 Hydra (`mode=hydra`)

| Option | Description |
|--------|-------------|
| `service` | `ssh`, `ftp`, `rdp`, `smb`, `mysql`, `vnc`, `telnet`, `http-post-form`, `http-get` |
| `port` | Port TCP optionnel (sinon port par défaut du service) |
| `threads` | `-t N`, défaut 4 |
| `user_file` / `users_inline` | Chemin d'une wordlist uploadée **ou** chaîne avec un login par ligne |
| `pass_file` / `passwords_inline` / `use_rockyou` | Idem pour les mots de passe, avec option rockyou.txt |

L'UI propose 2 « sources » pour users et 3 pour passwords (fichier uploadé / modale manuelle / rockyou.txt).

#### 4.3 John the Ripper (`mode=john`)

La **cible** est le hash brut (ou un chemin de fichier `/tmp/…`).

| Option | Description |
|--------|-------------|
| `format` | Format de hash (`md5crypt`, `sha512crypt`, `NT`, `bcrypt`, `argon2`… ou vide pour auto-détection) |
| `wordlist_file` / `wordlist_inline` / `use_rockyou` | Wordlist personnalisée (upload / manuelle / défaut) |
| `rules` | bool, active `--rules` (mutations leet, suffixes…) |
| `timeout` | secondes, défaut 180 |

#### 4.4 Metasploit (`mode=msf`)

| Profil | Module MSF | Options auto |
|--------|-----------|--------------|
| Handler | `exploit/multi/handler` | `PAYLOAD=generic/shell_reverse_tcp`, `LHOST=0.0.0.0`, `LPORT=4444` |
| EternalBlue | `exploit/windows/smb/ms17_010_eternalblue` | `PAYLOAD=windows/x64/meterpreter/reverse_tcp` |
| PortScan | `auxiliary/scanner/portscan/tcp` | `PORTS=1-65535` |
| SMB Vuln | `auxiliary/scanner/smb/smb_ms17_010` | (aucune option spécifique) |

Chaque profil ajoute automatiquement `RHOSTS=<cible>`. Requiert un démon `msfrpcd` joignable (`msf_host`, `msf_port`, `msf_password`).

> **Avertissement** : uniquement sur des cibles pour lesquelles vous avez une autorisation écrite.

---

### 5. Scan Web / API (`web_scan`)

**Fichier** : [backend/app/modules/offensive/web_scan.py](../backend/app/modules/offensive/web_scan.py)

**Outils** : OWASP ZAP (via API HTTP), Dependency-Check (optionnel).

**Profils ZAP Spider** :

| Profil | Paramètres ZAP |
|--------|----------------|
| Quick | `maxChildren=50, recurse=false` |
| Standard | `maxChildren=200, recurse=true` |
| Deep | `maxChildren=1000, recurse=true, subtreeOnly=false` |

**Profils ZAP Active** :

| Profil | Paramètres ZAP |
|--------|----------------|
| Quick | `recurse=false, scanPolicyName=XSS-SQLi` |
| OWASP | `recurse=true, scanPolicyName=OWASP-Top10` |
| Full  | `recurse=true, scanPolicyName=Default Policy` |

**Options UI** :

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `zap` | bool | `true` | Lancer ZAP |
| `scan_type` | enum | `spider` | `spider` ou `active` |
| `zap_url` | string | `http://localhost:8080` | URL de l'instance ZAP |
| `zap_spider_profile` | enum | `standard` | Profil Spider |
| `zap_active_profile` | enum | `owasp` | Profil Active |
| `dep_check` | bool | `false` | Activer Dependency-Check |

---

### 6. Post-exploitation (`post_exploit`)

**Fichier** : [backend/app/modules/offensive/post_exploit.py](../backend/app/modules/offensive/post_exploit.py)

Actions :

- `enumerate` : liste des commandes d'énumération locale (users, processes, sudo, SUID)
- `persistence_check` : vérification des mécanismes de persistance (cron, rc.local, systemd)

> Ce module est documentaire (il retourne les commandes recommandées, il ne les exécute pas sur la cible distante).

---

## Modules défensifs

### 7. SIEM (`siem`)

**Fichier** : [backend/app/modules/defensive/siem.py](../backend/app/modules/defensive/siem.py)

Interface avec Elasticsearch :

- `index_event(type, data)` : indexe un événement
- `search_events(query)` : recherche full-text
- `get_recent_alerts()` : dernières alertes

Tous les résultats de scan sont automatiquement indexés dans `pentest-logs-*`.

### 8. IDS (`ids`)

**Fichier** : [backend/app/modules/defensive/ids.py](../backend/app/modules/defensive/ids.py)

Parse les alertes Snort depuis `/var/log/snort/alert`. Règles locales fournies ([siem/snort/local.rules](../siem/snort/local.rules)) :

- Détection scan Nmap SYN
- Brute-force SSH / HTTP Basic
- SQL Injection / XSS / Directory Traversal

### 9. Réponse active (`response`)

**Fichier** : [backend/app/modules/defensive/response.py](../backend/app/modules/defensive/response.py)

- `block_ip(ip, reason)` : règle iptables `DROP`
- `unblock_ip(ip)` : suppression de la règle
- `isolate_host(ip)` : isolation réseau (à connecter à un hyperviseur)
- `send_alert(message, severity)` : alerte vers le SIEM

### 10. Forensique (`forensic`) (bonus)

**Fichier** : [backend/app/modules/defensive/forensic.py](../backend/app/modules/defensive/forensic.py)

- `ClamAV` : antivirus open-source
- `VirusTotal API v3` : analyse multi-moteurs

Méthodes : `scan_file(path)`, `get_vt_result(analysis_id)`.

---

## Endpoint d'upload de wordlists

Pour Hydra et John, l'utilisateur peut fournir ses propres listes via :

```http
POST /api/modules/wordlist   (multipart/form-data : file=...)

Réponse 201 :
{
  "path":     "/tmp/wordlists/<uuid>_users.txt",
  "filename": "users.txt",
  "size":     142,
  "lines":    18
}
```

Le chemin retourné est directement utilisable comme `user_file` / `pass_file` / `wordlist_file` dans l'option du module. Limite : 200 MB. Le fichier est accessible au worker via le volume Docker partagé `wordlists_data`.

## Format de résultat unifié

Toutes les sorties d'outils offensifs alimentent le rapport via la fonction `_format_tool_data(tool, data)` du générateur PDF ([generator.py](../backend/app/reporting/generator.py)), qui extrait :

- `error` : encart rouge si échec
- `command` : ligne inline monospace
- `main_output` (`output` / `raw_xml` / `stdout`) : bloc préformaté noir
- `stderr` : bloc noir séparé
- `results_list` (`credentials` / `cracked`) : liste verte
- `extras_json` : JSON indenté pour les clés non interprétées

Le résultat : chaque outil apparaît dans le PDF avec sa sortie CLI **telle qu'en terminal**.
