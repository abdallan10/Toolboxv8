"""
Module Reconnaissance passive (OSINT)
---------------------------------------
Génère des Google Dorks (et URLs de recherche) prêts à lancer
pour une cible donnée (domaine ou organisation).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

# {target} = chaîne nettoyée (domaine OU mot-clé libre selon le dork)
DORK_TEMPLATES: dict[str, dict[str, str]] = {
    # ── Mot-clé général (cible = nom, marque, sujet libre) ──
    "kw_pdf": {
        "name": "PDF mentionnant la cible",
        "category": "Mot-clé",
        "query": '"{target}" filetype:pdf',
        "desc": "PDFs du web entier mentionnant le mot-clé.",
    },
    "kw_office": {
        "name": "Documents Office",
        "category": "Mot-clé",
        "query": '"{target}" (filetype:doc | filetype:docx | filetype:xls | filetype:xlsx | filetype:ppt | filetype:pptx)',
        "desc": "Documents bureautiques mentionnant le mot-clé.",
    },
    "kw_intitle": {
        "name": "Pages avec ce titre",
        "category": "Mot-clé",
        "query": 'intitle:"{target}"',
        "desc": "Pages dont le titre contient le mot-clé.",
    },
    "kw_cv": {
        "name": "CV / Curriculum",
        "category": "Mot-clé",
        "query": '"{target}" ("CV" | "curriculum vitae" | "resume") filetype:pdf',
        "desc": "CV au format PDF mentionnant le mot-clé.",
    },
    "kw_leaks": {
        "name": "Fuites / breaches",
        "category": "Mot-clé",
        "query": '"{target}" ("leaked" | "leak" | "breach" | "dump" | "database")',
        "desc": "Mentions de fuites de données associées au mot-clé.",
    },
    "kw_creds": {
        "name": "Mentions de credentials",
        "category": "Mot-clé",
        "query": '"{target}" ("password" | "passwd" | "credentials" | "api_key")',
        "desc": "Contenu mentionnant le mot-clé + mots-clés de credentials.",
    },
    # ── Réseaux sociaux / plateformes ──
    "social_linkedin": {
        "name": "LinkedIn",
        "category": "Réseaux sociaux",
        "query": '"{target}" site:linkedin.com',
        "desc": "Profils et pages LinkedIn associés au mot-clé.",
    },
    "social_github": {
        "name": "GitHub",
        "category": "Réseaux sociaux",
        "query": '"{target}" site:github.com',
        "desc": "Dépôts, profils et code GitHub.",
    },
    "social_twitter": {
        "name": "Twitter / X",
        "category": "Réseaux sociaux",
        "query": '"{target}" (site:twitter.com | site:x.com)',
        "desc": "Tweets et profils.",
    },
    "social_reddit": {
        "name": "Reddit",
        "category": "Réseaux sociaux",
        "query": '"{target}" site:reddit.com',
        "desc": "Discussions Reddit.",
    },
    "social_facebook": {
        "name": "Facebook",
        "category": "Réseaux sociaux",
        "query": '"{target}" site:facebook.com',
        "desc": "Pages et profils Facebook.",
    },
    "social_pastebin": {
        "name": "Pastebin / pastes",
        "category": "Réseaux sociaux",
        "query": '"{target}" (site:pastebin.com | site:paste.ee | site:ghostbin.com)',
        "desc": "Pastes publics mentionnant le mot-clé.",
    },
    # ── Dorks domaine (cible = domaine ou IP) ──
    "site": {
        "name": "Pages indexées",
        "category": "Domaine",
        "query": "site:{target}",
        "desc": "Toutes les pages indexées par le moteur pour ce domaine.",
    },
    "subdomains": {
        "name": "Sous-domaines",
        "category": "Domaine",
        "query": "site:*.{target} -www",
        "desc": "Sous-domaines hors www (selon indexation du moteur).",
    },
    "pdf": {
        "name": "PDF du domaine",
        "category": "Domaine",
        "query": "site:{target} ext:pdf",
        "desc": "Fichiers PDF hébergés sur le domaine.",
    },
    "office": {
        "name": "Office du domaine",
        "category": "Domaine",
        "query": "site:{target} (ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx)",
        "desc": "Documents bureautiques potentiellement sensibles.",
    },
    "configs": {
        "name": "Fichiers de configuration",
        "category": "Domaine",
        "query": "site:{target} (ext:conf | ext:cfg | ext:ini | ext:env | ext:yml | ext:yaml)",
        "desc": "Configs, .env, YAML — souvent source de fuites.",
    },
    "sql_logs": {
        "name": "SQL / logs / backups",
        "category": "Domaine",
        "query": "site:{target} (ext:sql | ext:log | ext:bak | ext:old | ext:backup)",
        "desc": "Dumps SQL, journaux et sauvegardes exposés.",
    },
    "admin": {
        "name": "Panneaux d'administration",
        "category": "Domaine",
        "query": "site:{target} (inurl:admin | inurl:administrator | inurl:wp-admin)",
        "desc": "Interfaces d'administration et back-office.",
    },
    "login": {
        "name": "Pages de connexion",
        "category": "Domaine",
        "query": "site:{target} (inurl:login | inurl:signin | intitle:login)",
        "desc": "Portails d'authentification et formulaires.",
    },
    "directory_listing": {
        "name": "Directory listing",
        "category": "Domaine",
        "query": 'site:{target} intitle:"index of"',
        "desc": "Listings de répertoires ouverts.",
    },
    "api_keys": {
        "name": "Clés / secrets exposés",
        "category": "Domaine",
        "query": 'site:{target} ("api_key" | "apikey" | "secret" | "password" | "token")',
        "desc": "Chaînes ressemblant à des secrets dans le contenu indexé.",
    },
    "emails": {
        "name": "Emails du domaine",
        "category": "Domaine",
        "query": 'intext:"@{target}"',
        "desc": "Adresses e-mail associées au domaine.",
    },
    "errors": {
        "name": "Messages d'erreur",
        "category": "Domaine",
        "query": 'site:{target} ("sql syntax" | "warning:" | "fatal error" | "stack trace")',
        "desc": "Pages affichant des erreurs applicatives ou SQL.",
    },
}

SEARCH_ENGINES: dict[str, dict[str, str]] = {
    "google": {
        "name": "Google",
        "url": "https://www.google.com/search?q={q}",
    },
    "bing": {
        "name": "Bing",
        "url": "https://www.bing.com/search?q={q}",
    },
    "duckduckgo": {
        "name": "DuckDuckGo",
        "url": "https://duckduckgo.com/?q={q}",
    },
}


def normalize_target(target: str) -> str:
    t = target.strip().lower()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/")[0].split(":")[0]
    if t.startswith("www."):
        t = t[4:]
    return t


def build_search_url(engine: str, query: str) -> str:
    eng = SEARCH_ENGINES.get(engine, SEARCH_ENGINES["google"])
    return eng["url"].format(q=quote_plus(query))


class PassiveReconModule:
    def run(self, target: str, options: dict) -> dict:
        domain = normalize_target(target)
        engine = options.get("engine", "google")
        if engine not in SEARCH_ENGINES:
            engine = "google"

        selected = options.get("dorks") or []
        if isinstance(selected, str):
            selected = [s.strip() for s in selected.split(",") if s.strip()]

        custom = options.get("custom_dorks") or []
        if isinstance(custom, str):
            custom = [ln.strip() for ln in custom.splitlines() if ln.strip()]

        dorks_out: list[dict[str, Any]] = []
        for key in selected:
            tpl = DORK_TEMPLATES.get(key)
            if not tpl:
                continue
            query = tpl["query"].format(target=domain)
            dorks_out.append({
                "id": key,
                "name": tpl["name"],
                "category": tpl["category"],
                "desc": tpl["desc"],
                "query": query,
                "url": build_search_url(engine, query),
            })

        for i, raw in enumerate(custom):
            query = raw.replace("{target}", domain)
            label = query if len(query) <= 48 else query[:45] + "…"
            dorks_out.append({
                "id": f"custom_{i}",
                "name": f"Personnalisé — {label}",
                "category": "Personnalisé",
                "desc": "Dork saisi manuellement",
                "query": query,
                "url": build_search_url(engine, query),
            })

        return {
            "target": target,
            "domain": domain,
            "engine": engine,
            "engine_label": SEARCH_ENGINES[engine]["name"],
            "dorks": dorks_out,
            "count": len(dorks_out),
        }
