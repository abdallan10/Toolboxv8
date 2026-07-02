"""
Module Web/API Scan
--------------------
Intègre :
  - OWASP ZAP (API mode)
  - Dependency-Check (OWASP)
  - SSLyze via module scan
"""

import os
import subprocess
import shutil
import time
import logging
import requests
from typing import Any

logger = logging.getLogger(__name__)


def _web_url(target: str, options: dict | None = None) -> str:
    opts = options or {}
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        scheme = opts.get("scheme", "http")
        host = t.split("/")[0]
        t = f"{scheme}://{host}"
    return t.rstrip("/")


class WebScanModule:
    def run(self, target: str, options: dict) -> dict:
        results: dict[str, Any] = {"target": target}

        if options.get("zap", True):
            results["zap"] = self._zap_scan(target, options)

        if options.get("gobuster", False):
            results["gobuster"] = self._gobuster(target, options)

        if options.get("dep_check", False):
            results["dependency_check"] = self._dependency_check(options.get("project_path", "."))

        return results

    # Profils ZAP Spider → paramètres de /JSON/spider/action/scan/
    _ZAP_SPIDER_PROFILES = {
        "quick":    {"maxChildren": "50",   "recurse": "false"},
        "standard": {"maxChildren": "200",  "recurse": "true"},
        "deep":     {"maxChildren": "1000", "recurse": "true", "subtreeOnly": "false"},
    }

    # Profils ZAP Active → paramètres de /JSON/ascan/action/scan/
    # Pas de scanPolicyName custom : ZAP utilise sa policy par défaut (toujours
    # présente). Les anciennes valeurs "XSS-SQLi" / "OWASP-Top10" provoquaient
    # une 400 Bad Request car ces policies n'existent pas par défaut.
    _ZAP_ACTIVE_PROFILES = {
        "quick":    {"recurse": "false"},
        "owasp":    {"recurse": "true"},
        "full":     {"recurse": "true", "scanPolicyName": "Default Policy"},
    }

    def _zap_scan(self, target: str, options: dict) -> dict:
        # Défauts alignés sur le service zap du docker-compose (réseau pentest_net).
        zap_url   = options.get("zap_url") or os.getenv("ZAP_URL", "http://zap:8080")
        zap_key   = options.get("zap_api_key") or os.getenv("ZAP_API_KEY", "zapsecret")
        scan_type = options.get("scan_type", "spider")

        if scan_type == "spider":
            endpoint = f"{zap_url}/JSON/spider/action/scan/"
            profile_key = options.get("zap_spider_profile", "standard")
            profile_params = self._ZAP_SPIDER_PROFILES.get(
                profile_key, self._ZAP_SPIDER_PROFILES["standard"]
            )
        elif scan_type == "active":
            endpoint = f"{zap_url}/JSON/ascan/action/scan/"
            profile_key = options.get("zap_active_profile", "owasp")
            profile_params = self._ZAP_ACTIVE_PROFILES.get(
                profile_key, self._ZAP_ACTIVE_PROFILES["owasp"]
            )
        else:
            return {"error": f"Type de scan ZAP inconnu : {scan_type}"}

        params = {"apikey": zap_key, "url": target, **profile_params}

        try:
            r = requests.get(endpoint, params=params, timeout=10)
            r.raise_for_status()
            scan_id = r.json().get("scan")
            status_path = "spider" if scan_type == "spider" else "ascan"
            pretty_params = " ".join(f"{k}={v}" for k, v in profile_params.items())

            # Polling jusqu'à fin du scan (max 8 min en Active, 3 min en Spider)
            max_wait = int(options.get("zap_max_wait", 480 if scan_type == "active" else 180))
            status_url = f"{zap_url}/JSON/{status_path}/view/status/"
            start = time.monotonic()
            last_status = "0"
            log_lines = [
                f"$ curl -s '{endpoint}?url={target}&{pretty_params}'",
                f"[+] Scan ZAP {scan_type} ({profile_key}) démarré → scan_id = {scan_id}",
                f"[+] Polling progression (timeout {max_wait}s)…",
            ]
            while time.monotonic() - start < max_wait:
                try:
                    sr = requests.get(status_url, params={"apikey": zap_key, "scanId": scan_id}, timeout=10)
                    last_status = sr.json().get("status", "0")
                    if last_status == "100":
                        break
                except requests.RequestException:
                    pass
                time.sleep(5)

            elapsed = int(time.monotonic() - start)
            log_lines.append(f"[+] Scan terminé à {last_status}% en {elapsed}s")

            # Récupération des alertes (Active uniquement — Spider ne génère pas d'alertes)
            alerts: list[dict] = []
            findings_summary: list[str] = []
            if scan_type == "active":
                try:
                    ar = requests.get(
                        f"{zap_url}/JSON/core/view/alerts/",
                        params={"apikey": zap_key, "baseurl": target},
                        timeout=15,
                    )
                    alerts = ar.json().get("alerts", []) or []
                except requests.RequestException as e:
                    log_lines.append(f"[!] Echec récupération alertes : {e}")

                # Agrégation par (nom, risque) pour ne pas spammer les doublons
                from collections import Counter
                counter: Counter = Counter()
                for a in alerts:
                    counter[(a.get("alert", "?"), a.get("risk", "?"))] += 1

                log_lines.append(f"[+] {len(alerts)} alertes trouvées ({len(counter)} types uniques)")
                # Tri par sévérité décroissante puis par occurrence
                risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
                items = sorted(counter.items(), key=lambda kv: (risk_order.get(kv[0][1], 9), -kv[1]))
                for (name, risk), count in items[:50]:
                    findings_summary.append(f"[{risk:13s}] x{count:<3d} {name}")
            else:
                # Spider : récupérer les URLs découvertes
                try:
                    ur = requests.get(
                        f"{zap_url}/JSON/spider/view/results/",
                        params={"apikey": zap_key, "scanId": scan_id},
                        timeout=15,
                    )
                    urls = ur.json().get("results", []) or []
                    log_lines.append(f"[+] {len(urls)} URLs découvertes par le Spider")
                    for u in urls[:30]:
                        findings_summary.append(u)
                except requests.RequestException as e:
                    log_lines.append(f"[!] Echec récupération URLs : {e}")

            output = "\n".join(log_lines)
            if findings_summary:
                output += "\n\n=== Résumé des découvertes ===\n" + "\n".join(findings_summary)

            return {
                "command": f"GET {endpoint}?url={target}&{pretty_params}",
                "profile": profile_key,
                "output": output,
                "scan_id": scan_id,
                "type": scan_type,
                "status_pct": last_status,
                "elapsed_s": elapsed,
                "alerts_count": len(alerts),
                "alerts": alerts[:50] if scan_type == "active" else None,
            }
        except requests.RequestException as e:
            return {"error": f"ZAP non disponible : {e}"}

    _GOBUSTER_PROFILES = {
        "quick": {
            "wordlist": "/usr/share/dirb/wordlists/common.txt",
            "threads": 10,
            "extra": "-q --no-error",
            "desc": "Wordlist courte (dirb/common) — scan rapide",
        },
        "standard": {
            "wordlist": "/usr/share/dirb/wordlists/small.txt",
            "threads": 20,
            "extra": "-q --no-error",
            "desc": "Liste dirb small — équilibre vitesse/couverture",
        },
        "full": {
            "wordlist": "/usr/share/dirb/wordlists/big.txt",
            "threads": 30,
            "extra": "-q --no-error",
            "desc": "Liste dirb big — plus exhaustif (long)",
        },
    }

    def _gobuster(self, target: str, options: dict) -> dict:
        if not shutil.which("gobuster"):
            return {"error": "gobuster non installé"}

        url = _web_url(target, options)
        profile_key = options.get("gobuster_profile", "standard")
        profile = self._GOBUSTER_PROFILES.get(
            profile_key, self._GOBUSTER_PROFILES["standard"]
        )
        wordlist = options.get("gobuster_wordlist") or profile["wordlist"]
        threads = int(options.get("gobuster_threads") or profile["threads"])
        extensions = (options.get("gobuster_extensions") or "").strip()

        if not os.path.isfile(wordlist):
            alt_wordlist = wordlist.replace("/usr/share/wordlists", "/usr/share/dirb/wordlists")
            if os.path.isfile(alt_wordlist):
                wordlist = alt_wordlist
            else:
                return {"error": f"Wordlist introuvable : {wordlist}"}

        try:
            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-t", str(threads),
            ]
            if extensions:
                cmd.extend(["-x", extensions])
            cmd.extend(profile["extra"].split())

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = (proc.stdout or "") + (proc.stderr or "")
            found = [
                ln.strip() for ln in output.splitlines()
                if ln.strip() and not ln.startswith("=") and "Progress" not in ln
            ]
            return {
                "command": " ".join(cmd),
                "url": url,
                "profile": profile_key,
                "wordlist": wordlist,
                "paths_found": len(found),
                "output": output.strip() or "(aucun chemin trouvé)",
            }
        except subprocess.TimeoutExpired:
            return {"error": "Timeout gobuster (600s)"}
        except Exception as e:
            return {"error": str(e)}

    def _dependency_check(self, project_path: str) -> dict:
        dc_bin = shutil.which("dependency-check") or shutil.which("dependency-check.sh")
        if not dc_bin:
            return {"error": "dependency-check non installé"}
        try:
            cmd = [dc_bin, "--project", "pentest", "--scan", project_path,
                   "--format", "HTML", "--out", "/tmp/depcheck"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return {
                "command": " ".join(cmd),
                "output": proc.stdout,
                "stderr": proc.stderr,
            }
        except Exception as e:
            return {"error": str(e)}
