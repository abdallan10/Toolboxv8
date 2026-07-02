"""
Module Scan de Vulnérabilités
------------------------------
Intègre :
  - Nmap NSE (scripts vulnérabilité)
  - Nikto (serveurs web)
  - SSLyze (audit TLS/SSL)
"""

import subprocess
import shutil
import socket
import logging
from typing import Any

from app.modules.offensive.recon import _strip_nmap_fingerprints

logger = logging.getLogger(__name__)


class ScanModule:
    def run(self, target: str, options: dict) -> dict:
        results: dict[str, Any] = {"target": target}

        results["nmap_vuln"] = self._nmap_vuln(target, options)

        if options.get("nikto", True):
            results["nikto"] = self._nikto(target, options)

        if options.get("sslyze", False):
            results["sslyze"] = self._sslyze(target, options)

        return results

    # Profils Nmap NSE → catégories de scripts appliquées.
    _NMAP_VULN_PROFILES = {
        "quick":    ["--script=default"],
        "standard": ["--script=vuln"],
        "full":     ["--script=vuln,exploit,auth"],
        "safe":     ["--script=safe"],
    }

    def _nmap_vuln(self, target: str, options: dict) -> dict:
        if not shutil.which("nmap"):
            return {"error": "nmap non installé"}
        port = options.get("port", "")
        port_arg = ["-p", str(port)] if port else []
        profile = options.get("nmap_vuln_profile", "standard")
        script_args = self._NMAP_VULN_PROFILES.get(profile, self._NMAP_VULN_PROFILES["standard"])
        try:
            cmd = ["nmap"] + script_args + ["-Pn"] + port_arg + [target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
            return {
                "command": " ".join(cmd),
                "profile": profile,
                "output": _strip_nmap_fingerprints(proc.stdout),
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout nmap vuln (> 20 min, profil '{profile}'). "
                             f"Limite avec l'option 'port' ou utilise 'Quick'."}
        except Exception as e:
            return {"error": str(e)}

    # Profils Nikto → options -Tuning (+ évasion) + timeout adapté (en secondes).
    # Standard (tuning x6) = ~6000 requêtes HTTP → 30 min mini sur cible distante.
    # Full (0123456789abc) = toute la base Nikto → jusqu'à 1h.
    _NIKTO_PROFILES = {
        "quick":    {"tuning": "x",            "evasion": None, "timeout":  600},
        "standard": {"tuning": "x6",           "evasion": None, "timeout": 1800},
        "full":     {"tuning": "0123456789abc", "evasion": None, "timeout": 3600},
        "evasion":  {"tuning": "x",            "evasion": "1",  "timeout":  900},
    }

    def _nikto(self, target: str, options: dict) -> dict:
        if not shutil.which("nikto"):
            return {"error": "nikto non installé"}
        port = options.get("port") or 80
        profile = options.get("nikto_profile", "standard")
        cfg = self._NIKTO_PROFILES.get(profile, self._NIKTO_PROFILES["standard"])
        to = cfg.get("timeout", 1800)
        try:
            cmd = ["nikto", "-h", target, "-p", str(port),
                   "-Tuning", cfg["tuning"], "-nointeractive"]
            if cfg["evasion"]:
                cmd += ["-evasion", cfg["evasion"]]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=to)
            return {
                "command": " ".join(cmd),
                "profile": profile,
                "output": proc.stdout,
                "stderr": self._clean_stderr(proc.stderr),
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout nikto (> {to // 60} min, profil '{profile}'). "
                             f"Essaie 'Quick' sur cibles distantes, ou cible un port/service précis."}
        except Exception as e:
            return {"error": str(e)}

    # Profils SSLyze → arguments passés au binaire (sslyze >= 5.x)
    # --regular a été retiré : on passe les scans individuellement ou via
    # --mozilla_config qui regroupe les commandes standard.
    _SSLYZE_PROFILES = {
        "cert":     ["--certinfo"],
        "standard": ["--mozilla_config", "intermediate", "--certinfo",
                     "--http_headers", "--elliptic_curves"],
        "full":     ["--certinfo", "--elliptic_curves", "--http_headers",
                     "--tlsv1_2", "--tlsv1_3", "--tlsv1_1", "--tlsv1",
                     "--sslv2", "--sslv3", "--compression", "--reneg",
                     "--resum", "--heartbleed", "--robot", "--openssl_ccs",
                     "--fallback", "--ems", "--early_data"],
    }

    _SSLYZE_NO_TLS_HINT = (
        "La cible n'accepte pas de connexion TLS sur ce port. "
        "SSLyze nécessite un service HTTPS/TLS actif. "
        "Cibles de test recommandées : badssl.com, expired.badssl.com, "
        "self-signed.badssl.com, github.com, ou n'importe quel site HTTPS."
    )

    # Motifs de bruit à filtrer de stderr (warnings Python sans gravité).
    _STDERR_NOISE_MARKERS = (
        "deprecationwarning",
        "pendingdeprecationwarning",
        "userwarning",
        "futurewarning",
        "pkg_resources is deprecated",
        "cryptographydeprecationwarning",
        "failed to check for updates",  # Nikto : check de version, anodin
    )

    @classmethod
    def _clean_stderr(cls, stderr: str | None) -> str:
        """Retire les warnings Python et autres lignes de bruit qui
        font apparaître à tort 'Erreurs / Stderr' dans le rapport."""
        if not stderr:
            return ""
        kept: list[str] = []
        skip_next_indented = False
        for line in stderr.splitlines():
            low = line.lower()
            if any(m in low for m in cls._STDERR_NOISE_MARKERS):
                skip_next_indented = True
                continue
            # Lignes "self._raw_oid = ..." ou continuations indentées d'un warning
            if skip_next_indented and (line.startswith((" ", "\t")) or not line.strip()):
                continue
            skip_next_indented = False
            kept.append(line)
        return "\n".join(kept).strip()

    @staticmethod
    def _tls_reachable(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
        """Vérifie qu'un port TCP est ouvert (précondition à SSLyze).
        Essaie chaque adresse résolue (IPv4 puis IPv6) — utile dans Docker
        où le réseau IPv6 n'est souvent pas routé."""
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False, f"DNS introuvable : impossible de résoudre {host}."

        # IPv4 d'abord, puis IPv6 (fallback)
        infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
        last_err: Exception | None = None
        for family, socktype, proto, _, sockaddr in infos:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                sock.close()
                return True, ""
            except (TimeoutError, socket.timeout) as e:
                last_err = e
            except OSError as e:
                last_err = e
            finally:
                sock.close()

        if isinstance(last_err, (TimeoutError, socket.timeout)):
            return False, f"Timeout TCP sur {host}:{port} — port filtré ou hôte inaccessible."
        if isinstance(last_err, ConnectionRefusedError):
            return False, f"Connexion refusée sur {host}:{port} — aucun service n'écoute."
        return False, f"Connexion impossible vers {host}:{port} : {last_err}"

    def _sslyze(self, target: str, options: dict | None = None) -> dict:
        """Utilise le binaire sslyze (présent dans l'image Kali) pour produire
        le même rendu qu'en ligne de commande."""
        opts = options or {}
        profile = opts.get("sslyze_profile", "standard")
        args = self._SSLYZE_PROFILES.get(profile, self._SSLYZE_PROFILES["standard"])

        # Parse host:port (port 443 par défaut)
        host = target.split("://", 1)[-1].split("/")[0]
        if ":" in host:
            host_only, port_str = host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host_only, port = host, 443
        else:
            host_only, port = host, 443
        endpoint = f"{host_only}:{port}"

        # Pré-check connectivité TCP : évite de lancer sslyze sur une cible
        # sans service TLS (cas typique de scanme.nmap.org).
        reachable, reason = self._tls_reachable(host_only, port)
        if not reachable:
            return {
                "command": f"sslyze {' '.join(args)} {endpoint}",
                "profile": profile,
                "error": f"{reason} {self._SSLYZE_NO_TLS_HINT}",
            }

        if shutil.which("sslyze"):
            try:
                cmd = ["sslyze"] + args + [endpoint]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                # Détecter les erreurs de connexion remontées par sslyze
                # (port ouvert mais ne parle pas TLS, handshake rejeté, etc.).
                out_lower = (proc.stdout or "").lower()
                tls_error_markers = [
                    "rejected the connection",
                    "server rejected",
                    "tls handshake",
                    "ssl handshake",
                    "could not connect",
                    "connection error",
                ]
                if any(m in out_lower for m in tls_error_markers):
                    return {
                        "command": " ".join(cmd),
                        "profile": profile,
                        "output": proc.stdout,
                        "stderr": self._clean_stderr(proc.stderr),
                        "error": (
                            f"SSLyze a pu joindre {endpoint} mais le handshake TLS a échoué. "
                            f"{self._SSLYZE_NO_TLS_HINT}"
                        ),
                    }
                return {
                    "command": " ".join(cmd),
                    "profile": profile,
                    "output": proc.stdout,
                    "stderr": self._clean_stderr(proc.stderr),
                }
            except subprocess.TimeoutExpired:
                return {"error": "Timeout sslyze (> 3 min). Cible lente ou filtrée."}
            except Exception as e:
                return {"error": str(e)}

        # Fallback : API Python (sortie texte reconstruite)
        try:
            from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
            from sslyze.plugins.scan_commands import ScanCommand
            location = ServerNetworkLocation(target, 443)
            request = ServerScanRequest(
                server_location=location,
                scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES},
            )
            scanner = Scanner()
            scanner.queue_scans([request])
            for result in scanner.get_results():
                return {"output": str(result)}
            return {"error": "sslyze : aucun résultat"}
        except ImportError:
            return {"error": "sslyze non installé"}
        except Exception as e:
            return {"error": str(e)}
