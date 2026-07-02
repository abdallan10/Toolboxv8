"""
Module Forensique (Bonus)
--------------------------
Intègre :
  - ClamAV (antivirus)
  - VirusTotal API
  - Analyse de fichiers suspects
"""

import logging
import subprocess
import shutil
import os
from typing import Any

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)


class ForensicModule:
    def scan_file(self, file_path: str) -> dict:
        results: dict[str, Any] = {"file": file_path}
        results["clamav"]   = self._clamav_scan(file_path)
        results["virustotal"] = self._virustotal_scan(file_path)
        return results

    def _clamav_scan(self, file_path: str) -> dict:
        if not shutil.which("clamscan"):
            return {"error": "ClamAV non installé"}
        if not os.path.exists(file_path):
            return {"error": "Fichier introuvable"}
        try:
            proc = subprocess.run(
                ["clamscan", "--infected", "--no-summary", file_path],
                capture_output=True, text=True, timeout=120,
            )
            return {
                "infected": proc.returncode == 1,
                "output": proc.stdout.strip(),
            }
        except Exception as e:
            return {"error": str(e)}

    def _virustotal_scan(self, file_path: str) -> dict:
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "Clé VirusTotal non configurée"}
        if not os.path.exists(file_path):
            return {"error": "Fichier introuvable"}
        try:
            with open(file_path, "rb") as f:
                r = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                    files={"file": f},
                    timeout=30,
                )
            r.raise_for_status()
            analysis_id = r.json().get("data", {}).get("id")
            return {"status": "uploaded", "analysis_id": analysis_id}
        except requests.RequestException as e:
            return {"error": str(e)}

    def get_vt_result(self, analysis_id: str) -> dict:
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "Clé VirusTotal non configurée"}
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            return {"error": str(e)}
