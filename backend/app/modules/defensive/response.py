"""
Module Réponse Active
----------------------
Actions de remédiation automatiques déclenchées après détection :
  - Blocage IP via iptables
  - Isolation réseau (simulation)
  - Notification SIEM
"""

import subprocess
import shutil
import logging
from typing import Any

from app.modules.defensive.siem import SIEMModule

logger = logging.getLogger(__name__)


class ResponseModule:
    def __init__(self):
        self.siem = SIEMModule()

    def block_ip(self, ip: str, reason: str = "automated") -> dict:
        self.siem.index_event("response_action", {
            "action": "block_ip",
            "ip": ip,
            "reason": reason,
        })

        if not shutil.which("iptables"):
            logger.warning("iptables non disponible, simulation du blocage")
            return {"status": "simulated", "ip": ip, "reason": reason}

        try:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                return {"status": "blocked", "ip": ip}
            return {"status": "error", "stderr": proc.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def unblock_ip(self, ip: str) -> dict:
        if not shutil.which("iptables"):
            return {"status": "simulated", "ip": ip}
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {"status": "unblocked" if proc.returncode == 0 else "error", "ip": ip}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def isolate_host(self, ip: str) -> dict:
        self.siem.index_event("response_action", {"action": "isolate", "ip": ip})
        return {"status": "isolation_scheduled", "ip": ip, "note": "Isolation réseau à implémenter via hyperviseur"}

    def send_alert(self, message: str, severity: str = "high") -> dict:
        self.siem.index_event("alert", {"message": message, "severity": severity})
        return {"status": "alert_sent", "severity": severity}
