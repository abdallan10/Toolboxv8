"""
Module IDS/IPS – Intégration Snort
------------------------------------
Lit les alertes Snort depuis le fichier de logs
et les remonte dans le SIEM.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SNORT_ALERT_LOG = os.getenv("SNORT_ALERT_LOG", "/var/log/snort/alert")


class IDSModule:
    def parse_alerts(self, log_path: str = SNORT_ALERT_LOG) -> list[dict]:
        alerts = []
        if not os.path.exists(log_path):
            logger.warning(f"Snort alert log introuvable : {log_path}")
            return alerts

        pattern = re.compile(
            r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+\[Classification:\s*(?P<class>.+?)\]"
        )
        try:
            with open(log_path, "r", errors="replace") as f:
                for line in f:
                    m = pattern.search(line)
                    if m:
                        alerts.append({
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "ids_alert",
                            "sid": m.group("sid"),
                            "message": m.group("msg").strip(),
                            "classification": m.group("class").strip(),
                            "raw": line.strip(),
                        })
        except OSError as e:
            logger.error(f"Lecture Snort échouée : {e}")

        return alerts

    def get_stats(self, log_path: str = SNORT_ALERT_LOG) -> dict:
        alerts = self.parse_alerts(log_path)
        classifications: dict[str, int] = {}
        for a in alerts:
            cls = a.get("classification", "Unknown")
            classifications[cls] = classifications.get(cls, 0) + 1
        return {
            "total_alerts": len(alerts),
            "by_classification": classifications,
        }
