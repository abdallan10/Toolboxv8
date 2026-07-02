"""
Module SIEM – Intégration ELK Stack
-------------------------------------
Envoie les logs des scans vers Elasticsearch.
Fournit des méthodes pour requêter les alertes Kibana.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)


class SIEMModule:
    def __init__(self):
        self.es_url = settings.ELASTICSEARCH_URL

    def index_event(self, event_type: str, data: dict) -> bool:
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "source": "toolbox-pentest",
            **data,
        }
        try:
            r = requests.post(
                f"{self.es_url}/pentest-logs/_doc",
                json=doc,
                timeout=5,
            )
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.warning(f"SIEM indexation échouée : {e}")
            return False

    def search_events(self, query: str, size: int = 50) -> list[dict]:
        payload = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["event_type", "target", "module"],
                }
            },
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        try:
            r = requests.post(
                f"{self.es_url}/pentest-logs/_search",
                json=payload,
                timeout=10,
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except requests.RequestException as e:
            logger.warning(f"SIEM search échouée : {e}")
            return []

    def get_recent_alerts(self, limit: int = 20) -> list[dict]:
        payload = {
            "query": {"match": {"event_type": "alert"}},
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        try:
            r = requests.post(f"{self.es_url}/pentest-logs/_search", json=payload, timeout=10)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except Exception as e:
            logger.warning(f"SIEM get_alerts échouée : {e}")
            return []
