"""
Module défensif - SIEM mini-dashboard
Expose des métriques de sécurité, l'état des services et des séries temporelles.
"""
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.scan import ScanJob, Report, AuditLog
from app.models.user import User

router = APIRouter()


# ── Helpers de check de service ────────────────────────────────────────

def _check_http(url: str, timeout: float = 1.5) -> dict:
    """Ping une URL HTTP et renvoie {up, latency_ms}."""
    import httpx
    t0 = datetime.now()
    try:
        r = httpx.get(url, timeout=timeout)
        latency = (datetime.now() - t0).total_seconds() * 1000
        return {"up": 200 <= r.status_code < 500, "latency_ms": round(latency, 1), "code": r.status_code}
    except Exception as e:
        return {"up": False, "latency_ms": None, "error": str(e)[:80]}


def _check_redis() -> dict:
    t0 = datetime.now()
    try:
        import redis
        from app.core.config import settings
        r = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=1.5)
        r.ping()
        latency = (datetime.now() - t0).total_seconds() * 1000
        return {"up": True, "latency_ms": round(latency, 1)}
    except Exception as e:
        return {"up": False, "latency_ms": None, "error": str(e)[:80]}


def _check_postgres(db: Session) -> dict:
    t0 = datetime.now()
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        latency = (datetime.now() - t0).total_seconds() * 1000
        return {"up": True, "latency_ms": round(latency, 1)}
    except Exception as e:
        return {"up": False, "latency_ms": None, "error": str(e)[:80]}


# ── Endpoint principal SIEM ────────────────────────────────────────────

@router.get("/overview")
def siem_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Vue d'ensemble SIEM : services, métriques, timeline, distributions."""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # ── 1. État des services ───────────────────────────────────────────
    services = {
        "elasticsearch": _check_http("http://elasticsearch:9200/_cluster/health"),
        "kibana":        _check_http("http://kibana:5601/api/status"),
        "logstash":      _check_http("http://logstash:9600/_node/stats"),
        "minio":         _check_http("http://minio:9000/minio/health/live"),
        "redis":         _check_redis(),
        "postgres":      _check_postgres(db),
    }
    services_up = sum(1 for s in services.values() if s["up"])

    # ── 2. Métriques globales ──────────────────────────────────────────
    total_scans   = db.query(ScanJob).count()
    scans_24h     = db.query(ScanJob).filter(ScanJob.created_at >= last_24h).count()
    done_scans    = db.query(ScanJob).filter(ScanJob.status == "done").count()
    error_scans   = db.query(ScanJob).filter(ScanJob.status == "error").count()
    running_scans = db.query(ScanJob).filter(ScanJob.status.in_(["running", "pending"])).count()
    total_reports = db.query(Report).count()
    success_rate  = round((done_scans / total_scans * 100), 1) if total_scans else 0

    # ── 3. Timeline 24h (scans par heure) ─────────────────────────────
    timeline_jobs = db.query(ScanJob).filter(ScanJob.created_at >= last_24h).all()
    buckets = defaultdict(int)
    for j in timeline_jobs:
        # Bucket par heure
        hour_key = j.created_at.replace(minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
        buckets[hour_key] += 1
    # Construire la série complète sur 24h
    timeline = []
    for i in range(23, -1, -1):
        h = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        timeline.append({
            "time":  h.strftime("%H:00"),
            "count": buckets.get(h, 0),
        })

    # ── 4. Distribution par module ─────────────────────────────────────
    modules_count = (
        db.query(ScanJob.module, func.count(ScanJob.id))
        .group_by(ScanJob.module)
        .all()
    )
    modules = [{"name": m, "count": c} for m, c in modules_count]

    # ── 5. Distribution par statut ─────────────────────────────────────
    status_count = (
        db.query(ScanJob.status, func.count(ScanJob.id))
        .group_by(ScanJob.status)
        .all()
    )
    statuses = [{"name": s, "count": c} for s, c in status_count]

    # ── 6. Top 5 cibles scannées ───────────────────────────────────────
    top_targets = (
        db.query(ScanJob.target, func.count(ScanJob.id).label("c"))
        .group_by(ScanJob.target)
        .order_by(func.count(ScanJob.id).desc())
        .limit(5)
        .all()
    )
    targets = [{"target": t, "count": c} for t, c in top_targets]

    # ── 7. Activité récente (10 derniers événements) ──────────────────
    recent_jobs = (
        db.query(ScanJob)
        .order_by(ScanJob.created_at.desc())
        .limit(10)
        .all()
    )
    activity = [
        {
            "id": j.id,
            "module": j.module,
            "target": j.target,
            "status": j.status,
            "time": j.created_at.isoformat() if j.created_at else None,
        }
        for j in recent_jobs
    ]

    # ── 8. Niveau d'alerte global ──────────────────────────────────────
    if services_up == len(services) and error_scans == 0:
        alert_level = {"level": "ok",       "label": "Système nominal",     "color": "#22c55e"}
    elif services_up >= len(services) - 1 and error_scans < 3:
        alert_level = {"level": "warning",  "label": "Vigilance",           "color": "#f59e0b"}
    else:
        alert_level = {"level": "critical", "label": "Anomalies détectées", "color": "#ef4444"}

    return {
        "services": services,
        "services_up": services_up,
        "services_total": len(services),
        "metrics": {
            "total_scans":   total_scans,
            "scans_24h":     scans_24h,
            "done_scans":    done_scans,
            "error_scans":   error_scans,
            "running_scans": running_scans,
            "total_reports": total_reports,
            "success_rate":  success_rate,
        },
        "timeline":    timeline,
        "modules":     modules,
        "statuses":    statuses,
        "top_targets": targets,
        "activity":    activity,
        "alert_level": alert_level,
        "timestamp":   now.isoformat(),
    }
