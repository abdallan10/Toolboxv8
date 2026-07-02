import logging
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="tasks.generate_report")
def generate_report(self, scan_job_id: int, fmt: str, user_id: int) -> dict:
    logger.info(f"[REPORT] Génération rapport scan#{scan_job_id} format={fmt}")
    self.update_state(state="STARTED", meta={"scan_job_id": scan_job_id})
    from app.reporting.generator import ReportGenerator
    path = ReportGenerator().generate(scan_job_id=scan_job_id, fmt=fmt, user_id=user_id)
    return {"status": "done", "file_path": path}
