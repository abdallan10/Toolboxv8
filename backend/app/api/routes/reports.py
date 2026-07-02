from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel
from typing import Literal
from sqlalchemy.orm import Session

from app.core.auth import require_analyst, get_current_user
from app.core.database import get_db
from app.models.scan import Report, ScanJob
from app.models.user import User

router = APIRouter()


class ReportRequest(BaseModel):
    scan_job_id: int
    title: str
    format: Literal["pdf", "html", "csv"] = "pdf"


@router.post("/generate", status_code=202)
def generate_report(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    from app.tasks.report_tasks import generate_report as task
    t = task.delay(payload.scan_job_id, payload.format, current_user.id)
    return {"task_id": t.id, "message": "Génération du rapport lancée"}


@router.get("/", response_model=list[dict])
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    reports = db.query(Report).filter(Report.created_by == current_user.id).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "format": r.format,
            "created_at": r.created_at.isoformat(),
        }
        for r in reports
    ]


@router.delete("/{report_id}", status_code=204)
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    import os as _os
    report = db.query(Report).filter(
        Report.id == report_id, Report.created_by == current_user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Rapport introuvable")
    if report.file_path and _os.path.exists(report.file_path):
        _os.remove(report.file_path)
    db.delete(report)
    db.commit()


_MIME = {
    "pdf":  "application/pdf",
    "html": "text/html; charset=utf-8",
    "csv":  "text/csv; charset=utf-8",
}


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Rapport introuvable")
    if not report.file_path:
        raise HTTPException(status_code=404, detail="Fichier non disponible")
    return FileResponse(
        report.file_path,
        media_type=_MIME.get(report.format, "application/octet-stream"),
        filename=f"rapport_{report_id}.{report.format}",
    )


@router.get("/{report_id}/view", response_class=HTMLResponse)
def view_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Renvoie le rapport au format HTML pour visualisation inline dans le navigateur."""
    import os as _os
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Rapport introuvable")

    # Si format HTML et le fichier existe → on le sert directement
    if report.format == "html" and report.file_path and _os.path.exists(report.file_path):
        with open(report.file_path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())

    # Sinon (PDF/CSV ou fichier manquant) → régénérer le HTML à la volée
    from app.reporting.generator import ReportGenerator
    gen = ReportGenerator()
    job = db.query(ScanJob).filter(ScanJob.id == report.scan_job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan associé introuvable")

    from app.reporting.generator import _build_tools_sections
    raw = job.result or {}
    result_data = raw.get("data", raw) if isinstance(raw, dict) and "data" in raw else raw
    safe_result = result_data if isinstance(result_data, dict) else {}
    ctx = {
        "title": report.title,
        "generated_at": report.created_at.strftime("%d/%m/%Y %H:%M"),
        "job": job,
        "result": safe_result,
        "tools_sections": _build_tools_sections(safe_result),
    }
    tpl = gen.jinja_env.get_template("report.html")
    return HTMLResponse(tpl.render(**ctx))
