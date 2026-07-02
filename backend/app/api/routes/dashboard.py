from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.scan import ScanJob, Report
from app.models.user import User

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    jobs = db.query(ScanJob).filter(ScanJob.created_by == current_user.id).order_by(ScanJob.created_at.desc()).limit(10).all()
    reports = db.query(Report).filter(Report.created_by == current_user.id).order_by(Report.created_at.desc()).limit(5).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "jobs": jobs,
        "reports": reports,
    })


@router.get("/stats")
def stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_jobs    = db.query(ScanJob).filter(ScanJob.created_by == current_user.id).count()
    done_jobs     = db.query(ScanJob).filter(ScanJob.created_by == current_user.id, ScanJob.status == "done").count()
    error_jobs    = db.query(ScanJob).filter(ScanJob.created_by == current_user.id, ScanJob.status == "error").count()
    total_reports = db.query(Report).filter(Report.created_by == current_user.id).count()

    return {
        "total_jobs": total_jobs,
        "done_jobs": done_jobs,
        "error_jobs": error_jobs,
        "total_reports": total_reports,
    }
