from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id         = Column(Integer, primary_key=True, index=True)
    task_id    = Column(String(64), unique=True, index=True)
    module     = Column(String(64), nullable=False)      # recon | scan | exploit | ...
    target     = Column(String(256), nullable=False)
    options    = Column(JSON, default={})
    status     = Column(String(32), default="pending")   # pending | running | done | error
    result     = Column(JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at= Column(DateTime(timezone=True), nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String(256), nullable=False)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    format      = Column(String(16), default="pdf")      # pdf | html | csv
    file_path   = Column(String(512), nullable=True)
    summary     = Column(Text, nullable=True)
    created_by  = Column(Integer, ForeignKey("users.id"))
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=True)
    action     = Column(String(128), nullable=False)
    detail     = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp  = Column(DateTime(timezone=True), server_default=func.now())
