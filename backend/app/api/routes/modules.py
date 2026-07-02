import os
import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_analyst, get_current_user
from app.core.database import get_db
from app.models.scan import ScanJob, Report
from app.models.user import User

router = APIRouter()

WORDLIST_DIR = Path("/tmp/wordlists")
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
MAX_WORDLIST_BYTES = 200 * 1024 * 1024  # 200 MB

MODULES = {
    "recon":         "tasks.run_recon",
    "passive_recon": "tasks.run_passive_recon",
    "scan":          "tasks.run_scan",
    "exploit":     "tasks.run_exploit",
    "web_scan":    "tasks.run_web_scan",
}


class ModuleLaunch(BaseModel):
    module: str
    target: str
    options: Optional[dict] = {}


class JobOut(BaseModel):
    id: int
    task_id: str
    module: str
    target: str
    status: str

    class Config:
        from_attributes = True


class WordlistUploaded(BaseModel):
    path: str
    filename: str
    size: int
    lines: int


@router.post("/wordlist", response_model=WordlistUploaded, status_code=201)
async def upload_wordlist(
    file: UploadFile = File(...),
    current_user: User = Depends(require_analyst),
):
    """Accepte un fichier texte (liste d'utilisateurs, de passwords ou wordlist)
    et le stocke dans le volume partagé /tmp/wordlists (accessible au worker)."""
    raw_name = Path(file.filename or "wordlist.txt").name
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:80] or "wordlist.txt"
    uid = uuid.uuid4().hex[:12]
    dest = WORDLIST_DIR / f"{uid}_{safe_name}"

    written = 0
    lines = 0
    try:
        with dest.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_WORDLIST_BYTES:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Fichier trop volumineux (max {MAX_WORDLIST_BYTES // (1024*1024)} MB)",
                    )
                fh.write(chunk)
                lines += chunk.count(b"\n")
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Upload impossible : {exc}")

    # Décompte final : si pas de saut de ligne final, on ajoute 1
    try:
        with dest.open("rb") as fh:
            fh.seek(max(0, written - 1))
            last = fh.read(1)
        if last and last != b"\n":
            lines += 1
    except Exception:
        pass

    return WordlistUploaded(
        path=str(dest),
        filename=safe_name,
        size=written,
        lines=lines,
    )


@router.get("/")
def list_modules():
    return {
        "modules": [
            {"name": "recon",         "description": "Reconnaissance active — DNS, Nmap, Whois, WhatWeb"},
            {"name": "passive_recon", "description": "Reconnaissance passive — Google Dorks & OSINT"},
            {"name": "scan",          "description": "Scan de vulnérabilités (OpenVAS/Nessus/Nikto)"},
            {"name": "exploit",  "description": "Exploitation (Metasploit, SQLmap, Hydra, John the Ripper)"},
            {"name": "web_scan", "description": "Analyse Web/API (OWASP ZAP, Gobuster, Dep-Check)"},
        ]
    }


def _validate_target(target: str, module: str = "", options: dict | None = None) -> str | None:
    """Valide le format de la cible. Retourne un message d'erreur ou None si valide."""
    import re
    t = target.strip()
    if not t:
        return "La cible ne peut pas etre vide."
    # John the Ripper : la cible est un hash (ou un chemin de fichier de hashes),
    # pas une IP / domaine / URL. On accepte tout non-vide.
    if module == "exploit" and (options or {}).get("mode") == "john":
        return None
    # Hydra : la cible peut être un hostname interne (ex: 'target', 'db' dans Docker)
    # ou n'importe quel service réseau accessible. On accepte tout non-vide.
    if module == "exploit" and (options or {}).get("mode") == "hydra":
        return None
    # Reconnaissance passive (dorks) : champ libre — marque, nom, produit, etc.
    if module == "passive_recon":
        return None
    # URL (http/https) — accepté pour SQLmap, ZAP, etc.
    if re.match(r"^https?://", t):
        return None
    # IPv4 (avec CIDR optionnel)
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", t):
        parts = t.split("/")[0].split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return None
        return f"Adresse IP invalide : chaque octet doit etre entre 0 et 255 (recu : {t})."
    # IPv6
    if re.match(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$", t):
        return None
    # Domaine
    if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", t):
        return None
    return f"Format de cible invalide : '{t}'. Utilisez une IP (192.168.1.1), un domaine (example.com) ou une URL (http://site.com)."


@router.post("/launch", response_model=JobOut, status_code=202)
def launch_module(
    payload: ModuleLaunch,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if payload.module not in MODULES:
        raise HTTPException(status_code=400, detail=f"Module inconnu : {payload.module}")

    # Validation de la cible
    target_err = _validate_target(payload.target, payload.module, payload.options)
    if target_err:
        # Créer un job en erreur pour tracer l'anomalie
        import uuid
        job = ScanJob(
            task_id=f"invalid-{uuid.uuid4().hex[:16]}",
            module=payload.module,
            target=payload.target,
            options=payload.options,
            status="error",
            result={"error": target_err, "logs": [
                {"time": __import__("datetime").datetime.now().strftime("%H:%M:%S"),
                 "msg": f"ERREUR : {target_err}"}
            ]},
            created_by=current_user.id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    from celery import current_app as celery
    task = celery.send_task(MODULES[payload.module], args=[payload.target, payload.options])

    job = ScanJob(
        task_id=task.id,
        module=payload.module,
        target=payload.target,
        options=payload.options,
        status="pending",
        created_by=current_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(ScanJob).filter(ScanJob.created_by == current_user.id).all()


@router.delete("/jobs/{job_id}", status_code=204)
def delete_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    job = db.query(ScanJob).filter(
        ScanJob.id == job_id, ScanJob.created_by == current_user.id
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job introuvable")
    # Supprimer les rapports liés avant (FK constraint)
    import os as _os
    reports = db.query(Report).filter(Report.scan_job_id == job_id).all()
    for r in reports:
        if r.file_path and _os.path.exists(r.file_path):
            _os.remove(r.file_path)
        db.delete(r)
    db.delete(job)
    db.commit()


@router.get("/jobs/{job_id}")
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job introuvable")

    def _job_out():
        return {"id": job.id, "module": job.module, "target": job.target,
                "status": job.status, "created_at": job.created_at,
                "options": job.options,
                "result": job.result}

    # Job déjà finalisé en DB → retourner les logs stockés
    if job.status == "done":
        stored_logs = job.result.get("logs", []) if isinstance(job.result, dict) else []
        return {
            "job": _job_out(),
            "celery_state": "SUCCESS",
            "progress": {"percent": 100, "step": "Scan terminé avec succès.", "logs": stored_logs},
        }
    if job.status == "error":
        return {
            "job": _job_out(),
            "celery_state": "FAILURE",
            "progress": {"percent": 100, "step": "Erreur lors de l'exécution.", "logs": []},
        }

    from celery.result import AsyncResult
    ar = AsyncResult(job.task_id)

    # Progression en cours
    progress = {"percent": 0, "step": "En attente du worker...", "logs": []}
    if ar.state == "PROGRESS" and isinstance(ar.info, dict):
        progress = {
            "percent": ar.info.get("percent", 0),
            "step":    ar.info.get("step", ""),
            "logs":    ar.info.get("logs", []),
        }
        job.status = "running"
        db.commit()

    # Terminé
    if ar.ready():
        if ar.successful():
            job.status = "done"
            res = ar.result or {}
            scan_logs = res.get("logs", []) if isinstance(res, dict) else []
            # Stocker data ET logs pour pouvoir les réafficher plus tard
            job.result = {
                "data": res.get("result") if isinstance(res, dict) else res,
                "logs": scan_logs,
            }
            db.commit()
            progress = {
                "percent": 100,
                "step": "Terminé avec succès",
                "logs": scan_logs,
            }
        else:
            job.status = "error"
            db.commit()
            progress = {"percent": 100, "step": "Erreur lors de l'exécution", "logs": []}

    return {
        "job":      _job_out(),
        "celery_state": ar.state,
        "progress": progress,
    }
