"""
Générateur de Rapports
-----------------------
Produit des rapports en PDF, HTML et CSV à partir des résultats de scan.
Utilise Jinja2 pour le rendu et WeasyPrint pour la conversion PDF.
Stocke les fichiers dans MinIO.
"""

import csv
import io
import json
import logging
import os
import tempfile
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from app.core.config import settings


# Clés reconnues par ordre de priorité pour le bloc "sortie principale"
_MAIN_OUTPUT_KEYS = ("output", "raw_xml", "stdout")
# Clés à masquer dans le bloc "Détails" parce que déjà rendues séparément
_HANDLED_KEYS = {"command", "cmd", "stderr", "error", "credentials", "cracked",
                 "output", "raw_xml", "stdout"}


def _format_tool_data(tool_name: str, data) -> dict:
    """Transforme les données brutes d'un outil en structure prête à afficher.

    Retourne un dict :
      name, error, command, main_output, stderr, items, extras_json
    """
    section = {
        "name":        tool_name,
        "error":       None,
        "command":     None,
        "main_output": None,
        "stderr":      None,
        "results_list": None,
        "extras_json": None,
    }

    if data is None:
        return section

    # Valeur brute string = on la met telle quelle dans main_output
    if isinstance(data, str):
        section["main_output"] = data
        return section

    # Liste = results_list (ex. cracked credentials déjà listées)
    if isinstance(data, list):
        section["results_list"] = [str(x) for x in data]
        return section

    if not isinstance(data, dict):
        section["main_output"] = str(data)
        return section

    # --- Dict : extraction structurée ---
    err = data.get("error")
    if err:
        section["error"] = str(err)

    cmd = data.get("command") or data.get("cmd")
    if cmd:
        section["command"] = str(cmd)

    # Sortie principale : première clé connue qui a du contenu non-vide
    for key in _MAIN_OUTPUT_KEYS:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            section["main_output"] = val
            break

    stderr = data.get("stderr")
    if isinstance(stderr, str) and stderr.strip():
        section["stderr"] = stderr

    items = data.get("credentials") or data.get("cracked")
    if isinstance(items, list) and items:
        section["results_list"] = [str(x) for x in items]

    # Reste = tout sauf les clés déjà traitées
    extras = {k: v for k, v in data.items() if k not in _HANDLED_KEYS}
    if extras:
        try:
            section["extras_json"] = json.dumps(extras, indent=2, ensure_ascii=False, default=str)
        except Exception:
            section["extras_json"] = str(extras)

    # Si aucune sortie principale trouvée mais qu'on a des clés exploitables,
    # on synthétise un bloc lisible à partir des extras (évite un rapport vide).
    if not section["main_output"] and not section["results_list"] and extras:
        lines = []
        for k, v in extras.items():
            if isinstance(v, (str, int, float, bool)):
                lines.append(f"{k}: {v}")
            elif isinstance(v, list):
                lines.append(f"{k}: {', '.join(str(x) for x in v)}")
        if lines:
            section["main_output"] = "\n".join(lines)

    return section


def _build_tools_sections(result_data) -> list[dict]:
    """Itère sur la collection d'outils d'un job et retourne une liste
    de sections normalisées exploitables par le template / ReportLab."""
    if not isinstance(result_data, dict):
        return []
    sections = []
    for tool, data in result_data.items():
        # 'target' et similaires (scalaires d'info) ne sont pas des outils à déployer
        if tool in ("target", "mode") and not isinstance(data, (dict, list)):
            continue
        # Outils désactivés par l'utilisateur : dict vide / None / "" → on n'affiche pas
        if not data or (isinstance(data, dict) and not any(data.values())):
            continue
        sections.append(_format_tool_data(tool, data))
    return sections

logger = logging.getLogger(__name__)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "templates")
REPORTS_DIR   = "/tmp/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    def __init__(self):
        self.jinja_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)

    def generate(self, scan_job_id: int, fmt: str, user_id: int) -> str:
        from app.core.database import SessionLocal
        from app.models.scan import ScanJob, Report

        db = SessionLocal()
        try:
            # Import all models so SQLAlchemy metadata knows all tables
            from app.models.user import User  # noqa: F401
            job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if not job:
                raise ValueError(f"ScanJob #{scan_job_id} introuvable")

            # job.result peut être {"data": {...}, "logs": [...]} ou directement les données
            raw = job.result or {}
            result_data = raw.get("data", raw) if isinstance(raw, dict) and "data" in raw else raw

            safe_result = result_data if isinstance(result_data, dict) else {}
            context = {
                "title": f"Rapport Pentest – {job.module.upper()} sur {job.target}",
                "generated_at": datetime.now().strftime("%d/%m/%Y %H:%M"),
                "job": job,
                "result": safe_result,
                "tools_sections": _build_tools_sections(safe_result),
            }

            if fmt == "pdf":
                path = self._generate_pdf(context, scan_job_id)
            elif fmt == "html":
                path = self._generate_html(context, scan_job_id)
            elif fmt == "csv":
                path = self._generate_csv(context, scan_job_id)
            else:
                raise ValueError(f"Format inconnu : {fmt}")

            report = Report(
                title=context["title"],
                scan_job_id=scan_job_id,
                format=fmt,
                file_path=path,
                created_by=user_id,
            )
            db.add(report)
            db.commit()

            self._upload_to_minio(path)
            return path
        finally:
            db.close()

    def _generate_html(self, context: dict, job_id: int) -> str:
        tpl = self.jinja_env.get_template("report.html")
        html = tpl.render(**context)
        path = os.path.join(REPORTS_DIR, f"rapport_{job_id}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _generate_pdf(self, context: dict, job_id: int) -> str:
        """Génère un vrai PDF structuré avec ReportLab.

        S'inspire de la mise en page de l'exemple HTML dans
        pentest_rapport_generator_inspiration/ (template externe utilisé comme
        référence de charte graphique, pas comme dépendance runtime)."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        # Palette inspirée du template exemple
        PRIMARY      = colors.HexColor("#1f3b82")
        PRIMARY_DARK = colors.HexColor("#16306b")
        TEXT         = colors.HexColor("#0b1b2b")
        MUTED        = colors.HexColor("#5c6b7a")
        BORDER       = colors.HexColor("#d7dbe8")
        BG_SOFT      = colors.HexColor("#f6f7fb")
        CODIR_BG     = colors.HexColor("#fff7ed")
        CODIR_BORDER = colors.HexColor("#fb923c")
        CODIR_TEXT   = colors.HexColor("#c2410c")
        # Code blocks : palette "slate" douce, texte sombre sur fond très clair.
        # Texte sombre obligatoire car ReportLab ne re-dessine pas backColor sur
        # les pages d'overflow (Preformatted long) — un texte clair serait invisible.
        CODE_BG      = colors.HexColor("#f8fafc")  # slate-50 (presque blanc, plus pro que pur blanc)
        CODE_FG      = colors.HexColor("#1e293b")  # slate-800 (sombre mais doux, moins agressif que noir pur)
        CODE_BORDER  = colors.HexColor("#cbd5e1")  # slate-300 (bordure subtile autour des blocs)
        CODE_ACCENT  = colors.HexColor("#3b82f6")  # blue-500 (filet vertical à gauche, style IDE)

        pdf_path = os.path.join(REPORTS_DIR, f"rapport_{job_id}.pdf")
        doc = SimpleDocTemplate(
            pdf_path, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2.5*cm,
            title=context["title"], author="ToolboxV8",
        )

        ss = getSampleStyleSheet()
        eyebrow = ParagraphStyle("eyebrow", parent=ss["Normal"],
            fontSize=7, textColor=MUTED, spaceAfter=4,
            fontName="Helvetica-Bold", leading=9)
        title_st = ParagraphStyle("title", parent=ss["Title"],
            fontSize=22, textColor=PRIMARY, spaceAfter=6,
            alignment=TA_LEFT, fontName="Helvetica-Bold", leading=26)
        subtitle_st = ParagraphStyle("subtitle", parent=ss["Normal"],
            fontSize=10, textColor=MUTED, spaceAfter=10, leading=13)
        h2_st = ParagraphStyle("h2", parent=ss["Heading2"],
            fontSize=14, textColor=PRIMARY, spaceBefore=14, spaceAfter=8,
            fontName="Helvetica-Bold", leading=18,
            borderColor=PRIMARY, borderPadding=(0, 0, 0, 8), leftIndent=10)
        h3_st = ParagraphStyle("h3", parent=ss["Heading3"],
            fontSize=11, textColor=PRIMARY_DARK, spaceBefore=8, spaceAfter=4,
            fontName="Helvetica-Bold", leading=14)
        meta_lbl = ParagraphStyle("metalbl", parent=ss["Normal"],
            fontSize=7, textColor=PRIMARY, fontName="Helvetica-Bold", leading=9)
        meta_val = ParagraphStyle("metaval", parent=ss["Normal"],
            fontSize=9, textColor=TEXT, leading=12)
        body_st = ParagraphStyle("body", parent=ss["Normal"],
            fontSize=9.5, textColor=TEXT, spaceAfter=5, leading=13.5)
        muted_st = ParagraphStyle("muted", parent=ss["Normal"],
            fontSize=8, textColor=MUTED, spaceAfter=5, leading=11)
        code_st = ParagraphStyle("code", parent=ss["Code"],
            fontSize=7.5, textColor=CODE_FG, backColor=CODE_BG,
            borderPadding=(8, 10, 8, 10), borderColor=CODE_BORDER, borderWidth=0.5,
            leading=10.5, fontName="Courier", leftIndent=0, spaceAfter=8)
        codir_st = ParagraphStyle("codir", parent=ss["Normal"],
            fontSize=10, textColor=TEXT, leading=14, leftIndent=8, rightIndent=8,
            spaceBefore=4, spaceAfter=4)

        from reportlab.platypus import Preformatted

        story = []
        job = context["job"]
        result = context.get("result", {}) or {}
        tools_sections: list[dict] = context.get("tools_sections") or []

        # ── HEADER (cover) ─────────────────────────────────────────
        story.append(Paragraph("TOOLBOXV8 • RAPPORT AUTOMATISÉ", eyebrow))
        story.append(Paragraph(context["title"], title_st))
        story.append(Paragraph(
            "Audit de sécurité offensif – résultats détaillés et recommandations.",
            subtitle_st))
        story.append(HRFlowable(width="100%", thickness=2, color=PRIMARY,
            spaceBefore=4, spaceAfter=10))

        # Tableau métadonnées (4 colonnes)
        meta_rows = [
            ["CIBLE", "MODULE", "STATUT", "GÉNÉRÉ LE"],
            [str(job.target), str(job.module).upper(), str(job.status), context['generated_at']],
        ]
        meta_t = Table(meta_rows, colWidths=[(17/4)*cm]*4)
        meta_t.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), BG_SOFT),
            ("TEXTCOLOR",      (0, 0), (-1, 0), PRIMARY),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, 0), 7),
            ("FONTSIZE",       (0, 1), (-1, 1), 9),
            ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("BOX",            (0, 0), (-1, -1), 0.5, BORDER),
            ("INNERGRID",      (0, 0), (-1, -1), 0.5, BORDER),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_t)
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "<b>Légende criticité :</b> Info • Low • Medium • High • Critical "
            "(selon CVSS et impact métier).", muted_st))

        # ── SYNTHÈSE CODIR ────────────────────────────────────────
        story.append(Spacer(1, 10))
        codir_title = ParagraphStyle("codir_h", parent=h2_st,
            textColor=CODIR_TEXT, leftIndent=0)
        codir_content = [
            Paragraph("Synthèse exécutive (CODIR)", codir_title),
            Paragraph(
                f"Ce rapport présente les résultats du module <b>{job.module}</b> "
                f"exécuté sur la cible <b>{job.target}</b>. Les sections ci-dessous "
                f"détaillent les outils utilisés, les données collectées et les "
                f"recommandations de remédiation. Les actions urgentes sont listées "
                f"en fin de rapport.", codir_st),
        ]
        codir_box = Table([[c] for c in codir_content], colWidths=[17*cm])
        codir_box.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), CODIR_BG),
            ("LINEBEFORE",   (0, 0), (0, -1), 4, CODIR_BORDER),
            ("LEFTPADDING",  (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING",   (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ]))
        story.append(codir_box)

        # ── STATISTIQUES ──────────────────────────────────────────
        story.append(Paragraph("Statistiques", h2_st))
        stat_rows = [[
            Paragraph(f"<b><font size=14 color='#1f3b82'>{len(tools_sections)}</font></b><br/>"
                      f"<font size=7 color='#5c6b7a'>OUTILS UTILISÉS</font>", body_st),
            Paragraph(f"<b><font size=14 color='#1f3b82'>{job.module.upper()}</font></b><br/>"
                      f"<font size=7 color='#5c6b7a'>MODULE</font>", body_st),
            Paragraph(f"<b><font size=14 color='#1f3b82'>{job.status}</font></b><br/>"
                      f"<font size=7 color='#5c6b7a'>STATUT FINAL</font>", body_st),
        ]]
        stats_t = Table(stat_rows, colWidths=[(17/3)*cm]*3)
        stats_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), BG_SOFT),
            ("BOX",          (0, 0), (-1, -1), 0.5, BORDER),
            ("INNERGRID",    (0, 0), (-1, -1), 0.5, BORDER),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 12),
        ]))
        story.append(stats_t)

        # ── DÉROULÉ TECHNIQUE & PREUVES ───────────────────────────
        story.append(Paragraph("Déroulé technique &amp; preuves", h2_st))

        subh_st = ParagraphStyle("subh", parent=ss["Normal"],
            fontSize=8, textColor=MUTED, spaceBefore=6, spaceAfter=2,
            fontName="Helvetica-Bold", leading=10)
        err_st = ParagraphStyle("err", parent=body_st,
            textColor=colors.HexColor("#991b1b"),
            backColor=colors.HexColor("#fef2f2"),
            borderPadding=(6, 6, 6, 8), leftIndent=0,
            spaceAfter=6)
        cmd_st = ParagraphStyle("cmd", parent=body_st, fontName="Courier", fontSize=8.5,
            textColor=CODE_FG, backColor=CODE_BG,
            borderPadding=(6, 8, 6, 10), borderColor=CODE_BORDER, borderWidth=0.5,
            leading=12, spaceAfter=6)
        cred_st = ParagraphStyle("cred", parent=body_st, fontName="Courier", fontSize=8.5,
            textColor=colors.HexColor("#047857"), leading=12, leftIndent=14, spaceAfter=2)
        pre_st = ParagraphStyle("pre", parent=ss["Code"],
            fontSize=7.5, textColor=CODE_FG, backColor=CODE_BG,
            borderPadding=(8, 10, 8, 10), borderColor=CODE_BORDER, borderWidth=0.5,
            leading=10, fontName="Courier", leftIndent=0, spaceAfter=8)

        def _clip(text: str, limit: int = 20000) -> str:
            if text is None:
                return ""
            if len(text) > limit:
                return text[:limit] + "\n[…] (tronqué à %d caractères)" % limit
            return text

        if not tools_sections:
            story.append(Paragraph("<i>Aucune donnée collectée.</i>", body_st))
        else:
            for t in tools_sections:
                story.append(Paragraph(t["name"].upper(), h3_st))
                if t["error"]:
                    story.append(Paragraph(f"<b>Erreur :</b> {t['error']}", err_st))
                if t["command"]:
                    escaped_cmd = t["command"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(f"<b>Commande :</b> {escaped_cmd}", cmd_st))
                if t["main_output"]:
                    story.append(Paragraph("SORTIE CONSOLE", subh_st))
                    story.append(Preformatted(_clip(t["main_output"]), pre_st, maxLineLength=95))
                if t["results_list"]:
                    story.append(Paragraph(f"RÉSULTATS ({len(t['results_list'])})", subh_st))
                    for it in t["results_list"]:
                        escaped = str(it).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        story.append(Paragraph(f"• {escaped}", cred_st))
                if t["stderr"]:
                    story.append(Paragraph("ERREURS / STDERR", subh_st))
                    story.append(Preformatted(_clip(t["stderr"], 4000), pre_st, maxLineLength=95))
                if t["extras_json"]:
                    story.append(Paragraph("DÉTAILS COMPLÉMENTAIRES", subh_st))
                    story.append(Preformatted(_clip(t["extras_json"], 6000), pre_st, maxLineLength=95))
                if not any([t["error"], t["command"], t["main_output"], t["results_list"], t["stderr"], t["extras_json"]]):
                    story.append(Paragraph("<i>Aucune donnée retournée par cet outil.</i>", muted_st))
                story.append(Spacer(1, 8))

        # ── TABLEAU SYNTHÉTIQUE ───────────────────────────────────
        story.append(Paragraph("Tableau synthétique", h2_st))
        table_data = [["ID", "Outil", "Type", "Statut"]]
        if tools_sections:
            for i, t in enumerate(tools_sections, start=1):
                table_data.append([
                    f"R-{i:03d}",
                    str(t["name"]),
                    str(job.module),
                    "Erreur" if t["error"] else "Collecté",
                ])
        else:
            table_data.append(["—", "—", "—", "—"])

        synth_t = Table(table_data, colWidths=[2.5*cm, 5.5*cm, 4.5*cm, 4.5*cm], repeatRows=1)
        synth_t.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, 0), 9),
            ("FONTSIZE",       (0, 1), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_SOFT]),
            ("GRID",           (0, 0), (-1, -1), 0.25, BORDER),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ]))
        story.append(synth_t)

        # ── RECOMMANDATIONS ───────────────────────────────────────
        story.append(Paragraph("Recommandations", h2_st))
        recs = [
            ("Correctifs", "appliquer les patches de sécurité pour les vulnérabilités identifiées (CVE)."),
            ("Composants tiers", "mettre à jour les dépendances et bibliothèques signalées."),
            ("Configuration", "renforcer TLS, en-têtes HTTP, désactiver les services obsolètes (Telnet, SMBv1)."),
            ("Surface d'attaque", "restreindre les ports exposés publiquement et appliquer le principe du moindre privilège."),
            ("Validation", "planifier un nouveau test après remédiation pour confirmer les corrections."),
        ]
        for label, txt in recs:
            story.append(Paragraph(f"• <b>{label} :</b> {txt}", body_st))

        # ── ANNEXES ───────────────────────────────────────────────
        story.append(Paragraph("Annexes", h2_st))
        story.append(Paragraph(
            "Les données brutes des outils sont incluses dans la section "
            "« Déroulé technique &amp; preuves » ci-dessus. Les logs d'exécution "
            "complets sont disponibles dans l'interface ToolboxV8 via le bouton "
            "« Voir » du job correspondant.", muted_st))

        # ── FOOTER ────────────────────────────────────────────────
        def _footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(MUTED)
            canvas.drawString(2*cm, 1.2*cm,
                f"ToolboxV8 – Mastère Cybersécurité – {context['generated_at']}")
            canvas.drawRightString(A4[0] - 2*cm, 1.2*cm, f"Page {doc_.page}")
            canvas.setStrokeColor(BORDER)
            canvas.line(2*cm, 1.6*cm, A4[0] - 2*cm, 1.6*cm)
            canvas.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        logger.info(f"PDF généré avec ReportLab : {pdf_path}")
        return pdf_path

    def _generate_csv(self, context: dict, job_id: int) -> str:
        path = os.path.join(REPORTS_DIR, f"rapport_{job_id}.csv")
        result = context.get("result", {})
        rows: list[list] = [["Clé", "Valeur"]]
        for k, v in result.items():
            rows.append([k, str(v)])

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Rapport", context["title"]])
            writer.writerow(["Généré le", context["generated_at"]])
            writer.writerow([])
            writer.writerows(rows)
        return path

    def _upload_to_minio(self, file_path: str) -> bool:
        try:
            from minio import Minio
            client = Minio(
                settings.MINIO_ENDPOINT,
                access_key=settings.MINIO_ACCESS_KEY,
                secret_key=settings.MINIO_SECRET_KEY,
                secure=settings.MINIO_SECURE,
            )
            if not client.bucket_exists(settings.MINIO_BUCKET):
                client.make_bucket(settings.MINIO_BUCKET)
            object_name = os.path.basename(file_path)
            client.fput_object(settings.MINIO_BUCKET, object_name, file_path)
            logger.info(f"Rapport uploadé dans MinIO : {object_name}")
            return True
        except Exception as e:
            logger.warning(f"Upload MinIO échoué : {e}")
            return False
