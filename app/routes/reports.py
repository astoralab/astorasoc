import os
from datetime import datetime
from io import BytesIO

from flask import Blueprint, abort, current_app, send_file
from flask_login import current_user
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from app import db
from app.decorators import roles_required
from app.ai_reports import AI_SECTION_KEYS, SECTION_TITLES, ai_config_summary, ai_reports_enabled, build_ai_docx, call_ai, case_allows_report, collect_case_intelligence, enhanced_context
from app.docx_reports import build_case_docx, case_report_context
from app.models import Case, Report
from app.utils import audit, case_is_assigned_to, format_short_datetime, random_filename, role_allows, setting, timeline, tracking_label

reports_bp = Blueprint("reports", __name__)


def require_approved_report_case(case):
    if not case_allows_report(case):
        abort(403)


def try_ai_sections(case, case_ref, report_kind):
    if not ai_reports_enabled():
        return None
    ai_meta = ai_config_summary()
    try:
        return call_ai(collect_case_intelligence(case, current_user))
    except Exception as exc:
        current_app.logger.exception("AI report generation failed; falling back to standard %s report.", report_kind)
        detail = (
            f"AI report generation failed. Case={case_ref} Report Type={report_kind} "
            f"Provider={ai_meta['provider_label']} Model={ai_meta['model_label']} "
            f"User={current_user.full_name} Status=Failure Error={exc}"
        )
        timeline(case, "AI report failed", detail, current_user.id)
        audit("ai_report_failed", detail, current_user.id)
        db.session.commit()
        return None


def record_report(case, filename, enhanced_by_ai, report_kind):
    case_ref = tracking_label(case)
    ai_meta = ai_config_summary() if enhanced_by_ai else {"provider_label": "Standard Generator", "model_label": "Rule-based"}
    db.session.add(Report(
        case_id=case.id,
        generated_by_id=current_user.id,
        filename=filename,
        enhanced_by_ai=enhanced_by_ai,
        approved_report=True,
        report_version="1.0",
    ))
    detail = (
        f"Report generated. Case={case_ref} Report Type={report_kind} "
        f"Provider={ai_meta['provider_label']} Model={ai_meta['model_label']} "
        f"User={current_user.full_name} Status=Success"
    )
    if enhanced_by_ai:
        audit("ai_report_generated", detail, current_user.id)
    else:
        audit("report_generated", detail, current_user.id)


@reports_bp.route("/cases/<int:case_id>/report.docx")
@roles_required("Admin", "Lead", "Analyst")
def case_report_docx(case_id):
    case = load_report_case(case_id)
    require_approved_report_case(case)
    case_ref = tracking_label(case)
    sections = try_ai_sections(case, case_ref, "DOCX")
    if sections:
        try:
            buffer = build_ai_docx(case, current_user, sections)
        except Exception as exc:
            current_app.logger.exception("AI DOCX rendering failed; falling back to standard report.")
            ai_meta = ai_config_summary()
            detail = (
                f"AI report rendering failed. Case={case_ref} Report Type=DOCX "
                f"Provider={ai_meta['provider_label']} Model={ai_meta['model_label']} "
                f"User={current_user.full_name} Status=Failure Error={exc}"
            )
            timeline(case, "AI report failed", detail, current_user.id)
            audit("ai_report_failed", detail, current_user.id)
            db.session.commit()
            sections = None
        else:
            filename = random_filename(f"case-{case_ref}.docx")
            download_name = f"astorasoc-case-{case_ref}.docx"
            record_report(case, filename, True, "DOCX")
    if not sections:
        buffer = build_case_docx(case, current_user, report_template_path())
        filename = random_filename(f"case-{case_ref}.docx")
        download_name = f"astorasoc-case-{case_ref}.docx"
        record_report(case, filename, False, "DOCX")
    db.session.commit()
    return send_file(
        buffer,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=download_name,
    )


@reports_bp.route("/cases/<int:case_id>/report")
@roles_required("Admin", "Lead", "Analyst")
def case_report(case_id):
    case = load_report_case(case_id)
    require_approved_report_case(case)
    case_ref = tracking_label(case)
    sections = try_ai_sections(case, case_ref, "PDF")
    if sections:
        try:
            buffer = build_ai_pdf(case, current_user, sections)
        except Exception as exc:
            current_app.logger.exception("AI PDF rendering failed; falling back to standard report.")
            ai_meta = ai_config_summary()
            detail = (
                f"AI report rendering failed. Case={case_ref} Report Type=PDF "
                f"Provider={ai_meta['provider_label']} Model={ai_meta['model_label']} "
                f"User={current_user.full_name} Status=Failure Error={exc}"
            )
            timeline(case, "AI report failed", detail, current_user.id)
            audit("ai_report_failed", detail, current_user.id)
            db.session.commit()
        else:
            filename = random_filename(f"case-{case_ref}.pdf")
            record_report(case, filename, True, "PDF")
            db.session.commit()
            return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"astorasoc-case-{case_ref}.pdf")

    context = case_report_context(case, current_user)
    buffer = build_context_pdf(context)
    filename = random_filename(f"case-{case_ref}.pdf")
    record_report(case, filename, False, "PDF")
    db.session.commit()
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"astorasoc-case-{case_ref}.pdf")


def build_ai_pdf(case, generated_by, sections):
    return build_context_pdf(enhanced_context(case, generated_by, sections), approved_ai=True)


def build_context_pdf(context, approved_ai=False):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 44
    y = height - 54
    case_ref = context["case_id"]

    def new_page():
        nonlocal y
        pdf.showPage()
        y = height - 54
        header(compact=True)

    def ensure(space=70):
        if y < margin + space:
            new_page()

    def line(text, size=9, font="Helvetica", color=colors.HexColor("#1d2b32"), gap=13):
        nonlocal y
        ensure(gap + 10)
        pdf.setFont(font, size)
        pdf.setFillColor(color)
        pdf.drawString(margin, y, str(text)[:132])
        y -= gap

    def paragraph_text(text, width_chars=96):
        for chunk in wrap(text or "", width_chars):
            line(chunk)

    def section(title):
        nonlocal y
        ensure(52)
        y -= 8
        pdf.setFillColor(colors.HexColor("#071315"))
        pdf.roundRect(margin, y - 20, width - margin * 2, 26, 5, fill=1, stroke=0)
        pdf.setFillColor(colors.HexColor("#24d6a3"))
        pdf.setFont("Helvetica-Bold", 9.5)
        pdf.drawString(margin + 12, y - 12, title.upper())
        y -= 36

    def badge(text, x, y_pos, fill):
        pdf.setFillColor(fill)
        pdf.roundRect(x, y_pos - 4, max(70, len(text) * 5.8 + 18), 18, 9, fill=1, stroke=0)
        pdf.setFillColor(colors.white)
        pdf.setFont("Helvetica-Bold", 8)
        pdf.drawString(x + 9, y_pos + 1, text)

    def header(compact=False):
        pdf.setFillColor(colors.HexColor("#071315"))
        pdf.rect(0, height - 36, width, 36, fill=1, stroke=0)
        pdf.setFillColor(colors.HexColor("#24d6a3"))
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(margin, height - 23, "ASTORASOC CASE INVESTIGATION REPORT")
        pdf.setFillColor(colors.HexColor("#9fb8b4"))
        pdf.setFont("Helvetica", 8)
        pdf.drawRightString(width - margin, height - 23, case_ref if compact else context["classification"])
        pdf.setFillColor(colors.HexColor("#9fb8b4"))
        pdf.setFont("Helvetica", 7)
        footer_text = (
            f"AstoraSOC v{context['report_version']} | {case_ref} | {context['classification']} | "
            f"Generated {context['generated_at']} | Page {pdf.getPageNumber()} | Generated by AstoraSOC"
        )
        pdf.drawCentredString(width / 2, 24, footer_text[:150])

    def draw_table(headers, rows, col_widths):
        nonlocal y
        if not rows:
            return
        row_gap = 10
        x0 = margin

        def cell_lines(value, col_width):
            return wrap(str(value or ""), max(int(col_width / 5.2), 12))

        def draw_row(values, is_header=False):
            nonlocal y
            lines_by_cell = [cell_lines(value, col_widths[idx]) for idx, value in enumerate(values)]
            row_height = max(len(lines) for lines in lines_by_cell) * row_gap + 10
            ensure(row_height + 14)
            fill = colors.HexColor("#dff3ef") if is_header else colors.white
            text_color = colors.HexColor("#063b39") if is_header else colors.HexColor("#1d2b32")
            font = "Helvetica-Bold" if is_header else "Helvetica"
            pdf.setFillColor(fill)
            pdf.rect(x0, y - row_height + 3, sum(col_widths), row_height, fill=1, stroke=0)
            pdf.setStrokeColor(colors.HexColor("#b7d7d2"))
            pdf.rect(x0, y - row_height + 3, sum(col_widths), row_height, fill=0, stroke=1)
            x = x0
            for idx, lines in enumerate(lines_by_cell):
                pdf.setFillColor(text_color)
                pdf.setFont(font, 7.4 if is_header else 7)
                line_y = y - 9
                for part in lines[:6]:
                    pdf.drawString(x + 5, line_y, part[:90])
                    line_y -= row_gap
                x += col_widths[idx]
            y -= row_height

        draw_row(headers, True)
        for row in rows:
            draw_row(list(row)[: len(headers)] + [""] * max(0, len(headers) - len(row)))
        y -= 8

    def add_section(title_text, body=None, table_data=None, headers=None, widths=None):
        if not body and not table_data:
            return
        section(title_text)
        if body:
            paragraph_text(body)
            y_gap()
        if table_data and headers and widths:
            draw_table(headers, table_data, widths)

    def draw_chart_image(chart, figure_number):
        nonlocal y
        image_bytes = chart.get("png")
        if not image_bytes:
            return
        image_width = width - margin * 2
        image_height = 184
        ensure(image_height + 38)
        pdf.drawImage(
            ImageReader(BytesIO(image_bytes)),
            margin,
            y - image_height,
            width=image_width,
            height=image_height,
            preserveAspectRatio=True,
            mask="auto",
        )
        y -= image_height + 10
        pdf.setFillColor(colors.HexColor("#52646d"))
        pdf.setFont("Helvetica-Oblique", 7.5)
        pdf.drawString(margin, y, f"Figure {figure_number}: {chart.get('caption', chart.get('title', 'Report chart'))}")
        y -= 18

    def y_gap(amount=4):
        nonlocal y
        y -= amount

    header()
    pdf.setFillColor(colors.HexColor("#071315"))
    pdf.setFont("Helvetica-Bold", 23)
    pdf.drawString(margin, y, "AstoraSOC")
    y -= 26
    pdf.setFont("Helvetica", 11)
    pdf.setFillColor(colors.HexColor("#52646d"))
    pdf.drawString(margin, y, "SOC & Incident Response Platform")
    y -= 26
    pdf.setFillColor(colors.HexColor("#071315"))
    pdf.setFont("Helvetica-Bold", 19)
    pdf.drawString(margin, y, "Case Investigation Report")
    y -= 24
    pdf.setFont("Helvetica-Bold", 10)
    pdf.setFillColor(colors.HexColor("#138c7b"))
    pdf.drawString(margin, y, f"{case_ref} | {context['case_title']}"[:110])
    badge(context.get("severity") or "Severity", margin + 235, y - 1, severity_color(context.get("severity")))
    badge("Approved Report", margin + 320, y - 1, colors.HexColor("#0f766e"))
    y -= 28
    line(f"Generated by {context['generated_by']} | {context['generated_at']} | Version {context['report_version']}", size=8, color=colors.HexColor("#52646d"))
    draw_table(["Field", "Value"], [
        ["Case Type", context["case_type"]],
        ["Final Disposition", context["final_disposition"]],
        ["Classification", context["classification"]],
        ["Report Version", context["report_version"]],
    ], [150, 370])
    new_page()

    add_section("Management Summary", context["summary"])
    add_section("Executive Impact Summary", context.get("executive_impact_summary"))
    add_section("Executive Risk Scorecard", table_data=context["scorecard_rows"], headers=["Category", "Status"], widths=[230, 290])
    add_section("Incident Classification", table_data=context["classification_rows"], headers=["Category", "Assessment"], widths=[150, 370])
    add_section("MITRE ATT&CK Mapping", table_data=context.get("mitre_rows"), headers=["Field", "Value"], widths=[150, 370])
    add_section("Root Cause Analysis", context["root_cause_analysis"])
    add_section("Asset Impact Assessment", f"{context['business_impact']}\n\n{context['asset_impact']}", context["asset_rows"], ["Field", "Value"], [130, 390])
    add_section("Investigation Narrative", context["investigation_narrative"])
    add_section("Technical Findings", table_data=context["technical_findings_rows"], headers=["Finding ID", "Title", "Description", "Severity", "Status"], widths=[55, 105, 220, 60, 80])
    add_section("Evidence Assessment", context["evidence_assessment"])
    if context.get("evidence_images"):
        section("Evidence Preview")
        for index, image in enumerate(context["evidence_images"][:4], 1):
            draw_chart_image(image, index)
    add_section("Risk Assessment", context["risk_justification"], (context.get("risk_metric_rows") or []) + context["risk_rows"], ["Risk Factor", "Assessment"], [150, 370])
    add_section("Vulnerability Remediation Details", table_data=context.get("vulnerability_rows"), headers=["Field", "Detail"], widths=[150, 370])
    add_section("Technical Remediation Summary", context.get("technical_remediation_summary"), context.get("technical_remediation_rows"), ["Field", "Detail"], [150, 370])
    if context.get("chart_images"):
        section("Report Visual Summary")
        for index, chart in enumerate(context["chart_images"][:3], 1):
            draw_chart_image(chart, index)
    add_section("Remediation Validation", context["remediation_validation"])
    if context["containment_rows"]:
        add_section("Containment and Response Actions", context["remediation_summary"])
        add_section("Containment Action Summary", table_data=[[row[0], row[2], row[3], row[5], row[6], row[12]] for row in context["containment_rows"]], headers=["ID", "Action", "Target", "Risk", "Status", "Result"], widths=[70, 90, 110, 50, 70, 130])
    add_section("Timeline Highlights", table_data=context["timeline_rows"], headers=["Date/Time", "Actor", "Milestone", "Summary"], widths=[85, 85, 105, 245])
    add_section("Task Completion Summary", table_data=context["task_summary_rows"], headers=["Metric", "Count"], widths=[160, 360])
    add_section("Reviewer Approval and Closure", table_data=context["review_rows"], headers=["Field", "Value"], widths=[140, 380])
    add_section("Lessons Learned", context["lessons_learned"])
    add_section("Recommendations", context["recommendations"])
    add_section("Final Conclusion", context["final_conclusion"])
    if context["ioc_rows"]:
        add_section("Appendix: IOC Intelligence", table_data=context["ioc_rows"], headers=["Type", "Indicator", "Confidence", "First Seen", "Last Seen", "Source"], widths=[55, 155, 65, 85, 85, 75])
    if context["evidence_rows"]:
        add_section("Appendix: Evidence Register", context["evidence_summary"], context["evidence_rows"], ["Preview", "Filename", "Type", "Size", "Uploaded By", "Upload Time", "SHA256", "Purpose"], [58, 82, 48, 48, 62, 62, 118, 42])
    if context["note_rows"]:
        add_section("Appendix: Investigation Journal", table_data=context["note_rows"], headers=["Date", "Author", "Note"], widths=[85, 95, 340])
    pdf.save()
    buffer.seek(0)
    return buffer


def wrap(text, width=95):
    words = (text or "").split()
    lines = []
    current = []
    for word in words:
        if len(word) > width:
            if current:
                lines.append(" ".join(current))
                current = []
            lines.extend(word[index : index + width] for index in range(0, len(word), width))
            continue
        if sum(len(w) for w in current) + len(current) + len(word) > width:
            if current:
                lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines or ["-"]


def severity_color(severity):
    return {
        "Critical": colors.HexColor("#ff355d"),
        "High": colors.HexColor("#ff8a2a"),
        "Medium": colors.HexColor("#b58a00"),
        "Low": colors.HexColor("#2f6e9f"),
    }.get(severity, colors.HexColor("#607d8b"))


def report_template_path():
    stored = setting("report_template_file")
    if stored and stored.lower().endswith(".docx"):
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], "report_templates", stored)
        if os.path.exists(path):
            return path
    default_path = os.path.join(current_app.root_path, "static", "templates", "default-report-template.docx")
    return default_path if os.path.exists(default_path) else None


def load_report_case(case_id):
    case = Case.query.get_or_404(case_id)
    if role_allows(current_user.role, "Analyst") and not case_is_assigned_to(case, current_user):
        abort(403)
    return case
