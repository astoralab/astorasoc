import os
import re
import zipfile
from collections import Counter
from datetime import datetime
from html import escape
from io import BytesIO

from flask import current_app

from app.ioc_intel import canonical_ioc_type, extract_iocs, ioc_type_label, sanitize_ioc_value
from app.playbooks import active_case_playbook, aligned_case_tasks
from app.report_charts import render_report_charts
from app.utils import format_short_datetime, tracking_label
from app.workflow import status_label


PLACEHOLDER_HINTS = {
    "case_id": "AstoraSOC tracking ID",
    "case_title": "Case title",
    "severity": "Case severity",
    "status": "Case workflow status",
    "assigned_analysts": "Assigned analyst names",
    "summary": "Case description / executive summary",
    "timeline": "Investigation timeline",
    "iocs": "IOC intelligence",
    "evidence": "Evidence list",
    "tasks": "Investigation tasks",
    "notes": "Investigation journal notes",
    "recommendations": "Closure recommendations",
}

EMPTY_VALUES = {"", "-", "n/a", "na", "none", "null", "undefined", "unknown", "not available", "not set"}
MAJOR_TIMELINE_KEYWORDS = (
    "case created",
    "investigation started",
    "evidence",
    "ioc",
    "severity",
    "assigned",
    "reassigned",
    "review requested",
    "closure",
    "closed",
    "reopened",
    "false positive",
    "containment",
    "remediation",
    "task completed",
    "approved",
)
TIMELINE_NOISE_KEYWORDS = (
    "report",
    "pdf",
    "docx",
    "ai report failed",
    "note added",
    "note updated",
    "chat",
)

CASE_PROFILES = {
    "Vulnerability Remediation": {
        "keywords": ("cve", "vulnerability", "patch", "kernel", "cis", "benchmark", "compliance", "hardening", "remediation"),
        "task_keywords": ("vulnerab", "risk", "patch", "remediat", "scan", "validate", "verify", "monitor", "asset", "owner", "closure"),
        "closed_disposition": "Vulnerability Confirmed and Remediated",
        "active_disposition": "Vulnerability Remediation In Progress",
        "focus": "validation, patch planning, remediation verification, and post-remediation monitoring",
    },
    "Credential Access": {
        "keywords": ("credential", "password", "login", "authentication", "account", "token", "session", "brute", "mfa"),
        "task_keywords": ("auth", "session", "account", "password", "token", "mfa", "contain", "reset", "user", "login"),
        "closed_disposition": "Credential Access Reviewed and Contained",
        "active_disposition": "Credential Access Investigation In Progress",
        "focus": "authentication review, session analysis, account validation, token review, and containment",
    },
    "Malware": {
        "keywords": ("malware", "trojan", "ransom", "virus", "payload", "process", "quarantine", "file hash", "edr"),
        "task_keywords": ("malware", "isolate", "ioc", "hash", "process", "quarantine", "remove", "recover", "host"),
        "closed_disposition": "Malware Activity Remediated",
        "active_disposition": "Malware Investigation In Progress",
        "focus": "malware validation, host containment, IOC collection, eradication, and recovery validation",
    },
    "Malware Incident": {
        "keywords": ("malware", "trojan", "ransom", "virus", "payload", "process", "quarantine", "file hash", "edr"),
        "task_keywords": ("malware", "isolate", "ioc", "hash", "process", "quarantine", "remove", "recover", "host"),
        "closed_disposition": "Malware Activity Remediated",
        "active_disposition": "Malware Investigation In Progress",
        "focus": "malware validation, host containment, IOC collection, eradication, and recovery validation",
    },
    "Phishing Incident": {
        "keywords": ("phishing", "email", "mailbox", "credential harvest"),
        "task_keywords": ("phish", "email", "mailbox", "user", "indicator", "credential", "awareness", "closure"),
        "closed_disposition": "Phishing Investigation Completed",
        "active_disposition": "Phishing Investigation In Progress",
        "focus": "phishing validation, evidence preservation, user impact review, indicator blocking, and closure validation",
    },
    "Threat Hunt": {
        "keywords": ("hunt", "hypothesis", "threat hunting", "anomaly"),
        "task_keywords": ("hunt", "query", "hypothesis", "ioc", "scope", "validate", "correlat"),
        "closed_disposition": "Threat Hunt Completed",
        "active_disposition": "Threat Hunt In Progress",
        "focus": "hypothesis validation, related activity review, and threat confirmation",
    },
    "Privilege Escalation": {
        "keywords": ("privilege escalation", "elevation", "admin right", "sudo"),
        "task_keywords": ("privilege", "admin", "account", "scope", "contain", "evidence", "closure"),
        "closed_disposition": "Privilege Escalation Reviewed and Contained",
        "active_disposition": "Privilege Escalation Investigation In Progress",
        "focus": "privilege validation, account scope review, evidence collection, containment, and monitoring",
    },
    "Lateral Movement": {
        "keywords": ("lateral movement", "remote logon", "psexec", "rdp", "smb"),
        "task_keywords": ("lateral", "remote", "host", "account", "scope", "evidence", "contain", "closure"),
        "closed_disposition": "Lateral Movement Investigation Completed",
        "active_disposition": "Lateral Movement Investigation In Progress",
        "focus": "movement path validation, affected host scoping, account review, and containment assessment",
    },
    "Data Exfiltration": {
        "keywords": ("exfiltration", "data transfer", "data loss", "large upload"),
        "task_keywords": ("data", "transfer", "scope", "destination", "evidence", "contain", "closure"),
        "closed_disposition": "Data Exfiltration Investigation Completed",
        "active_disposition": "Data Exfiltration Investigation In Progress",
        "focus": "data movement validation, exposure assessment, destination review, and impact documentation",
    },
    "Compliance": {
        "keywords": ("audit", "policy", "control", "compliance"),
        "task_keywords": ("control", "policy", "evidence", "audit", "validate", "review", "closure"),
        "closed_disposition": "Compliance Review Completed",
        "active_disposition": "Compliance Review In Progress",
        "focus": "control validation, evidence review, and compliance closure",
    },
    "Compliance Investigation": {
        "keywords": ("audit", "policy", "control", "compliance"),
        "task_keywords": ("control", "policy", "evidence", "audit", "validate", "review", "closure", "compliance"),
        "closed_disposition": "Compliance Review Completed",
        "active_disposition": "Compliance Review In Progress",
        "focus": "control validation, evidence review, remediation gap tracking, and compliance closure",
    },
    "Asset Investigation": {
        "keywords": ("asset", "inventory", "exposure", "critical asset"),
        "task_keywords": ("asset", "owner", "impact", "evidence", "exposure", "review", "closure"),
        "closed_disposition": "Asset Investigation Completed",
        "active_disposition": "Asset Investigation In Progress",
        "focus": "asset context validation, exposure assessment, ownership review, and operational impact analysis",
    },
    "Security Request": {
        "keywords": ("request", "service request", "security task"),
        "task_keywords": ("request", "review", "evidence", "document", "remediation", "closure"),
        "closed_disposition": "Security Request Completed",
        "active_disposition": "Security Request In Progress",
        "focus": "request validation, evidence gathering, action documentation, and closure readiness",
    },
    "Manual Investigation": {
        "keywords": ("manual",),
        "task_keywords": ("review", "gather", "investigation", "document", "remediation", "closure", "evidence"),
        "closed_disposition": "Manual Investigation Completed",
        "active_disposition": "Manual Investigation In Progress",
        "focus": "case review, evidence gathering, investigation documentation, remediation identification, and closure readiness",
    },
    "Generic": {
        "keywords": (),
        "task_keywords": ("validate", "review", "evidence", "ioc", "contain", "document", "closure"),
        "closed_disposition": "Security Review Completed",
        "active_disposition": "Security Review In Progress",
        "focus": "general security validation, evidence review, response planning, and closure readiness",
    },
    "Incident Response": {
        "keywords": (),
        "task_keywords": ("scope", "evidence", "ioc", "contain", "recover", "monitor", "review", "closure"),
        "closed_disposition": "Confirmed Security Incident",
        "active_disposition": "Active Security Investigation",
        "focus": "scope validation, evidence review, containment, recovery, and monitoring",
    },
}


def build_case_docx(case, generated_by, template_path=None):
    context = case_report_context(case, generated_by)
    if template_path and template_path.lower().endswith(".docx") and os.path.exists(template_path):
        try:
            return fill_docx_template(template_path, context)
        except (zipfile.BadZipFile, KeyError, RuntimeError):
            current_app.logger.exception("Failed to fill DOCX report template; falling back to default AstoraSOC report.")
    return build_default_docx(context)


def case_report_context(case, generated_by):
    assigned = ", ".join(user.full_name for user in case.assigned_users)
    if not assigned and case.assignee:
        assigned = case.assignee.full_name
    report_case_type = case_type_for_case(case)
    profile = case_profile(report_case_type)
    active_playbook = active_case_playbook(case)
    aligned_tasks = aligned_case_tasks(case)
    relevant_tasks = aligned_tasks if active_playbook and aligned_tasks else relevant_case_tasks(aligned_tasks, report_case_type)
    active_tasks = [task for task in relevant_tasks if not task.is_complete]
    completed_tasks = [task for task in relevant_tasks if task.is_complete]
    final_disposition = disposition_for_case(case)
    closure_reason = clean_closure_reason(case, final_disposition)
    ioc_rows = []
    for ioc in case.iocs:
        ioc_type = display_ioc_type(ioc.type, ioc.value)
        value = sanitize_ioc_value(ioc_type, ioc.value)
        if not value:
            continue
        ioc_rows.append(
            [
                ioc_type_label(ioc_type),
                value,
                ioc.confidence or "Medium",
                format_short_datetime(ioc.first_seen_at),
                format_short_datetime(ioc.last_seen_at),
                clean_value(ioc.source_system or ioc.source) or "AstoraSOC",
            ]
        )
    evidence_rows = []
    for item in case.evidence:
        filename = clean_value(item.original_filename)
        row = [
            evidence_preview_status(item),
            filename,
            evidence_type(item.original_filename or ""),
            evidence_file_size(item),
            item.uploaded_by.full_name if item.uploaded_by else "System",
            format_short_datetime(item.uploaded_at),
            clean_value(item.sha256),
            evidence_purpose(item),
        ]
        if any(meaningful(cell) for cell in row):
            evidence_rows.append(row)
    evidence_images = evidence_preview_images(case.evidence)
    timeline_rows = timeline_highlights(case)
    appendix_timeline_rows = [
        [
            format_short_datetime(event.created_at),
            event.actor.full_name if event.actor else "System",
            clean_value(event.event_type),
            clean_value(event.description),
        ]
        for event in reversed(case.timeline)
        if (meaningful(event.event_type) or meaningful(event.description))
        and not any(word in f"{event.event_type} {event.description}".lower() for word in TIMELINE_NOISE_KEYWORDS)
    ]
    note_rows = [
        [
            format_short_datetime(note.created_at),
            note.created_by.full_name if note.created_by else "System",
            clean_multiline(note.body),
        ]
        for note in case.notes
        if meaningful(note.body)
    ][:12]
    action_rows = [
        [
            action.containment_id or f"CA-{action.id:06d}",
            format_short_datetime(action.created_at),
            action.action_type.replace("_", " ").title(),
            action.target,
            clean_value(action.asset.hostname if action.asset else action.target_host),
            action.risk_level or "Medium",
            status_label(action.status),
            action.approval_requirement or "Lead approval required",
            (action.execution_provider or "MANUAL").replace("_", " ").title(),
            action.requested_by.full_name if action.requested_by else "System",
            action.approved_by.full_name if action.approved_by else "",
            action.executed_by.full_name if action.executed_by else "",
            clean_value(action.rollback_result or action.execution_result or action.output or action.notes),
        ]
        for action in case.containment_actions
    ]
    task_rows = [
        [
            clean_value(task.title),
            task.source or "Analyst",
            clean_value(task.playbook_name),
            "Completed" if task.is_complete else "Active",
            task.completed_by.full_name if task.completed_by else "",
            format_short_datetime(task.completed_at) if task.completed_at else "",
        ]
        for task in case.tasks
        if task in relevant_tasks and meaningful(task.title)
    ]
    recommendations = recommendations_for_case(case, final_disposition, bool(ioc_rows), bool(evidence_rows))
    remediation_actions = extract_remediation_actions(case)
    remediation_detail_rows = technical_remediation_rows(case, remediation_actions)
    vulnerability_rows = vulnerability_detail_rows(case)
    overview_rows = meaningful_rows([
        ("Case ID", tracking_label(case)),
        ("Title", case.title),
        ("Case Type", report_case_type),
        ("Business Impact", getattr(case, "business_impact", None)),
        ("Source", case.source),
        ("Severity", case.severity),
        ("Status", status_label(case.status)),
        ("Final Disposition", final_disposition),
        ("Priority", priority_for_case(case)),
        ("Created", format_short_datetime(case.created_at)),
        ("Closed", format_short_datetime(case.closed_at) if case.closed_at else ""),
        ("MTTR", mttr_label(case)),
        ("Assigned Analysts", assigned),
        ("Lead Reviewer", case.reviewed_by.full_name if case.reviewed_by else ""),
        ("Rule ID", case.rule_id),
        ("Host", case.affected_host),
        ("Username", case.affected_user),
        ("Source IP", case.source_ip),
        ("Destination IP", case.destination_ip),
        ("MITRE Tactic", case.mitre_tactic),
        ("MITRE Technique", case.mitre_technique),
        ("CVE ID", getattr(case, "cve_id", None)),
        ("CVSS Score", getattr(case, "cvss_score", None)),
        ("Affected Software", getattr(case, "affected_software", None)),
        ("Affected Version", getattr(case, "affected_version", None)),
        ("Fixed Version", getattr(case, "fixed_version", None)),
        ("Patch Status", getattr(case, "patch_status", None)),
        ("Remediation Owner", getattr(case, "remediation_owner", None)),
    ])
    asset_rows = asset_summary_rows(case)
    risk_rows = risk_assessment_rows(case, final_disposition, bool(completed_tasks), bool(evidence_rows))
    initial_risk = clean_value(case.severity) or "Medium"
    residual_risk = residual_risk_label(case, report_case_type, bool(completed_tasks))
    risk_metric_rows = risk_metric_assessment_rows(case, report_case_type, bool(evidence_rows), bool(completed_tasks))
    scorecard_rows = executive_scorecard_rows(case, final_disposition, bool(evidence_rows), bool(completed_tasks), residual_risk)
    classification_rows = incident_classification_rows(case, report_case_type, final_disposition)
    mitre_rows = mitre_attack_rows(case)
    if active_playbook:
        classification_rows.extend([
            ["Active Playbook", active_playbook.name],
            ["Playbook Category", active_playbook.category],
        ])
    technical_findings_rows = technical_findings_for_case(case, report_case_type, final_disposition)
    review_rows = meaningful_rows([
        ("Lead Reviewer", case.reviewed_by.full_name if case.reviewed_by else ""),
        ("Closed By", case.closed_by.full_name if case.closed_by else ""),
        ("Approval Date", format_short_datetime(case.closed_at) if case.closed_at else ""),
        ("Final Disposition", final_disposition),
        ("Closure Reason", closure_reason),
    ])
    ioc_counts = Counter(row[0] for row in ioc_rows)
    task_summary_rows = [
        ["Completed Tasks", str(len(completed_tasks))],
        ["Pending Tasks", str(len(active_tasks))],
    ]
    chart_rows = report_chart_rows(
        case,
        report_case_type,
        ioc_counts,
        len(completed_tasks),
        len(active_tasks),
        evidence_rows,
        timeline_rows,
        action_rows,
        remediation_detail_rows,
        remediation_actions,
    )
    chart_images = render_report_charts(chart_rows)
    return {
        "case_id": tracking_label(case),
        "case_title": case.title or "Untitled case",
        "case_type": report_case_type,
        "source": clean_value(case.source),
        "severity": clean_value(case.severity),
        "status": status_label(case.status),
        "rule_id": clean_value(case.rule_id),
        "host": clean_value(case.affected_host),
        "username": clean_value(case.affected_user),
        "source_ip": clean_value(case.source_ip),
        "destination_ip": clean_value(case.destination_ip),
        "mitre_tactic": clean_value(case.mitre_tactic),
        "mitre_technique": clean_value(case.mitre_technique),
        "assigned_analysts": assigned or "",
        "active_playbook_name": active_playbook.name if active_playbook else "",
        "active_playbook_category": active_playbook.category if active_playbook else "",
        "created_at": format_short_datetime(case.created_at),
        "updated_at": format_short_datetime(case.updated_at),
        "closed_at": format_short_datetime(case.closed_at) if case.closed_at else "",
        "mttr": mttr_label(case),
        "generated_at": format_short_datetime(datetime.utcnow()),
        "generated_by": generated_by.full_name if generated_by else "AstoraSOC",
        "summary": executive_summary_for_case(case, report_case_type, final_disposition, closure_reason, bool(ioc_rows), bool(evidence_rows), len(completed_tasks)),
        "executive_impact_summary": executive_impact_summary_for_case(case, report_case_type, final_disposition, recommendations),
        "root_cause_analysis": root_cause_for_case(case, report_case_type),
        "investigation_narrative": investigation_narrative_for_case(case, report_case_type, bool(evidence_rows), bool(completed_tasks), final_disposition),
        "evidence_assessment": evidence_assessment_for_case(case, evidence_rows),
        "remediation_validation": remediation_validation_for_case(case, report_case_type, bool(completed_tasks), closure_reason),
        "technical_remediation_summary": technical_remediation_summary_for_case(case, remediation_detail_rows, remediation_actions),
        "lessons_learned": lessons_learned_for_case(case, report_case_type),
        "final_conclusion": final_conclusion_for_case(case, report_case_type, final_disposition),
        "closure_reason": closure_reason,
        "final_disposition": final_disposition,
        "business_impact": business_impact_for_case(case),
        "asset_impact": asset_impact_for_case(case),
        "investigation_findings": investigation_findings_for_case(case, report_case_type, bool(evidence_rows), bool(ioc_rows)),
        "risk_justification": risk_narrative_for_case(case, final_disposition, initial_risk, residual_risk),
        "evidence_summary": evidence_summary_for_case(evidence_rows),
        "remediation_summary": remediation_summary_for_case(case, report_case_type, bool(action_rows), closure_reason),
        "remediation_actions": "\n".join(remediation_actions),
        "timeline": rows_to_text(timeline_rows),
        "iocs": rows_to_text(ioc_rows),
        "evidence": rows_to_text(evidence_rows),
        "tasks": "\n".join(task.title for task in active_tasks if meaningful(task.title)),
        "completed_tasks": "\n".join(task.title for task in completed_tasks if meaningful(task.title)),
        "notes": rows_to_text(note_rows),
        "containment_actions": rows_to_text(action_rows),
        "recommendations": recommendations,
        "overview_rows": overview_rows,
        "asset_rows": asset_rows,
        "risk_rows": risk_rows,
        "risk_metric_rows": risk_metric_rows,
        "initial_risk": initial_risk,
        "residual_risk": residual_risk,
        "scorecard_rows": scorecard_rows,
        "classification_rows": classification_rows,
        "mitre_rows": mitre_rows,
        "technical_findings_rows": technical_findings_rows,
        "vulnerability_rows": vulnerability_rows,
        "technical_remediation_rows": remediation_detail_rows,
        "task_summary_rows": task_summary_rows,
        "ioc_count_rows": [[kind, str(count)] for kind, count in sorted(ioc_counts.items())],
        "chart_rows": chart_rows,
        "chart_images": chart_images,
        "evidence_images": evidence_images,
        "case_focus": profile["focus"],
        "ioc_rows": ioc_rows,
        "evidence_rows": evidence_rows,
        "timeline_rows": timeline_rows,
        "appendix_timeline_rows": appendix_timeline_rows,
        "task_rows": task_rows,
        "containment_rows": action_rows,
        "note_rows": note_rows,
        "review_rows": review_rows,
        "report_version": "1.0",
        "classification": "Internal Use Only",
    }


def meaningful(value):
    text = str(value or "").strip()
    return bool(text and text.lower() not in EMPTY_VALUES)


def clean_value(value):
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip(" '\"[](){}")
    text = text.rstrip(".,;:")
    return text if meaningful(text) else ""


def clean_multiline(value):
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    text = "\n".join(re.sub(r"[ ]+", " ", line).strip() for line in text.splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text).strip(" '\"[](){}")
    return text if meaningful(text) else ""


def evidence_file_path(item):
    stored = clean_value(getattr(item, "stored_filename", ""))
    if not stored:
        return ""
    return os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence", stored)


def evidence_file_size(item):
    path = evidence_file_path(item)
    if not path or not os.path.exists(path):
        return "Not Available"
    try:
        size = os.path.getsize(path)
    except OSError:
        return "Not Available"
    return human_file_size(size)


def human_file_size(size):
    try:
        size = float(size)
    except (TypeError, ValueError):
        return "Not Available"
    units = ["B", "KB", "MB", "GB"]
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    if unit == 0:
        return f"{int(size)} {units[unit]}"
    return f"{size:.1f} {units[unit]}"


def evidence_preview_status(item):
    filename = clean_value(getattr(item, "original_filename", ""))
    kind = evidence_type(filename)
    path = evidence_file_path(item)
    if kind == "Image" and path and os.path.exists(path):
        return "Image preview available"
    if kind == "PDF":
        return "PDF preview available"
    return "Metadata only"


def evidence_preview_images(evidence_items):
    images = []
    for item in evidence_items:
        if evidence_type(getattr(item, "original_filename", "") or "") != "Image":
            continue
        path = evidence_file_path(item)
        if not path or not os.path.exists(path):
            continue
        try:
            from PIL import Image

            with Image.open(path) as source:
                source.thumbnail((900, 420))
                canvas = Image.new("RGB", (900, 420), "#ffffff")
                x = (900 - source.width) // 2
                y = (420 - source.height) // 2
                canvas.paste(source.convert("RGB"), (x, y))
                buffer = BytesIO()
                canvas.save(buffer, format="PNG", optimize=True)
        except Exception:
            continue
        filename = clean_value(getattr(item, "original_filename", "")) or "Evidence image"
        images.append({
            "title": filename,
            "caption": f"Evidence preview: {filename}",
            "png": buffer.getvalue(),
        })
        if len(images) >= 4:
            break
    return images


def meaningful_rows(rows):
    return [[label, value] for label, value in rows if meaningful(value)]


def mttr_label(case):
    if not case.created_at or not case.closed_at:
        return ""
    seconds = max(0, int((case.closed_at - case.created_at).total_seconds()))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def case_type_for_case(case):
    if getattr(case, "incident_type", None) and meaningful(case.incident_type):
        return case.incident_type
    if getattr(case, "case_type", None) and meaningful(case.case_type):
        return case.case_type
    text = case_signal_text(case)
    for name, profile in CASE_PROFILES.items():
        if name == "Incident Response":
            continue
        if any(keyword in text for keyword in profile["keywords"]):
            return name
    if (case.source or "").lower() == "manual":
        return "Security Operations Task"
    return "Incident Response"


def case_profile(case_type):
    return CASE_PROFILES.get(case_type) or CASE_PROFILES["Incident Response"]


def case_signal_text(case):
    note_text = " ".join(note.body or "" for note in getattr(case, "notes", [])[:8])
    task_text = " ".join(task.title or "" for task in getattr(case, "tasks", [])[:12])
    return " ".join(filter(None, [
        case.title,
        case.description,
        case.source,
        case.rule_id,
        case.mitre_tactic,
        case.mitre_technique,
        case.affected_host,
        case.affected_user,
        note_text,
        task_text,
    ])).lower()


def relevant_case_tasks(tasks, case_type):
    tasks = list(tasks)
    profile = case_profile(case_type)
    keywords = profile["task_keywords"]
    relevant = [task for task in tasks if any(keyword in (task.title or "").lower() for keyword in keywords)]
    if relevant:
        return relevant[:10]
    return tasks[:8]


def priority_for_case(case):
    severity = (case.severity or "").lower()
    criticality = (case.asset.criticality if case.asset else "").lower()
    if "critical" in {severity, criticality}:
        return "P1"
    if severity == "high" or criticality == "high":
        return "P2"
    if severity == "medium" or criticality == "medium":
        return "P3"
    return "P4"


def asset_summary_rows(case):
    asset = case.asset
    if not asset:
        return []
    return meaningful_rows([
        ("Asset Name", getattr(asset, "asset_name", None) or asset.hostname),
        ("Hostname", asset.hostname),
        ("IP Address", asset.ip_address),
        ("Criticality", asset.criticality),
        ("Status", getattr(asset, "status", None)),
        ("Owner", asset.owner),
        ("Business Function", getattr(asset, "business_function", None) or asset.department),
        ("Asset Type", asset.asset_type),
        ("Operating System", asset.operating_system),
        ("Location", getattr(asset, "location", None)),
    ])


def vulnerability_detail_rows(case):
    return meaningful_rows([
        ("CVE Identifier", getattr(case, "cve_id", None)),
        ("Vulnerability Name", case.title if is_vulnerability_case(case) else ""),
        ("Affected Product", getattr(case, "affected_software", None)),
        ("Affected Version", getattr(case, "affected_version", None)),
        ("Fixed Version", getattr(case, "fixed_version", None)),
        ("Severity Rating", case.severity),
        ("CVSS Score", getattr(case, "cvss_score", None)),
        ("Patch Status", getattr(case, "patch_status", None)),
        ("Remediation Owner", getattr(case, "remediation_owner", None)),
    ])


def is_vulnerability_case(case):
    text = " ".join(filter(None, [
        getattr(case, "incident_type", None),
        getattr(case, "case_type", None),
        case.title,
        case.description,
        getattr(case, "cve_id", None),
        getattr(case, "affected_software", None),
    ])).lower()
    return any(token in text for token in ("vulnerability", "cve-", "patch", "remediation", "cvss"))


def evidence_purpose(item):
    name = clean_value(getattr(item, "original_filename", "")) or ""
    lowered = name.lower()
    if any(word in lowered for word in ("patch", "remediat", "fixed", "upgrade", "update", "validation", "verify")):
        return "Validation of remediation or patch deployment."
    if any(word in lowered for word in ("scan", "vulnerability", "cve", "nessus", "openvas")):
        return "Vulnerability validation and remediation evidence."
    if evidence_type(name) == "Image":
        return "Screenshot supporting investigation findings."
    if evidence_type(name) == "Log/Data":
        return "Log or exported telemetry used for technical review."
    if evidence_type(name) == "PDF" or evidence_type(name) == "Document":
        return "Supporting document retained for audit review."
    return "Investigation artifact retained for reviewer validation."


def case_text_sources(case):
    values = [
        case.title,
        case.description,
        getattr(case, "root_cause", None),
        getattr(case, "resolution_summary", None),
        getattr(case, "validation_performed", None),
        getattr(case, "closure_notes", None),
        case.closure_reason,
        getattr(case, "patch_status", None),
    ]
    values.extend(note.body for note in getattr(case, "notes", []) if meaningful(note.body))
    values.extend(task.title for task in getattr(case, "tasks", []) if meaningful(task.title))
    values.extend(item.original_filename for item in getattr(case, "evidence", []) if meaningful(item.original_filename))
    for action in getattr(case, "containment_actions", []):
        values.extend([
            action.action_type,
            action.target,
            action.execution_result,
            action.output,
            action.notes,
            action.rollback_result,
        ])
    return [clean_multiline(value) for value in values if meaningful(value)]


def extract_remediation_actions(case):
    command_patterns = [
        r"\bapt(?:-get)?\s+(?:update|upgrade|install|dist-upgrade)[^\n.;]*",
        r"\b(?:yum|dnf|zypper|pacman)\s+(?:update|upgrade|install)[^\n.;]*",
        r"\b(?:rpm\s+-q|dpkg\s+-l|dpkg-query\s+-W)[^\n.;]*",
        r"\bGet-HotFix\s+KB\d{6,8}\b",
        r"\bsystemctl\s+(?:disable|enable|stop|restart|status)[^\n.;]*",
        r"\b(?:reboot|shutdown\s+/r|restart-computer)\b[^\n.;]*",
        r"\b(?:sc\s+(?:stop|config)|net\s+stop|net\s+user)[^\n.;]*",
        r"\b(?:powershell|pwsh)\s+[^\n.;]*",
        r"\bCVE-\d{4}-\d{4,7}\b",
        r"\bKB\d{6,8}\b",
    ]
    action_keywords = (
        "patch", "patched", "update", "updated", "upgrade", "upgraded", "fixed",
        "remediat", "mitigat", "disabled", "reboot", "restart", "verified",
        "validated", "quarantine", "isolate", "removed", "resolved", "scan",
    )
    actions = []
    seen = set()
    for source in case_text_sources(case):
        candidates = []
        for pattern in command_patterns:
            candidates.extend(match.group(0) for match in re.finditer(pattern, source, re.IGNORECASE))
        candidates.extend(re.split(r"(?<=[.!?])\s+|\n+", source))
        for candidate in candidates:
            text = clean_multiline(candidate)
            if not text or len(text) < 4:
                continue
            lowered = text.lower()
            if not any(keyword in lowered for keyword in action_keywords) and not re.search(r"\bKB\d{6,8}\b", text, re.IGNORECASE):
                continue
            normalized = lowered[:220]
            if normalized in seen:
                continue
            seen.add(normalized)
            actions.append(professionalize_remediation_action(text))
            if len(actions) >= 8:
                return actions
    return actions


def professionalize_remediation_action(text):
    cleaned = clean_multiline(text)
    lowered = cleaned.lower()
    if "patched kernel" in lowered or ("kernel" in lowered and "patch" in lowered):
        return f"Analyst documented remediation activity: {cleaned}."
    if re.search(r"\bapt(?:-get)?\s+update", cleaned, re.IGNORECASE):
        return cleaned
    if re.search(r"\bapt(?:-get)?\s+upgrade", cleaned, re.IGNORECASE):
        return cleaned
    if re.search(r"\b(Get-HotFix|dpkg\s+-l|rpm\s+-q|systemctl|Restart-Computer)\b", cleaned, re.IGNORECASE):
        return cleaned
    if re.search(r"\bKB\d{6,8}\b", cleaned, re.IGNORECASE):
        return f"Applied security update {re.search(r'KB\d{6,8}', cleaned, re.IGNORECASE).group(0).upper()}."
    return cleaned


def technical_remediation_rows(case, remediation_actions):
    commands = [action for action in remediation_actions if looks_like_command(action)]
    patches = [action for action in remediation_actions if any(token in action.lower() for token in ("patch", "kb", "upgrade", "update", "fixed"))]
    cve = clean_value(getattr(case, "cve_id", None)) or "; ".join(sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", "\n".join(case_text_sources(case)), re.IGNORECASE))))[:220]
    validation = clean_multiline(getattr(case, "validation_performed", None))
    if not validation:
        validation_candidates = [action for action in remediation_actions if any(token in action.lower() for token in ("validat", "verified", "scan"))]
        validation = "; ".join(validation_candidates[:2])
    vulnerability_name = " ".join(filter(None, [cve, clean_value(case.title)]))
    rows = [
        ("CVE Identifier", cve),
        ("Vulnerability Addressed", vulnerability_name if is_vulnerability_case(case) else case.title),
        ("Affected Product", getattr(case, "affected_software", None)),
        ("Affected Version", getattr(case, "affected_version", None)),
        ("Fixed Version", getattr(case, "fixed_version", None)),
        ("Installed Patch / Update", "; ".join(patches[:3])),
        ("Verification Command", first_verification_command(commands)),
        ("Commands Executed", "; ".join(commands[:4])),
        ("Verification Result", validation),
        ("Patch Status", getattr(case, "patch_status", None)),
        ("Remediation Owner", getattr(case, "remediation_owner", None)),
    ]
    if any(meaningful(value) for _label, value in rows):
        return [[label, clean_value(value) or "Not Available"] for label, value in rows]
    return []


def first_verification_command(commands):
    for command in commands:
        if re.search(r"\b(Get-HotFix|dpkg\s+-l|rpm\s+-q|systemctl\s+status|scan|verify|validate)\b", command, re.IGNORECASE):
            return command
    return ""


def looks_like_command(text):
    return bool(re.search(r"\b(apt|apt-get|yum|dnf|zypper|rpm|dpkg|Get-HotFix|systemctl|powershell|pwsh|net|sc|reboot|shutdown|Restart-Computer)\b", text, re.IGNORECASE))


def timeline_highlights(case):
    rows = []
    seen_phases = set()
    for event in reversed(case.timeline):
        event_type = clean_value(event.event_type)
        description = clean_value(event.description)
        haystack = f"{event_type} {description}".lower()
        if any(word in haystack for word in TIMELINE_NOISE_KEYWORDS):
            continue
        phase = timeline_phase(haystack)
        if not phase and len(rows) >= 5:
            continue
        if phase in seen_phases:
            continue
        if phase:
            seen_phases.add(phase)
        summary = description or event_type
        rows.append([
            format_short_datetime(event.created_at),
            event.actor.full_name if event.actor else "System",
            timeline_display_phase(phase or event_type),
            summary,
        ])
        if len(rows) >= 8:
            break
    if not rows:
        rows.append([
            format_short_datetime(case.created_at),
            case.created_by.full_name if case.created_by else "System",
            "Case Created",
            f"{tracking_label(case)} was opened for investigation.",
        ])
    return rows


def timeline_display_phase(phase):
    label = clean_value(phase) or "Investigation"
    prefixes = {
        "Case Created": "[+] ",
        "Investigation Started": "[>] ",
        "Evidence Collected": "[E] ",
        "Findings Confirmed": "[F] ",
        "Remediation Performed": "[R] ",
        "Review Requested": "[?] ",
        "Lead Approval": "[A] ",
        "Closure": "[X] ",
    }
    return prefixes.get(label, "[*] ") + label


def timeline_phase(text):
    if "created" in text:
        return "Case Created"
    if "investigat" in text and "started" in text:
        return "Investigation Started"
    if "evidence" in text or "upload" in text:
        return "Evidence Collected"
    if "ioc" in text or "finding" in text or "confirmed" in text:
        return "Findings Confirmed"
    if "patch" in text or "remediat" in text or "contain" in text or "recover" in text:
        return "Remediation Performed"
    if "review" in text and ("request" in text or "submitted" in text):
        return "Review Requested"
    if "approved" in text:
        return "Lead Approval"
    if "closed" in text or "closure" in text:
        return "Closure"
    return ""


def executive_summary_for_case(case, case_type, disposition, closure_reason, has_iocs, has_evidence, completed_count):
    asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected environment"
    severity = clean_value(case.severity) or "the recorded"
    title = clean_value(case.title) or tracking_label(case)
    outcome = disposition.lower()
    impact = business_impact_for_case(case)
    profile = case_profile(case_type)
    if "vulnerability" in case_type.lower():
        first = (
            f"{tracking_label(case)} investigated {title} as a {severity.lower()} vulnerability remediation case affecting {asset_name}. "
            f"The investigation focused on {profile['focus']}."
        )
        second = (
            f"{impact} The case was finalized as {outcome}. "
            f"{completed_count} assigned investigation checklist task{'s' if completed_count != 1 else ''} were completed"
            f"{', supporting evidence was attached' if has_evidence else ''}"
            f"{', and extracted IOCs were reviewed' if has_iocs else ''}. "
            f"{closure_reason if meaningful(closure_reason) else 'Closure was approved based on completed investigation activities and available evidence.'}"
        )
    else:
        first = (
            f"{tracking_label(case)} investigated {title} as a {severity.lower()} SOC case involving {asset_name}. "
            f"Analysts reviewed available alert context, investigation notes, evidence, tasks, and related indicators with emphasis on {profile['focus']}."
        )
        second = (
            f"{impact} The case was finalized as {outcome}. "
            f"{'Evidence and related activity were reviewed' if has_evidence else 'Available case records were reviewed'}"
            f"{', and IOC correlation was considered' if has_iocs else ''}. "
            f"{closure_reason if meaningful(closure_reason) else 'Closure was approved by the reviewer based on available case data.'}"
        )
    return f"{first}\n\n{second}"


def executive_impact_summary_for_case(case, case_type, disposition, recommendations):
    asset_name = clean_value(getattr(case.asset, "asset_name", None) if case.asset else None)
    asset_name = asset_name or clean_value(case.asset.hostname if case.asset else case.affected_host) or "the scoped environment"
    impact = clean_value(getattr(case, "business_impact", None))
    criticality = clean_value(case.asset.criticality if case.asset else "")
    before = risk_score_100(case.severity)
    after = residual_risk_score_100(case, case_type)
    before_label = risk_rating_for_score(before)
    after_label = risk_rating_for_score(after)
    action_text = "; ".join(extract_remediation_actions(case)[:3])
    if not action_text and meaningful(getattr(case, "resolution_summary", None)):
        action_text = clean_multiline(case.resolution_summary)
    outcome = clean_value(disposition)
    sentences = [
        f"The investigation assessed {asset_name} under {case_type.lower()} workflow conditions.",
    ]
    if impact:
        sentences.append(f"Business impact was recorded as {impact.lower()}.")
    elif criticality:
        sentences.append(f"The asset is classified as {criticality.lower()}, which informed prioritization and reviewer attention.")
    sentences.append(f"Risk moved from {before_label.lower()} before remediation to {after_label.lower()} after closure review.")
    if action_text:
        sentences.append(f"Documented response activity included: {action_text}.")
    if outcome:
        sentences.append(f"The final disposition was {outcome}.")
    first_recommendation = next((line.strip("- ") for line in recommendations.splitlines() if meaningful(line)), "")
    if first_recommendation:
        sentences.append(f"Primary recommendation: {first_recommendation}")
    return " ".join(sentences)


def business_impact_for_case(case):
    if meaningful(getattr(case, "business_impact", None)):
        asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected environment"
        return f"Business impact was assessed as {case.business_impact}. This assessment applies to {asset_name} based on the case scope, linked asset context, investigation findings, and reviewer outcome."
    asset = case.asset
    if not asset:
        return "No linked asset record was available. Business impact should be interpreted from the affected host, user, and source context recorded in the case."
    criticality = clean_value(asset.criticality) or "recorded"
    owner = clean_value(asset.owner)
    department = clean_value(asset.department)
    business_function = clean_value(getattr(asset, "business_function", None))
    asset_name = clean_value(getattr(asset, "asset_name", None)) or asset.hostname
    owner_text = f" owned by {owner}" if owner else ""
    department_text = f" in {department}" if department else ""
    function_text = f" supporting {business_function}" if business_function else ""
    impact = f"{asset_name} is a {criticality.lower()} asset{owner_text}{department_text}{function_text}."
    if criticality.lower() == "critical":
        impact += " Because this asset is marked critical, disruption or compromise could affect priority business operations and should receive elevated validation and monitoring."
    else:
        impact += " Business impact should be managed according to the asset criticality, affected service, and any observed user or network exposure."
    return impact


def asset_impact_for_case(case):
    asset = case.asset
    exposure = "Internal exposure"
    if case.source_ip and case.destination_ip:
        exposure = "Network exposure recorded between source and destination addresses"
    elif case.source_ip:
        exposure = "Source network activity recorded"
    if not asset:
        return "Asset Name: Not linked\nOperational Impact: Impact assessment is based on the affected host and case context.\nSecurity Impact: Security impact depends on the validated scope and investigation outcome.\nExposure Level: " + exposure
    criticality = clean_value(asset.criticality) or "Unspecified"
    operational = "Potential disruption to the recorded business function if the asset is unavailable or compromised."
    if criticality.lower() == "critical":
        operational = "High operational sensitivity due to critical asset classification."
    return "\n".join([
        f"Asset Name: {clean_value(getattr(asset, 'asset_name', None)) or asset.hostname}",
        f"Criticality: {criticality}",
        f"Business Function: {clean_value(getattr(asset, 'business_function', None)) or clean_value(asset.department) or 'Business function not specified'}",
        f"Operational Impact: {operational}",
        "Security Impact: Weakness or compromise on this asset may affect confidentiality, integrity, or service availability depending on exposure and privilege context.",
        f"Exposure Level: {exposure}",
    ])


def investigation_findings_for_case(case, case_type, has_evidence, has_iocs):
    notes = [clean_multiline(note.body) for note in case.notes if meaningful(note.body)]
    note_signal = " ".join(professionalize_note(note) for note in notes[:3])
    if not note_signal:
        note_signal = clean_value(case.description)
    if "vulnerability" in case_type.lower():
        finding = "The investigation indicates a vulnerability remediation workflow. Analysts assessed the affected system, documented remediation activity, and prepared the case for closure review."
    else:
        finding = "The investigation reviewed available alert context, case notes, tasks, evidence, and related indicators to determine scope and disposition."
    if note_signal:
        finding += f" Analyst notes indicate: {note_signal[:500]}."
    if has_evidence:
        finding += " Supporting evidence was attached and preserved with hash metadata for review."
    if has_iocs:
        finding += " Extracted indicators were normalized and correlated for related activity."
    else:
        finding += " No confirmed IOCs were recorded for this case."
    return finding


def root_cause_for_case(case, case_type):
    if meaningful(getattr(case, "root_cause", None)):
        return clean_multiline(case.root_cause)
    asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected system"
    title = clean_value(case.title) or tracking_label(case)
    description = clean_value(case.description)
    if "vulnerability" in case_type.lower():
        return (
            f"The investigation determined that {asset_name} required security remediation related to {title}. "
            "The most likely root cause was a missing or incomplete security update, configuration hardening gap, or vulnerable software condition recorded during the case. "
            f"{description if description else 'The available case record did not include separate exploit detail, so the root cause is limited to verified case evidence and analyst notes.'}"
        )
    if "credential" in case_type.lower():
        return (
            f"The case was driven by account or authentication activity involving {asset_name}. "
            "The root cause assessment focused on credential exposure, session risk, access control weakness, or suspicious authentication patterns supported by the case evidence."
        )
    if "malware" in case_type.lower():
        return (
            f"The case involved malware-oriented investigation activity on {asset_name}. "
            "Root cause review focused on suspicious process/file execution, endpoint exposure, and related indicators documented during investigation."
        )
    return (
        f"The case occurred because monitored security activity required validation on {asset_name}. "
        "Root cause was assessed from the recorded alert context, analyst notes, evidence, timeline, and final reviewer decision without inventing unsupported details."
    )


def investigation_narrative_for_case(case, case_type, has_evidence, has_completed_tasks, disposition):
    asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected environment"
    title = clean_value(case.title) or tracking_label(case)
    profile = case_profile(case_type)
    started = format_short_datetime(case.created_at)
    closed = format_short_datetime(case.closed_at) if case.closed_at else ""
    narrative = [
        f"The SOC opened {tracking_label(case)} on {started} to investigate {title} affecting {asset_name}. The investigation followed a {case_type.lower()} workflow focused on {profile['focus']}.",
        "Analysts reviewed the available alert context, affected asset details, case notes, tasks, and related timeline activity to determine scope and support the final disposition.",
    ]
    if has_evidence:
        narrative.append("Supporting evidence was collected and preserved with metadata so the reviewer could validate the investigation outcome.")
    if has_completed_tasks:
        narrative.append("Assigned investigation tasks were completed before closure review, supporting operational readiness for reviewer approval.")
    narrative.append(f"The case reached the final disposition of {disposition}{f' on {closed}' if closed else ''}.")
    return "\n\n".join(narrative)


def technical_findings_for_case(case, case_type, disposition):
    title = clean_value(case.title) or "Validated Security Finding"
    status = "Resolved" if case.status == "CLOSED" and "false positive" not in disposition.lower() else status_label(case.status)
    if "false positive" in disposition.lower():
        status = "False Positive"
    description = clean_value(case.description)
    if not description:
        if "vulnerability" in case_type.lower():
            description = "Investigation confirmed a vulnerability remediation case requiring validation, remediation tracking, and reviewer-approved closure."
        else:
            description = "Investigation validated the recorded security activity using available case context, evidence, notes, and reviewer decision."
    return [[
        "Finding 01",
        title,
        description,
        clean_value(case.severity) or "Medium",
        status,
    ]]


def professionalize_note(note):
    text = clean_multiline(note)
    lowered = text.lower()
    replacements = []
    if "patched kernel" in lowered or ("kernel" in lowered and "patch" in lowered):
        replacements.append("Kernel-level remediation was completed to address the identified vulnerability.")
    if "admin gave permission" in lowered or "permission" in lowered or "approval" in lowered:
        replacements.append("Administrative approval was obtained before remediation or closure activities proceeded.")
    if "password" in lowered and ("reset" in lowered or "changed" in lowered):
        replacements.append("Password reset activity was performed or reviewed as part of credential-risk reduction.")
    if "isolat" in lowered:
        replacements.append("Host isolation activity was performed or reviewed as part of containment.")
    if replacements:
        return " ".join(replacements)
    return text


def executive_scorecard_rows(case, disposition, has_evidence, has_completed_tasks, residual_risk):
    case_type = case_type_for_case(case)
    is_vulnerability = "vulnerability" in case_type.lower()
    closed = case.status == "CLOSED"
    return [
        ["Vulnerability Confirmed" if is_vulnerability else "Security Activity Validated", "Yes" if closed else "In Progress"],
        ["Exploitation Observed", scorecard_exploitation_status(case)],
        ["Evidence Collected", "Yes" if has_evidence else "No"],
        ["Remediation Completed", "Yes" if closed and "false positive" not in disposition.lower() else "No"],
        ["Validation Completed", "Yes" if has_completed_tasks or closed else "In Progress"],
        ["Closure Approved", "Yes" if closed else "No"],
        ["Residual Risk", residual_risk],
    ]


def scorecard_exploitation_status(case):
    status = exploitation_observed(case).lower()
    if status == "yes":
        return "Yes"
    if status == "no" or status.startswith("no evidence"):
        return "No"
    return "Not confirmed by available evidence"


def incident_classification_rows(case, case_type, disposition):
    return meaningful_rows([
        ("Case Type", case_type),
        ("Investigation Category", case_profile(case_type)["focus"].capitalize()),
        ("Detection Source", case.source),
        ("Priority", priority_for_case(case)),
        ("Severity", case.severity),
        ("Classification", "Approved Report / Confidential" if case.status == "CLOSED" else "Internal Use Only"),
        ("Final Disposition", disposition),
    ])


def risk_assessment_rows(case, disposition, has_completed_tasks, has_evidence):
    asset_criticality = clean_value(case.asset.criticality if case.asset else "")
    remediated = case.status == "CLOSED" and ("false positive" not in disposition.lower())
    residual = "Low" if remediated and has_completed_tasks else ("Medium" if case.status == "CLOSED" else clean_value(case.severity) or "Medium")
    return meaningful_rows([
        ("Initial Severity", case.severity),
        ("Asset Criticality", asset_criticality),
        ("Exploitation Observed", exploitation_observed(case)),
        ("Business Impact", "Elevated" if asset_criticality.lower() == "critical" else "Context dependent"),
        ("Remediation Status", "Closed and reviewer approved" if case.status == "CLOSED" else status_label(case.status)),
        ("Evidence Status", "Evidence preserved" if has_evidence else ""),
        ("Residual Risk", residual),
    ])


def risk_metric_assessment_rows(case, case_type, has_evidence, has_completed_tasks):
    initial = risk_score_100(case.severity)
    residual = residual_risk_score_100(case, case_type)
    reduction = max(0, initial - residual)
    percentage = round((reduction / initial) * 100) if initial else 0
    confidence = risk_confidence(case, has_evidence, has_completed_tasks)
    return [
        ["Initial Risk", f"{initial}/100 {risk_rating_for_score(initial)}"],
        ["Residual Risk", f"{residual}/100 {risk_rating_for_score(residual)}"],
        ["Risk Reduction", f"{percentage}%"],
        ["Confidence", confidence],
    ]


def risk_confidence(case, has_evidence, has_completed_tasks):
    score = 0
    if has_evidence:
        score += 1
    if has_completed_tasks:
        score += 1
    if meaningful(getattr(case, "root_cause", None)):
        score += 1
    if meaningful(getattr(case, "resolution_summary", None)) or meaningful(getattr(case, "validation_performed", None)):
        score += 1
    if case.closed_at and case.reviewed_by:
        score += 1
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def mitre_attack_rows(case):
    tactic_id, tactic_name = split_mitre_value(getattr(case, "mitre_tactic", None), "TA")
    technique_id, technique_name = split_mitre_value(getattr(case, "mitre_technique", None), "T")
    procedure = clean_value(getattr(case, "description", None))
    source = clean_value(getattr(case, "source", None))
    if not source and getattr(case, "alerts", None):
        source = clean_value(case.alerts[0].source)
    return [
        ["Tactic ID", tactic_id or "Not Available"],
        ["Tactic Name", tactic_name or clean_value(getattr(case, "mitre_tactic", None)) or "Not Available"],
        ["Technique ID", technique_id or "Not Available"],
        ["Technique Name", technique_name or clean_value(getattr(case, "mitre_technique", None)) or "Not Available"],
        ["Procedure", procedure or "Not Available"],
        ["Detection Source", source or "Not Available"],
    ]


def split_mitre_value(value, prefix):
    text = clean_value(value)
    if not text:
        return "", ""
    pattern = r"\b(TA\d{4}|T\d{4}(?:\.\d{3})?)\b"
    match = re.search(pattern, text, re.IGNORECASE)
    if match and match.group(1).upper().startswith(prefix):
        identifier = match.group(1).upper()
        name = clean_value(text.replace(match.group(1), ""))
        return identifier, name
    return "", text


def residual_risk_label(case, case_type, has_completed_tasks):
    score = residual_risk_score(case, case_type)
    if case.status == "CLOSED" and has_completed_tasks:
        return {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(score, "Medium")
    return clean_value(case.severity) or {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(score, "Medium")


def exploitation_observed(case):
    text = " ".join(filter(None, [case.description, case.closure_reason] + [note.body for note in case.notes])).lower()
    if any(term in text for term in ["exploitation observed", "confirmed compromise", "malicious activity confirmed"]):
        return "Yes"
    if any(term in text for term in ["no exploitation", "no evidence of exploitation", "not exploited"]):
        return "No"
    return "No evidence identified in available case data"


def risk_justification_for_case(case, disposition):
    if "false positive" in disposition.lower():
        return "Residual risk is low because the case was closed as a false positive after review. Detection tuning should be considered only if the benign pattern repeats."
    if case.status == "CLOSED":
        return "Residual risk is reduced because the case reached reviewer-approved closure. Continued monitoring and evidence retention remain recommended for auditability."
    return "Risk remains active until investigation activities, evidence review, and closure approval are completed."


def risk_narrative_for_case(case, disposition, initial_risk, residual_risk):
    asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected environment"
    exposure = "based on available case evidence"
    if case.source_ip:
        exposure = "with source network context recorded"
    if "false positive" in disposition.lower():
        return f"Initial risk was assessed as {initial_risk}, but reviewer validation determined the activity was false positive or benign. Residual risk is {residual_risk} for {asset_name}."
    return (
        f"Initial risk was assessed as {initial_risk} for {asset_name} {exposure}. "
        f"After investigation, remediation tracking, and reviewer-approved closure, residual risk is assessed as {residual_risk}. "
        "This assessment is based only on verified case data, completed workflow evidence, and reviewer disposition."
    )


def evidence_summary_for_case(evidence_rows):
    if not evidence_rows:
        return ""
    count = len(evidence_rows)
    return f"{count} evidence item{'s' if count != 1 else ''} were preserved with upload metadata and SHA256 hashes. These artifacts support reviewer validation and audit traceability."


def evidence_assessment_for_case(case, evidence_rows):
    if not evidence_rows:
        return "No separate evidence artifacts were attached. The assessment is therefore based on case fields, analyst notes, timeline events, and reviewer approval."
    count = len(evidence_rows)
    return (
        f"{count} evidence item{'s' if count != 1 else ''} were collected to support investigation validation and closure review. "
        "Evidence metadata and hashes are retained in the appendix for auditability while the main report summarizes what the evidence supports."
    )


def remediation_validation_for_case(case, case_type, has_completed_tasks, closure_reason):
    remediation_rows = technical_remediation_rows(case, extract_remediation_actions(case))
    row_text = "; ".join(
        f"{label}: {value}"
        for label, value in remediation_rows
        if label in {"Verification Result", "Patch Status", "Fixed Version", "Installed Patch / Update"}
        and meaningful(value)
        and value != "Not Available"
    )
    if row_text:
        return row_text
    if meaningful(getattr(case, "validation_performed", None)):
        return clean_multiline(case.validation_performed)
    if "false positive" in disposition_for_case(case).lower():
        return "No remediation was required because the case was approved as a false positive after review."
    if "vulnerability" in case_type.lower():
        base = "Remediation validation focused on confirming that the identified vulnerability condition was addressed through patching, configuration correction, or compensating control validation."
    elif "credential" in case_type.lower():
        base = "Remediation validation focused on account review, session/token handling, password control, and post-action monitoring where supported by the case record."
    elif "malware" in case_type.lower():
        base = "Remediation validation focused on containment, eradication, recovery, and endpoint health where supported by the case record."
    else:
        base = "Remediation validation focused on confirming the investigation outcome and ensuring closure approval was supported by completed case activity."
    if has_completed_tasks:
        base += " Completed investigation tasks support the validation decision."
    if meaningful(closure_reason):
        base += f" Reviewer closure rationale: {closure_reason}"
    return base


def technical_remediation_summary_for_case(case, remediation_rows, remediation_actions):
    if not remediation_rows and not remediation_actions and not meaningful(getattr(case, "resolution_summary", None)):
        return ""
    details = {label: value for label, value in remediation_rows}
    parts = []
    addressed = details.get("Vulnerability Addressed") or clean_value(case.title)
    if addressed:
        parts.append(f"The remediation work addressed {addressed}.")
    version_before = details.get("Affected Version")
    version_after = details.get("Fixed Version")
    if version_before and version_after:
        parts.append(f"The affected version was recorded as {version_before}, with fixed version {version_after}.")
    patch = details.get("Installed Patch / Update")
    if patch:
        parts.append(f"Documented remediation action: {patch}.")
    commands = details.get("Commands Executed")
    if commands:
        parts.append(f"Commands or technical actions recorded: {commands}.")
    validation = details.get("Verification Result") or details.get("Validation Performed") or clean_multiline(getattr(case, "validation_performed", None))
    if validation:
        parts.append(f"Validation performed: {validation}.")
    if not parts and meaningful(getattr(case, "resolution_summary", None)):
        parts.append(clean_multiline(case.resolution_summary))
    return " ".join(parts)


def lessons_learned_for_case(case, case_type):
    if meaningful(getattr(case, "lessons_learned", None)):
        return clean_multiline(case.lessons_learned)
    if "vulnerability" in case_type.lower():
        lessons = [
            "Improve patch cadence for assets with similar exposure.",
            "Use follow-up vulnerability scans to verify remediation on critical systems.",
            "Confirm asset-owner approval and maintenance-window evidence during remediation.",
        ]
    elif "credential" in case_type.lower():
        lessons = [
            "Review authentication monitoring coverage for affected users.",
            "Validate password reset, MFA, and token/session handling when credential risk is suspected.",
            "Monitor recurrence across related source locations and accounts.",
        ]
    elif "malware" in case_type.lower():
        lessons = [
            "Preserve file, process, and hash evidence early in the investigation.",
            "Validate endpoint containment and recovery before closure.",
            "Search related indicators across monitored assets.",
        ]
    else:
        lessons = [
            "Maintain clear evidence and note quality for reviewer approval.",
            "Keep linked asset context current to improve impact analysis.",
            "Use post-closure monitoring for high-severity cases.",
        ]
    if case.asset and (case.asset.criticality or "").lower() == "critical":
        lessons.append("Prioritize monitoring and remediation tracking for critical assets.")
    return "\n".join(lessons)


def final_conclusion_for_case(case, case_type, disposition):
    asset_name = clean_value(case.asset.hostname if case.asset else case.affected_host) or "the affected environment"
    if "false positive" in disposition.lower():
        return f"The case was reviewed and approved as a false positive. Based on available evidence, no remediation action was required for {asset_name}."
    if "vulnerability" in case_type.lower() and case.status == "CLOSED":
        return f"The identified vulnerability condition affecting {asset_name} was investigated, remediated or validated through the case workflow, and approved for closure. Current risk is considered mitigated based on available evidence."
    if case.status == "CLOSED":
        return f"The SOC investigation for {asset_name} was completed and approved for closure. Based on verified case data and reviewer decision, the final disposition is {disposition}."
    return f"The investigation remains in {status_label(case.status)} status. Final risk and disposition should be confirmed after reviewer approval."


def report_chart_rows(case, case_type, ioc_counts, completed_tasks, active_tasks, evidence_rows, timeline_rows=None, action_rows=None, remediation_rows=None, remediation_actions=None):
    charts = []
    risk_values = [
        ("Before Remediation", risk_score_100(case.severity)),
        ("After Remediation", residual_risk_score_100(case, case_type)),
    ]
    if risk_values[0][1] != risk_values[1][1]:
        charts.append({"title": "Risk Reduction", "rows": risk_values})
    severity_counts = Counter(clean_value(getattr(alert, "severity", None)) for alert in getattr(case, "alerts", []) if meaningful(getattr(alert, "severity", None)))
    if len(severity_counts) >= 2:
        charts.append({"title": "Severity Distribution", "rows": sorted(severity_counts.items())})
    progress_rows = remediation_progress_rows(case, remediation_rows or [], remediation_actions or [], bool(evidence_rows))
    if len(progress_rows) >= 3 and (remediation_rows or remediation_actions or meaningful(getattr(case, "resolution_summary", None))):
        charts.append({"title": "Remediation Progress", "rows": progress_rows})
    if completed_tasks or active_tasks:
        charts.append({"title": "Task Completion", "rows": [("Completed", completed_tasks), ("Pending", active_tasks)]})
    if len(ioc_counts) >= 2:
        charts.append({"title": "IOC Distribution", "rows": sorted(ioc_counts.items())})
    mitre_counts = mitre_distribution_counts(case)
    if len(mitre_counts) >= 2:
        charts.append({"title": "MITRE Technique Distribution", "rows": sorted(mitre_counts.items())})
    containment_counts = Counter(row[6] for row in (action_rows or []) if len(row) > 6 and meaningful(row[6]))
    if containment_counts:
        charts.append({"title": "Containment Status", "rows": sorted(containment_counts.items())})
    timeline_counts = timeline_phase_counts(timeline_rows or [])
    if len(timeline_counts) >= 2 and sum(timeline_counts.values()) >= 3:
        charts.append({"title": "Timeline Activity", "rows": sorted(timeline_counts.items())})
    evidence_counts = Counter(row[2] for row in evidence_rows if len(row) > 2 and meaningful(row[2]))
    if len(evidence_counts) >= 2:
        charts.append({"title": "Evidence Summary", "rows": sorted(evidence_counts.items())})
    return charts[:3]


def mitre_distribution_counts(case):
    counts = Counter()
    for alert in getattr(case, "alerts", []):
        value = clean_value(getattr(alert, "mitre_technique", None) or getattr(alert, "mitre_tactic", None))
        if value:
            counts[value[:44]] += 1
    value = clean_value(getattr(case, "mitre_technique", None) or getattr(case, "mitre_tactic", None))
    if value:
        counts[value[:44]] += 1
    return counts


def timeline_phase_counts(timeline_rows):
    counts = Counter()
    for row in timeline_rows:
        text = " ".join(str(cell or "") for cell in row).lower()
        if "created" in text:
            counts["Created"] += 1
        elif "evidence" in text or "collected" in text:
            counts["Evidence"] += 1
        elif "remediation" in text or "patch" in text or "contain" in text:
            counts["Remediation"] += 1
        elif "review" in text or "approval" in text:
            counts["Review"] += 1
        elif "closed" in text or "closure" in text:
            counts["Closure"] += 1
        else:
            counts["Investigation"] += 1
    return counts


def risk_score(severity):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(severity, 2)


def risk_score_100(severity):
    key = (clean_value(severity) or "Medium").title()
    return {"Critical": 92, "High": 74, "Medium": 46, "Low": 18}.get(key, 46)


def residual_risk_score_100(case, case_type):
    if "false positive" in disposition_for_case(case).lower():
        return 5
    if case.status == "CLOSED" and "vulnerability" in case_type.lower():
        patch_status = clean_value(getattr(case, "patch_status", "")).lower()
        fixed_version = clean_value(getattr(case, "fixed_version", ""))
        if "patch" in patch_status or "fixed" in patch_status or fixed_version:
            return 18
        return 30
    if case.status == "CLOSED":
        return 24
    return risk_score_100(case.severity)


def risk_rating_for_score(score):
    if score >= 75:
        return "Critical Risk"
    if score >= 50:
        return "High Risk"
    if score >= 25:
        return "Medium Risk"
    return "Low Risk"


def residual_risk_score(case, case_type):
    if case.status == "CLOSED" and "vulnerability" in case_type.lower():
        return 1
    if case.status == "CLOSED":
        return 2
    return risk_score(case.severity)


def evidence_type(filename):
    ext = (filename.rsplit(".", 1)[-1].lower() if "." in filename else "file")
    if ext in {"png", "jpg", "jpeg", "gif", "webp"}:
        return "Image"
    if ext in {"pdf"}:
        return "PDF"
    if ext in {"log", "txt", "csv", "json"}:
        return "Log/Data"
    if ext in {"doc", "docx"}:
        return "Document"
    return "File"


def remediation_progress_rows(case, remediation_rows, remediation_actions, has_evidence):
    text = " ".join([f"{label} {value}" for label, value in remediation_rows] + remediation_actions).lower()
    rows = [("Detected", 1)]
    if is_vulnerability_case(case) or meaningful(case.description) or meaningful(getattr(case, "root_cause", None)):
        rows.append(("Validated", len(rows) + 1))
    if any(token in text for token in ("patch", "update", "upgrade", "fixed", "remediat", "mitigat")) or meaningful(getattr(case, "resolution_summary", None)):
        rows.append(("Remediated", len(rows) + 1))
    if any(token in text for token in ("validat", "verified", "scan")) or has_evidence or case.status == "CLOSED":
        rows.append(("Verified", len(rows) + 1))
    if case.closed_at or case.status == "CLOSED":
        rows.append(("Closed", len(rows) + 1))
    return rows


def remediation_summary_for_case(case, case_type, has_containment, closure_reason):
    remediation_rows = technical_remediation_rows(case, extract_remediation_actions(case))
    technical_summary = technical_remediation_summary_for_case(case, remediation_rows, extract_remediation_actions(case))
    if technical_summary:
        return technical_summary
    if meaningful(getattr(case, "resolution_summary", None)):
        return clean_multiline(case.resolution_summary)
    if has_containment:
        return "Containment and response actions were recorded in the case and are summarized below with execution and approval context."
    if "vulnerability" in case_type.lower():
        return "No active containment actions were required based on the available case data. Remediation centered on patching, validation, owner coordination, and closure approval."
    if case.status == "CLOSED":
        return "No active containment actions were required based on the available case data. The case was closed through the standard review workflow."
    return "Response actions should be recorded if containment, eradication, recovery, or validation activities are performed."


def display_ioc_type(kind, value):
    guessed = extract_iocs(value)
    if guessed:
        return guessed[0].type
    return canonical_ioc_type(kind)


def disposition_for_case(case):
    closure = (case.closure_reason or "").lower()
    case_type = case_type_for_case(case)
    profile = case_profile(case_type)
    if "false positive" in closure or "false-positive" in closure:
        return "False Positive"
    if "benign" in closure:
        return "Benign Activity"
    if case.status == "CLOSED":
        if case_type == "Threat Hunt":
            return "Threat Identified and Contained" if any(case.iocs) else "No Threat Identified"
        return profile["closed_disposition"]
    if case.status == "SUBMITTED_FOR_REVIEW":
        return "Pending Closure Review"
    if case.status == "INVESTIGATING":
        return profile["active_disposition"]
    if case.status == "ASSIGNED":
        return "Assigned for Investigation"
    return (case.status or "New").replace("_", " ").title()


def clean_closure_reason(case, final_disposition):
    reason = clean_multiline(case.closure_reason)
    if reason:
        return reason
    if final_disposition == "False Positive":
        return "The case was approved as a false positive based on reviewer assessment and available evidence."
    if case.status == "CLOSED":
        return "Closure was approved by the reviewer based on completed investigation activities and available evidence."
    return ""


def recommendations_for_case(case, disposition, has_iocs, has_evidence):
    recommendations = []
    case_type = case_type_for_case(case).lower()
    if disposition == "False Positive":
        recommendations.append("Retain the original alert, analyst reason, and review approval for audit traceability.")
        recommendations.append("Tune detection logic only after confirming the same benign pattern appears repeatedly.")
    elif "vulnerability" in case_type:
        recommendations.append("Validate that the vulnerable system remains patched through a follow-up vulnerability scan or configuration assessment.")
        recommendations.append("Confirm the asset owner has documented remediation acceptance and any required maintenance window closure.")
        recommendations.append("Add the affected asset to recurring vulnerability management and patch compliance monitoring.")
        recommendations.append("Review similar assets for the same weakness to prevent recurrence across the environment.")
    elif "credential" in case_type:
        recommendations.append("Review authentication logs for abnormal login patterns, impossible travel, and repeated failures around the investigation window.")
        recommendations.append("Confirm password reset, MFA validation, and token/session revocation for affected accounts where applicable.")
        recommendations.append("Monitor the account and related source locations for recurrence after closure.")
    elif "malware" in case_type:
        recommendations.append("Validate malware removal through endpoint security tooling and post-remediation host health checks.")
        recommendations.append("Search for related hashes, filenames, processes, and network indicators across monitored assets.")
        recommendations.append("Confirm recovery state and continue endpoint monitoring for recurrence.")
    elif "threat hunt" in case_type:
        recommendations.append("Document hunt queries, matched data sources, and whether the hypothesis was confirmed or rejected.")
        recommendations.append("Convert validated detection logic into monitoring rules where useful.")
    elif case.status == "CLOSED":
        recommendations.append("Validate that containment, recovery, and monitoring actions are documented before archival.")
        recommendations.append("Confirm affected assets and users are covered by post-incident monitoring.")
    elif case.status == "SUBMITTED_FOR_REVIEW":
        recommendations.append("Reviewer should verify evidence, IOC correlation, task completion, and closure rationale before approval.")
    else:
        recommendations.append("Continue triage until scope, affected assets, IOCs, and required containment actions are confirmed.")
    if has_iocs:
        recommendations.append("Search related alerts and cases for the listed IOCs to confirm recurrence and lateral movement.")
    if not has_evidence:
        recommendations.append("Attach supporting logs, screenshots, exports, or forensic artifacts before final closure where applicable.")
    if case.severity in {"High", "Critical"}:
        recommendations.append("For high-impact incidents, obtain Lead/Admin approval and preserve evidence according to retention policy.")
    return "\n".join(recommendations)


def rows_to_text(rows):
    return "\n".join(" | ".join(str(cell) for cell in row) for row in rows)


def fill_docx_template(path, context):
    output = BytesIO()
    chart_images = context.get("chart_images", [])[:3]
    evidence_images = context.get("evidence_images", [])[:4]
    replacements = {}
    for key, value in context.items():
        rendered = docx_text(value)
        replacements[f"{{{{{key}}}}}"] = rendered
        replacements[f"[[{key}]]"] = rendered
    replacements_made = 0
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.startswith("word/") and item.filename.endswith(".xml"):
                text = data.decode("utf-8")
                for marker, rendered in replacements.items():
                    count = text.count(marker)
                    if count:
                        replacements_made += count
                        text = text.replace(marker, rendered)
                if item.filename == "word/document.xml" and replacements_made == 0:
                    text = append_report_body(text, context)
                if item.filename == "word/document.xml" and (chart_images or evidence_images):
                    text = ensure_document_namespaces(text)
                data = text.encode("utf-8")
            if item.filename == "[Content_Types].xml" and (chart_images or evidence_images):
                data = ensure_png_content_type(data.decode("utf-8")).encode("utf-8")
            if item.filename == "word/_rels/document.xml.rels" and (chart_images or evidence_images):
                rels = append_chart_relationships(data.decode("utf-8"), chart_images)
                rels = append_evidence_relationships(rels, evidence_images)
                data = rels.encode("utf-8")
            target.writestr(item, data)
        existing = {item.filename for item in source.infolist()}
        for index, chart in enumerate(chart_images, 1):
            media_name = f"word/media/astorasoc-chart-{index}.png"
            if media_name not in existing:
                target.writestr(media_name, chart["png"])
        for index, image in enumerate(evidence_images, 1):
            media_name = f"word/media/astorasoc-evidence-{index}.png"
            if media_name not in existing:
                target.writestr(media_name, image["png"])
    output.seek(0)
    return output


def build_default_docx(context):
    document_xml = default_document_xml(context)
    chart_images = context.get("chart_images", [])[:3]
    evidence_images = context.get("evidence_images", [])[:4]
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", content_types_xml(chart_images, evidence_images, include_footer=True))
        docx.writestr("_rels/.rels", ROOT_RELS)
        docx.writestr("word/_rels/document.xml.rels", document_rels_xml(chart_images, evidence_images, include_footer=True))
        docx.writestr("word/styles.xml", STYLES_XML)
        docx.writestr("word/footer1.xml", footer_part_xml(context))
        docx.writestr("word/document.xml", document_xml)
        for index, chart in enumerate(chart_images, 1):
            docx.writestr(f"word/media/astorasoc-chart-{index}.png", chart["png"])
        for index, image in enumerate(evidence_images, 1):
            docx.writestr(f"word/media/astorasoc-evidence-{index}.png", image["png"])
    output.seek(0)
    return output


def default_document_xml(context):
    xml = DOCUMENT_XML_TEMPLATE.format(body=default_report_body(context))
    return xml.replace("<w:sectPr>", '<w:sectPr><w:footerReference w:type="default" r:id="rIdAstoraFooter"/>')


def append_report_body(document_xml, context):
    body = default_report_body(context, include_title=False)
    marker = "<w:sectPr"
    idx = document_xml.rfind(marker)
    if idx != -1:
        return document_xml[:idx] + body + document_xml[idx:]
    return document_xml.replace("</w:body>", body + "</w:body>")


def default_report_body(context, include_title=True):
    blocks = [
        title("AstoraSOC") if include_title else section("AstoraSOC Case Report"),
        subtitle("SOC & Incident Response Platform"),
        title("Case Investigation Report"),
        subtitle(f'{context["case_id"]} | {context["case_title"]}'),
        table(
            ["Field", "Value"],
            meaningful_rows([
                ("Case ID", context["case_id"]),
                ("Case Title", context["case_title"]),
                ("Case Type", context["case_type"]),
                ("Severity", context["severity"]),
                ("Final Disposition", context["final_disposition"]),
                ("Generated", context["generated_at"]),
                ("Classification", context["classification"]),
                ("Version", context["report_version"]),
            ]),
            [2600, 6760],
        ),
        page_break(),
        section("Management Summary"),
        paragraph(context["summary"]),
        section("Executive Impact Summary"),
        paragraph(context["executive_impact_summary"]),
        section("Executive Risk Scorecard"),
        table(["Category", "Status"], context["scorecard_rows"], [4200, 5160]),
        section("Incident Classification"),
        table(["Category", "Assessment"], context["classification_rows"], [2600, 6760]),
        section("MITRE ATT&CK Mapping"),
        table(["Field", "Value"], context.get("mitre_rows", []), [2600, 6760]),
        section("Root Cause Analysis"),
        paragraph(context["root_cause_analysis"]),
    ]
    if context["asset_rows"]:
        blocks.extend([
            section("Asset Impact Assessment"),
            paragraph(context["business_impact"]),
            paragraph(context["asset_impact"]),
            table(["Field", "Value"], context["asset_rows"], [2600, 6760]),
        ])
    else:
        blocks.extend([
            section("Asset Impact Assessment"),
            paragraph(context["business_impact"]),
            paragraph(context["asset_impact"]),
        ])
    blocks.extend([
        section("Investigation Narrative"),
        paragraph(context["investigation_narrative"]),
        section("Technical Findings"),
        table(["Finding ID", "Title", "Description", "Severity", "Status"], context["technical_findings_rows"], [1050, 1800, 3460, 1250, 1800]),
        section("Evidence Assessment"),
        paragraph(context["evidence_assessment"]),
        section("Risk Assessment"),
        paragraph(context["risk_justification"]),
        table(["Metric", "Value"], context.get("risk_metric_rows", []), [2600, 6760]),
        table(["Risk Factor", "Assessment"], context["risk_rows"], [2600, 6760]),
    ])
    if context.get("vulnerability_rows"):
        blocks.extend([
            section("Vulnerability Remediation Details"),
            table(["Field", "Detail"], context["vulnerability_rows"], [2600, 6760]),
        ])
    if context.get("technical_remediation_summary") or context.get("technical_remediation_rows"):
        blocks.extend([
            section("Technical Remediation Summary"),
            paragraph(context.get("technical_remediation_summary", "")),
            table(["Field", "Detail"], context.get("technical_remediation_rows", []), [2600, 6760]) if context.get("technical_remediation_rows") else "",
        ])
    if context.get("evidence_images"):
        blocks.append(section("Evidence Preview"))
        for index, image in enumerate(context["evidence_images"][:4], 1):
            blocks.append(docx_image(f"rIdAstoraEvidence{index}", f'{image["title"]} preview', 100 + index))
            blocks.append(paragraph(f'Figure E{index}: {image["caption"]}', "AstoraSOCFooter"))
    if context.get("chart_images"):
        blocks.append(section("Report Visual Summary"))
        for index, chart in enumerate(context["chart_images"][:3], 1):
            blocks.append(docx_image(f"rIdAstoraChart{index}", f'{chart["title"]} chart', index))
            blocks.append(paragraph(f'Figure {index}: {chart["caption"]}', "AstoraSOCFooter"))
    blocks.extend([
        section("Remediation Validation"),
        paragraph(context["remediation_validation"]),
    ])
    if context["containment_rows"]:
        blocks.append(section("Containment and Response Actions"))
        blocks.append(paragraph(context["remediation_summary"]))
        blocks.append(table(["ID", "Action", "Target", "Risk", "Status", "Result"], [[row[0], row[2], row[3], row[5], row[6], row[12]] for row in context["containment_rows"]], [900, 1200, 1700, 850, 1000, 3710]))
    blocks.extend([
        section("Timeline Highlights"),
        table(["Date/Time", "Actor", "Milestone", "Summary"], context["timeline_rows"], [1500, 1500, 1700, 4660]),
        section("Task Completion Summary"),
        table(["Metric", "Count"], context["task_summary_rows"], [2600, 6760]),
    ])
    blocks.extend([
        section("Reviewer Approval and Closure"),
        table(["Field", "Value"], context["review_rows"], [2600, 6760]),
        section("Lessons Learned"),
        paragraph(context["lessons_learned"]),
        section("Recommendations"),
        paragraph(context["recommendations"]),
        section("Final Conclusion"),
        paragraph(context["final_conclusion"]),
    ])
    appendix_blocks = []
    if context["ioc_rows"]:
        appendix_blocks.extend([
            section("Appendix: IOC Intelligence"),
            table(["IOC Type", "Count"], context["ioc_count_rows"], [2600, 6760]) if len(context["ioc_count_rows"]) > 1 else "",
            table(["Type", "Indicator", "Confidence", "First Seen", "Last Seen", "Source"], context["ioc_rows"], [1000, 2700, 1100, 1500, 1500, 1560]),
        ])
    if context["evidence_rows"]:
        appendix_blocks.extend([
            section("Appendix: Evidence Register"),
            paragraph(context["evidence_summary"]),
            table(["Preview", "Filename", "Type", "Size", "Uploaded By", "Upload Time", "SHA256", "Purpose"], context["evidence_rows"], [1000, 1450, 800, 800, 1200, 1150, 2000, 960]),
        ])
    important_tasks = [row for row in context["task_rows"] if row[3] == "Completed"][:8]
    if important_tasks:
        appendix_blocks.extend([
            section("Appendix: Completed Tasks"),
            table(["Task", "Source", "Playbook", "Status", "Completed By", "Completed At"], important_tasks, [3100, 900, 1600, 1000, 1500, 1560]),
        ])
    if context["note_rows"]:
        appendix_blocks.extend([
            section("Appendix: Investigation Journal"),
            table(["Date", "Author", "Note"], context["note_rows"], [1600, 1600, 6160]),
        ])
    if context["appendix_timeline_rows"] and len(context["appendix_timeline_rows"]) > len(context["timeline_rows"]):
        appendix_blocks.extend([
            section("Appendix: Detailed Timeline"),
            table(["Date", "Actor", "Action", "Details"], context["appendix_timeline_rows"][:30], [1600, 1500, 1600, 4660]),
        ])
    blocks.extend(appendix_blocks)
    blocks.append(footer(
        f'AstoraSOC v{context["report_version"]} | {context["case_id"]} | {context["classification"]} | '
        f'Generated {context["generated_at"]} | Generated by AstoraSOC for {context["generated_by"]}'
    ))
    return "".join(blocks)


def docx_text(value):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    return escape(text).replace("\n", '</w:t><w:br/><w:t xml:space="preserve">')


def paragraph(text, style="BodyText"):
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr><w:r><w:t xml:space="preserve">{docx_text(text)}</w:t></w:r></w:p>'


def multiline(text):
    return paragraph(text)


def title(text):
    return paragraph(text, "AstoraSOCTitle")


def subtitle(text):
    return paragraph(text, "AstoraSOCSubtitle")


def section(text):
    return paragraph(text, "Heading1")


def footer(text):
    return paragraph(text, "AstoraSOCFooter")


def page_break():
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def docx_image(rid, name, doc_id):
    width_emu = 5760000
    height_emu = 2000000
    return f"""
<w:p>
  <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
  <w:r>
    <w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0">
        <wp:extent cx="{width_emu}" cy="{height_emu}"/>
        <wp:effectExtent l="0" t="0" r="0" b="0"/>
        <wp:docPr id="{doc_id}" name="{docx_text(name)}"/>
        <wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>
        <a:graphic>
          <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:pic>
              <pic:nvPicPr><pic:cNvPr id="{doc_id}" name="{docx_text(name)}"/><pic:cNvPicPr/></pic:nvPicPr>
              <pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
              <pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{width_emu}" cy="{height_emu}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
            </pic:pic>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing>
  </w:r>
</w:p>"""


def table(headers, rows, widths, empty_text="No records."):
    rows = rows or [[empty_text] + [""] * (len(headers) - 1)]
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    header_cells = "".join(cell(header, width, "TableHeader", fill="D7EEEE") for header, width in zip(headers, widths))
    body_rows = []
    for row in rows:
        values = list(row)[: len(headers)] + [""] * max(0, len(headers) - len(row))
        body_rows.append("<w:tr>" + "".join(cell(value, width, "TableValue") for value, width in zip(values, widths)) + "</w:tr>")
    return (
        '<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/>'
        '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:left w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:bottom w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:right w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:insideH w:val="single" w:sz="4" w:color="DCEBE8"/>'
        '<w:insideV w:val="single" w:sz="4" w:color="DCEBE8"/></w:tblBorders></w:tblPr>'
        f'<w:tblGrid>{grid}</w:tblGrid><w:tr>{header_cells}</w:tr>'
        + "".join(body_rows)
        + "</w:tbl>"
        + paragraph("", "BodyText")
    )


def cell(value, width, style, fill=None):
    shade = f'<w:shd w:fill="{fill}"/>' if fill else ""
    return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{shade}<w:tcMar><w:top w:w="80" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar></w:tcPr>{paragraph(value, style)}</w:tc>'


def kv_table(rows):
    body = []
    for label, value in rows:
        body.append(
            "<w:tr>"
            '<w:tc><w:tcPr><w:tcW w:w="2600" w:type="dxa"/><w:shd w:fill="E8F3F1"/></w:tcPr>'
            f'{paragraph(label, "TableLabel")}</w:tc>'
            '<w:tc><w:tcPr><w:tcW w:w="6760" w:type="dxa"/></w:tcPr>'
            f'{paragraph(value, "TableValue")}</w:tc>'
            "</w:tr>"
        )
    return (
        '<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/>'
        '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:left w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:bottom w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:right w:val="single" w:sz="4" w:color="B7D7D2"/>'
        '<w:insideH w:val="single" w:sz="4" w:color="DCEBE8"/>'
        '<w:insideV w:val="single" w:sz="4" w:color="DCEBE8"/></w:tblBorders></w:tblPr>'
        '<w:tblGrid><w:gridCol w:w="2600"/><w:gridCol w:w="6760"/></w:tblGrid>'
        + "".join(body)
        + "</w:tbl>"
        + paragraph("", "BodyText")
    )


def content_types_xml(chart_images, evidence_images=None, include_footer=False):
    xml = CONTENT_TYPES
    if chart_images or evidence_images:
        xml = ensure_png_content_type(xml)
    if include_footer and "/word/footer1.xml" not in xml:
        xml = xml.replace(
            "</Types>",
            '  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>\n</Types>',
        )
    return xml


def document_rels_xml(chart_images, evidence_images=None, include_footer=False):
    xml = append_chart_relationships(DOCUMENT_RELS, chart_images)
    xml = append_evidence_relationships(xml, evidence_images or [])
    if include_footer and 'Id="rIdAstoraFooter"' not in xml:
        addition = (
            '  <Relationship Id="rIdAstoraFooter" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" '
            'Target="footer1.xml"/>'
        )
        if xml.rstrip().endswith("/>"):
            return (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                + addition
                + "\n</Relationships>"
            )
        xml = xml.replace("</Relationships>", addition + "\n</Relationships>")
    return xml


def footer_part_xml(context):
    text = (
        f'AstoraSOC v{context["report_version"]} | {context["case_id"]} | {context["classification"]} | '
        f'Generated {context["generated_at"]} | Generated by AstoraSOC | Page '
    )
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p>
    <w:pPr><w:pStyle w:val="AstoraSOCFooter"/><w:jc w:val="center"/></w:pPr>
    <w:r><w:t xml:space="preserve">{docx_text(text)}</w:t></w:r>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
    <w:r><w:t xml:space="preserve"> of </w:t></w:r>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
  </w:p>
</w:ftr>"""


def ensure_png_content_type(xml):
    if 'Extension="png"' in xml:
        return xml
    return xml.replace(
        "</Types>",
        '  <Default Extension="png" ContentType="image/png"/>\n</Types>',
    )


def append_chart_relationships(xml, chart_images):
    additions = []
    for index, _chart in enumerate(chart_images[:3], 1):
        rid = f"rIdAstoraChart{index}"
        if f'Id="{rid}"' not in xml:
            additions.append(
                f'  <Relationship Id="{rid}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                f'Target="media/astorasoc-chart-{index}.png"/>'
            )
    if not additions:
        return xml
    if xml.rstrip().endswith("/>"):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            + "\n".join(additions)
            + "\n</Relationships>"
        )
    return xml.replace("</Relationships>", "\n".join(additions) + "\n</Relationships>")


def append_evidence_relationships(xml, evidence_images):
    additions = []
    for index, _image in enumerate((evidence_images or [])[:4], 1):
        rid = f"rIdAstoraEvidence{index}"
        if f'Id="{rid}"' not in xml:
            additions.append(
                f'  <Relationship Id="{rid}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                f'Target="media/astorasoc-evidence-{index}.png"/>'
            )
    if not additions:
        return xml
    if xml.rstrip().endswith("/>"):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            + "\n".join(additions)
            + "\n</Relationships>"
        )
    return xml.replace("</Relationships>", "\n".join(additions) + "\n</Relationships>")


def ensure_document_namespaces(xml):
    namespaces = {
        "xmlns:r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "xmlns:wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
        "xmlns:a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "xmlns:pic": "http://schemas.openxmlformats.org/drawingml/2006/picture",
    }
    start = xml.find("<w:document")
    end = xml.find(">", start)
    if start == -1 or end == -1:
        return xml
    tag = xml[start:end]
    additions = [f' {name}="{url}"' for name, url in namespaces.items() if name not in tag]
    if not additions:
        return xml
    return xml[:end] + "".join(additions) + xml[end:]


CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

DOCUMENT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"""

DOCUMENT_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:body>{body}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body>
</w:document>"""

STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="22"/><w:color w:val="172B2F"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="AstoraSOCTitle"><w:name w:val="AstoraSOC Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="34"/><w:color w:val="063B39"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="AstoraSOCSubtitle"><w:name w:val="AstoraSOC Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="360"/></w:pPr><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="138C7B"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="260" w:after="120"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="063B39"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="BodyText"><w:name w:val="Body Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="21"/><w:color w:val="172B2F"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="TableLabel"><w:name w:val="Table Label"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="40"/></w:pPr><w:rPr><w:b/><w:sz w:val="19"/><w:color w:val="315E60"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="TableHeader"><w:name w:val="Table Header"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="40"/></w:pPr><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="063B39"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="TableValue"><w:name w:val="Table Value"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="40"/></w:pPr><w:rPr><w:sz w:val="19"/><w:color w:val="172B2F"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="AstoraSOCFooter"><w:name w:val="AstoraSOC Footer"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="300"/></w:pPr><w:rPr><w:i/><w:sz w:val="18"/><w:color w:val="6B7D82"/></w:rPr></w:style>
</w:styles>"""
