import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime

from flask import current_app

from app.ai_catalog import default_endpoint, model_label, provider_label, provider_requires_endpoint, provider_requires_key, valid_model
from app.docx_reports import build_default_docx, case_profile, case_report_context, case_type_for_case, default_report_body, default_document_xml, relevant_case_tasks
from app.ioc_intel import ioc_type_label, sanitize_ioc_value
from app.models import utcnow
from app.utils import decrypt_text, format_short_datetime, setting, tracking_label
from app.workflow import CASE_CLOSED, status_label


AI_SECTION_KEYS = [
    "executive_summary",
    "root_cause_analysis",
    "incident_overview",
    "asset_summary",
    "investigation_narrative",
    "investigation_findings",
    "technical_findings",
    "risk_assessment",
    "ioc_analysis_summary",
    "evidence_assessment",
    "evidence_summary",
    "remediation_validation",
    "containment_and_response_actions",
    "timeline_highlights",
    "lessons_learned",
    "reviewer_approval",
    "final_disposition",
    "final_conclusion",
    "recommendations",
    "report_metadata",
]

RAW_BODY_LABELS = {
    "summary",
    "description",
    "actions_taken",
    "action_taken",
    "vulnerability_details",
    "collected_evidence",
    "evidence_collected",
    "risk_assessment",
    "business_impact",
    "recommendations",
    "final_disposition",
}

SECTION_TITLES = {
    "executive_summary": "Executive Summary",
    "root_cause_analysis": "Root Cause Analysis",
    "incident_overview": "Incident Overview",
    "asset_summary": "Asset Summary",
    "investigation_narrative": "Investigation Narrative",
    "investigation_findings": "Investigation Findings",
    "technical_findings": "Technical Findings",
    "risk_assessment": "Risk Assessment",
    "ioc_analysis_summary": "IOC Intelligence Summary",
    "evidence_assessment": "Evidence Assessment",
    "evidence_summary": "Evidence Summary",
    "remediation_validation": "Remediation Validation",
    "containment_and_response_actions": "Containment and Response Actions",
    "timeline_highlights": "Timeline Highlights",
    "lessons_learned": "Lessons Learned",
    "reviewer_approval": "Reviewer Approval",
    "final_disposition": "Final Disposition",
    "final_conclusion": "Final Conclusion",
    "recommendations": "Recommendations",
    "report_metadata": "Report Metadata",
}


class AIReportError(RuntimeError):
    pass


def ai_reports_enabled():
    return setting("ai_reports_enabled", "false") == "true"


def case_allows_report(case):
    return case.status == CASE_CLOSED and bool(case.closed_at) and bool(case.reviewed_by_id)


def case_allows_ai_report(case):
    return case_allows_report(case)


def ai_config():
    provider = setting("ai_provider", "openai") or "openai"
    model = setting("ai_model", "") or ""
    encrypted_key = setting("ai_api_key", "")
    api_key = decrypt_text(encrypted_key) if encrypted_key else ""
    endpoint = (setting("ai_endpoint", "") or "").strip() or default_endpoint(provider)
    if not valid_model(provider, model):
        raise AIReportError("AI model is not valid for the selected provider.")
    if provider_requires_endpoint(provider) and not endpoint:
        raise AIReportError("AI endpoint is required for the selected provider.")
    if provider_requires_key(provider) and not api_key:
        raise AIReportError("AI API key is not configured.")
    return {"provider": provider, "model": model, "api_key": api_key, "endpoint": endpoint}


def ai_config_summary():
    provider = setting("ai_provider", "openai") or "openai"
    model = setting("ai_model", "") or ""
    return {
        "provider": provider,
        "provider_label": provider_label(provider),
        "model": model,
        "model_label": model_label(provider, model),
    }


def meaningful(value):
    text = str(value or "").strip()
    return bool(text and text.lower() not in {"-", "n/a", "na", "none", "null", "not available", "unknown", "unassigned"})


def compact_dict(values):
    return {key: value for key, value in values.items() if meaningful(value)}


def collect_case_intelligence(case, generated_by):
    assigned = [user.full_name for user in case.assigned_users]
    if not assigned and case.assignee:
        assigned = [case.assignee.full_name]
    asset = case.asset
    iocs = []
    for ioc in case.iocs:
        ioc_type = ioc.type
        value = sanitize_ioc_value(ioc_type, ioc.value)
        if not value:
            continue
        iocs.append(compact_dict({
            "type": ioc_type_label(ioc_type),
            "value": value,
            "confidence": ioc.confidence,
            "first_seen": format_short_datetime(ioc.first_seen_at or ioc.added_at),
            "last_seen": format_short_datetime(ioc.last_seen_at or ioc.added_at),
            "source_system": ioc.source_system or ioc.source,
            "analyst_notes": ioc.analyst_notes,
        }))
    case_type = case_type_for_case(case)
    profile = case_profile(case_type)
    relevant_tasks = relevant_case_tasks(case.tasks, case_type)
    completed_tasks = [
        compact_dict({
            "task": task.title,
            "source": task.source,
            "playbook": task.playbook_name,
            "completed_by": task.completed_by.full_name if task.completed_by else None,
            "completed_at": format_short_datetime(task.completed_at) if task.completed_at else None,
        })
        for task in case.tasks
        if task in relevant_tasks and task.is_complete
    ]
    notes = [
        compact_dict({
            "author": note.created_by.full_name if note.created_by else "System",
            "timestamp": format_short_datetime(note.created_at),
            "body": note.body,
        })
        for note in case.notes[:25]
        if meaningful(note.body)
    ]
    timeline = [
        compact_dict({
            "timestamp": format_short_datetime(event.created_at),
            "actor": event.actor.full_name if event.actor else "System",
            "action": event.event_type,
            "details": event.description,
        })
        for event in reversed(case.timeline)
        if event.event_type and "report" not in f"{event.event_type} {event.description}".lower()
    ]
    evidence = [
        compact_dict({
            "filename": item.original_filename,
            "evidence_type": evidence_type_for_ai(item.original_filename),
            "uploaded_by": item.uploaded_by.full_name if item.uploaded_by else "System",
            "uploaded_at": format_short_datetime(item.uploaded_at),
            "sha256": item.sha256,
        })
        for item in case.evidence
    ]
    containment = [
        compact_dict({
            "action": action.action_type.replace("_", " ").title() if action.action_type else None,
            "target": action.target,
            "target_host": action.target_host,
            "risk": action.risk_level,
            "status": (action.status or "").replace("_", " ").title(),
            "result": action.execution_result or action.output or action.notes,
            "requested_by": action.requested_by.full_name if action.requested_by else None,
            "approved_by": action.approved_by.full_name if action.approved_by else None,
            "executed_by": action.executed_by.full_name if action.executed_by else None,
        })
        for action in case.containment_actions
    ]
    return {
        "case_type": case_type,
        "case_focus": profile["focus"],
        "allowed_workflow_language": {
            "Vulnerability Remediation": ["vulnerability validation", "risk analysis", "patch planning", "patch deployment", "remediation verification", "post-patch monitoring", "closure review"],
            "Credential Access": ["authentication review", "session analysis", "account investigation", "password reset", "token review", "containment"],
            "Malware": ["malware validation", "host isolation", "IOC collection", "malware removal", "recovery validation"],
            "Threat Hunt": ["hypothesis validation", "related activity review", "threat confirmation"],
            "Incident Response": ["scope validation", "evidence review", "IOC review", "containment", "recovery", "monitoring"],
        }.get(case_type, []),
        "case": compact_dict({
            "tracking_id": tracking_label(case),
            "title": case.title,
            "description": case.description,
            "incident_type": getattr(case, "incident_type", None) or getattr(case, "case_type", None),
            "business_impact": getattr(case, "business_impact", None),
            "root_cause": getattr(case, "root_cause", None),
            "resolution_summary": getattr(case, "resolution_summary", None),
            "lessons_learned": getattr(case, "lessons_learned", None),
            "validation_performed": getattr(case, "validation_performed", None),
            "closure_notes": getattr(case, "closure_notes", None),
            "cve_id": getattr(case, "cve_id", None),
            "cvss_score": getattr(case, "cvss_score", None),
            "affected_software": getattr(case, "affected_software", None),
            "affected_version": getattr(case, "affected_version", None),
            "fixed_version": getattr(case, "fixed_version", None),
            "patch_status": getattr(case, "patch_status", None),
            "remediation_owner": getattr(case, "remediation_owner", None),
            "severity": case.severity,
            "status": status_label(case.status),
            "source": case.source,
            "rule_id": case.rule_id,
            "mitre_tactic": case.mitre_tactic,
            "mitre_technique": case.mitre_technique,
            "host": case.affected_host,
            "username": case.affected_user,
            "source_ip": case.source_ip,
            "destination_ip": case.destination_ip,
            "created_at": format_short_datetime(case.created_at),
            "closed_at": format_short_datetime(case.closed_at),
            "closure_reason": case.closure_reason,
            "assigned_analysts": ", ".join(assigned),
        }),
        "asset": compact_dict({
            "hostname": asset.hostname if asset else None,
            "ip_address": asset.ip_address if asset else None,
            "criticality": asset.criticality if asset else None,
            "type": asset.asset_type if asset else None,
            "department": asset.department if asset else None,
            "owner": asset.owner if asset else None,
            "os": asset.operating_system if asset else None,
        }),
        "review": compact_dict({
            "reviewed_by": case.reviewed_by.full_name if case.reviewed_by else None,
            "closed_by": case.closed_by.full_name if case.closed_by else None,
            "approval_date": format_short_datetime(case.closed_at),
            "approved_report": True,
        }),
        "iocs": iocs,
        "ioc_counts": dict(Counter(item.get("type", "Unclassified") for item in iocs)),
        "evidence": evidence,
        "completed_tasks": completed_tasks,
        "analyst_notes": notes,
        "timeline": timeline,
        "containment_actions": containment,
        "generated_by": generated_by.full_name if generated_by else "AstoraSOC",
        "generated_at": format_short_datetime(utcnow()),
        "report_version": "1.0",
    }


def ai_prompt(case_data):
    return (
        "Generate an executive-grade SOC/DFIR incident report as strict JSON. "
        "Do not include markdown fences. Return exactly these keys: "
        + ", ".join(AI_SECTION_KEYS)
        + ". Write a senior SOC analyst narrative, not a database export. Use concise professional paragraphs inside strings. "
        "Do not dump raw database fields. Hide empty or irrelevant fields. Never write repetitive 'Not Available'. "
        "Never invent facts; only summarize facts present in the structured case data. "
        "Omit missing optional values instead of writing placeholders. "
        "Strictly tailor findings, recommendations, tasks, conclusions, and closure wording to case_type and allowed_workflow_language. "
        "Do not mention credential access, malware, containment, threat hunting, or compliance workflows unless the case facts support that case type. "
        "The executive_summary is the Management Summary. It must answer what happened, affected system, risk, actions taken, exploitation status, remediation result, and current risk in 2-3 concise paragraphs. "
        "root_cause_analysis must explain why the case occurred, what weakness was identified, what system was affected, and what conditions enabled the issue. "
        "investigation_narrative must tell the chronology of validation, investigation, evidence collection, findings, remediation, verification, and closure in polished paragraphs. "
        "technical_findings must contain only verified findings; do not create fictional vulnerabilities or indicators. "
        "evidence_assessment must explain what the evidence supports instead of listing files. "
        "remediation_validation must explain exactly what was remediated and how validation was supported by case data. "
        "For vulnerability or remediation cases, include concrete technical remediation facts when present: CVE identifier, vulnerability name, affected product, affected version, fixed version, severity, CVSS score, exact patch or update applied, commands executed, service disabled, reboot performed, validation scan, or verification evidence. "
        "Do not write generic remediation text such as 'necessary remediation actions were performed'; if no exact remediation action exists, say only what the verified case data supports and omit unsupported details. "
        "Evidence sections must include the purpose of evidence where inferable from filename, notes, or context, and must not be only a filename list. "
        "lessons_learned and recommendations must be specific, actionable, and case-specific. "
        "final_conclusion must be a professional closing paragraph suitable for audit and executive review. "
        "Summarize significant timeline events only: Case Created, Investigation Started, Evidence Collected, Findings Confirmed, Remediation Performed, Review Requested, Lead Approval, Closure. "
        "Exclude repeated evidence uploads, report generation events, note-added noise, and internal workflow noise. "
        "For vulnerability cases, discuss validation, patch planning/deployment, remediation verification, residual risk, and post-patch monitoring. "
        "Convert short analyst notes into professional language, for example 'patched kernel' means kernel-level remediation was completed. "
        "Audience: SOC Leads, Security Managers, CISOs, Auditors, and stakeholders.\n\n"
        + json.dumps(case_data, ensure_ascii=False, default=str)
    )


def evidence_type_for_ai(filename):
    name = str(filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in {"png", "jpg", "jpeg", "gif", "webp"}:
        return "Screenshot/Image"
    if ext == "pdf":
        return "PDF"
    if ext in {"log", "txt", "csv", "json"}:
        return "Log/Data Export"
    if ext in {"doc", "docx"}:
        return "Document"
    return "Evidence Artifact"


def call_ai(case_data):
    config = ai_config()
    content = ai_text_completion(config, ai_prompt(case_data), timeout=60)
    return parse_ai_sections(content)


def ai_text_completion(config, prompt, timeout=60):
    provider = config["provider"]
    if provider in {
        "openai",
        "openrouter",
        "deepseek",
        "deepseek_openrouter_free",
        "azure_openai",
        "custom",
        "groq",
        "huggingface",
        "together",
        "cerebras",
        "fireworks",
        "deepinfra",
    }:
        return openai_compatible_completion(config, prompt, timeout)
    if provider == "gemini":
        return gemini_completion(config, prompt, timeout)
    if provider == "anthropic":
        return anthropic_completion(config, prompt, timeout)
    if provider == "ollama":
        return ollama_completion(config, prompt, timeout)
    raise AIReportError("Unsupported AI provider.")


def openai_compatible_completion(config, prompt, timeout):
    payload = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": "You are a senior SOC incident report writer. Produce accurate, sober, audit-ready reports."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if config["provider"] == "azure_openai":
        headers["api-key"] = config["api_key"]
    request = urllib.request.Request(
        config["endpoint"],
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AIReportError(provider_error_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise AIReportError(f"AI provider request failed: {exc}") from exc
    try:
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise AIReportError("AI provider returned an unsupported response.") from exc
    return content


def gemini_completion(config, prompt, timeout):
    base = config["endpoint"].rstrip("/")
    model = urllib.parse.quote(config["model"], safe="")
    separator = "&" if "?" in base else "?"
    url = f"{base}/models/{model}:generateContent{separator}key={urllib.parse.quote(config['api_key'])}"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "response_mime_type": "application/json"},
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AIReportError(provider_error_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise AIReportError(f"AI provider request failed: {exc}") from exc
    try:
        data = json.loads(raw)
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise AIReportError("AI provider returned an unsupported response.") from exc


def anthropic_completion(config, prompt, timeout):
    payload = {
        "model": config["model"],
        "max_tokens": 2200,
        "temperature": 0.2,
        "system": "You are a senior SOC incident report writer. Produce accurate, sober, audit-ready reports.",
        "messages": [{"role": "user", "content": prompt}],
    }
    request = urllib.request.Request(
        config["endpoint"],
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": config["api_key"],
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AIReportError(provider_error_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise AIReportError(f"AI provider request failed: {exc}") from exc
    try:
        data = json.loads(raw)
        return "\n".join(part.get("text", "") for part in data.get("content", []) if part.get("type") == "text").strip()
    except (TypeError, json.JSONDecodeError) as exc:
        raise AIReportError("AI provider returned an unsupported response.") from exc


def ollama_completion(config, prompt, timeout):
    endpoint = config["endpoint"].rstrip("/")
    url = endpoint if endpoint.endswith("/api/chat") else f"{endpoint}/api/chat"
    payload = {
        "model": config["model"],
        "stream": False,
        "messages": [
            {"role": "system", "content": "You are a senior SOC incident report writer. Produce accurate, sober, audit-ready reports."},
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AIReportError(provider_error_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise AIReportError(f"AI provider request failed: {exc}") from exc
    try:
        data = json.loads(raw)
        return data["message"]["content"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AIReportError("AI provider returned an unsupported response.") from exc


def provider_error_message(exc):
    try:
        body = exc.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        message = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else data.get("error")
        if message:
            return str(message)
    except Exception:
        pass
    if exc.code in {401, 403}:
        return "Authentication failed. Invalid API key or insufficient permissions."
    if exc.code == 404:
        return "Endpoint or model was not found."
    return f"AI provider returned HTTP {exc.code}."


def test_ai_connection(provider, model, api_key, endpoint):
    provider = provider or "openai"
    endpoint = (endpoint or "").strip() or default_endpoint(provider)
    model = model or ""
    if not valid_model(provider, model):
        raise AIReportError("Selected model is not available for this provider.")
    if provider_requires_endpoint(provider) and not endpoint:
        raise AIReportError("Custom endpoint is required for this provider.")
    if provider_requires_key(provider) and not api_key:
        raise AIReportError("API key is required for this provider.")
    config = {"provider": provider, "model": model, "api_key": api_key or "", "endpoint": endpoint}
    started = time.perf_counter()
    ai_text_completion(config, "Reply with exactly: connected", timeout=20)
    latency = int((time.perf_counter() - started) * 1000)
    return {
        "ok": True,
        "message": "Connected",
        "provider": provider_label(provider),
        "model": model_label(provider, model),
        "latency_ms": latency,
    }


def parse_ai_sections(content):
    text = extract_json_text(content)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIReportError("AI response was not valid JSON.") from exc
    sections = {}
    for key in AI_SECTION_KEYS:
        value = parsed.get(key, "")
        if isinstance(value, list):
            value = "\n".join(f"- {polish_ai_text(item)}" for item in value if meaningful(item))
        elif isinstance(value, dict):
            value = "\n".join(format_ai_dict_item(name, item) for name, item in value.items() if meaningful(item))
        cleaned = polish_ai_text(value)
        sections[key] = cleaned if meaningful(cleaned) else ""
    return sections


def format_ai_dict_item(name, item):
    label = str(name or "").strip().lower()
    text = polish_ai_text(item)
    if label in RAW_BODY_LABELS:
        return text
    return f"{humanize_ai_label(label)}. {text}"


def humanize_ai_label(label):
    return " ".join(part.capitalize() for part in str(label or "").replace("-", "_").split("_") if part)


def polish_ai_text(value):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""
    labels = "|".join(re.escape(label) for label in sorted(RAW_BODY_LABELS, key=len, reverse=True))
    text = re.sub(rf"(?im)^\s*[-*]?\s*(?:{labels})\s*:\s*", "", text)
    text = re.sub(r"(?m)^\s*[-*]\s*$", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_json_text(content):
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
        text = re.sub(r"```$", "", text).strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def enhanced_context(case, generated_by, sections):
    context = case_report_context(case, generated_by)
    context.update({
        "summary": sections.get("executive_summary") or context["summary"],
        "root_cause_analysis": sections.get("root_cause_analysis") or context["root_cause_analysis"],
        "business_impact": sections.get("asset_summary") or sections.get("business_impact") or context["business_impact"],
        "investigation_narrative": sections.get("investigation_narrative") or context["investigation_narrative"],
        "investigation_findings": sections.get("investigation_findings") or context["investigation_findings"],
        "risk_justification": sections.get("risk_assessment") or context["risk_justification"],
        "evidence_assessment": sections.get("evidence_assessment") or context["evidence_assessment"],
        "evidence_summary": sections.get("evidence_summary") or context["evidence_summary"],
        "remediation_validation": sections.get("remediation_validation") or context["remediation_validation"],
        "remediation_summary": sections.get("containment_and_response_actions") or sections.get("remediation_summary") or context["remediation_summary"],
        "lessons_learned": sections.get("lessons_learned") or context["lessons_learned"],
        "recommendations": sections.get("recommendations") or context["recommendations"],
        "final_conclusion": sections.get("final_conclusion") or sections.get("final_disposition") or context["final_conclusion"],
        "ai_sections": sections,
        "report_version": "1.0",
        "classification": "Approved Report / Confidential",
    })
    return context


def build_ai_docx(case, generated_by, sections):
    context = enhanced_context(case, generated_by, sections)
    return build_default_docx(context)
