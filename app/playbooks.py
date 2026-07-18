import json
import re

from app import db
from app.models import PlaybookTemplate, Task, utcnow
from app.utils import audit, timeline, tracking_label

MATCH_LABELS = {
    "RULE_ID": "SIEM Rule ID",
    "CATEGORY": "Source Category",
    "MITRE_TACTIC": "MITRE Tactic",
    "ALERT_TYPE": "Alert Type",
    "CASE_TYPE": "Case Type",
    "GENERIC": "Generic Fallback",
}

MATCH_TYPE_RANK = {
    "RULE_ID": 10,
    "CATEGORY": 20,
    "MITRE_TACTIC": 30,
    "ALERT_TYPE": 40,
    "CASE_TYPE": 50,
    "GENERIC": 60,
}

CASE_TYPE_CHOICES = [
    ("Vulnerability Remediation", "Vulnerability Remediation"),
    ("Malware Incident", "Malware Incident"),
    ("Phishing Incident", "Phishing Incident"),
    ("Credential Access", "Credential Access"),
    ("Privilege Escalation", "Privilege Escalation"),
    ("Lateral Movement", "Lateral Movement"),
    ("Data Exfiltration", "Data Exfiltration"),
    ("Threat Hunt", "Threat Hunt"),
    ("Compliance Investigation", "Compliance Investigation"),
    ("Asset Investigation", "Asset Investigation"),
    ("Security Request", "Security Request"),
    ("Manual Investigation", "Manual Investigation"),
    ("Generic", "Generic"),
]

PLAYBOOK_CATEGORY_CHOICES = [
    ("Vulnerability", "Vulnerability"),
    ("Malware", "Malware"),
    ("Phishing", "Phishing"),
    ("Credential Access", "Credential Access"),
    ("Threat Hunting", "Threat Hunting"),
    ("Compliance", "Compliance"),
    ("Operations", "Operations"),
    ("Generic", "Generic"),
]

DEFAULT_PLAYBOOKS = [
    {
        "name": "Vulnerability Remediation Playbook",
        "description": "Validation, remediation, and closure workflow for vulnerability cases.",
        "category": "Vulnerability",
        "match_type": "CASE_TYPE",
        "match_value": "Vulnerability Remediation",
        "priority": 50,
        "tasks_text": "\n".join([
            "Validate vulnerability",
            "Confirm affected asset",
            "Assess business impact",
            "Obtain owner approval",
            "Apply remediation",
            "Verify remediation",
            "Perform validation scan",
            "Monitor for issues",
            "Request closure review",
        ]),
    },
    {
        "name": "Malware Investigation Playbook",
        "description": "Malware validation, containment, eradication, and recovery workflow.",
        "category": "Malware",
        "match_type": "CASE_TYPE",
        "match_value": "Malware Incident",
        "priority": 50,
        "tasks_text": "\n".join([
            "Validate malware detection",
            "Collect evidence",
            "Identify infected assets",
            "Isolate affected host",
            "Perform malware analysis",
            "Remove malware",
            "Verify remediation",
            "Request closure review",
        ]),
    },
    {
        "name": "Credential Access Playbook",
        "description": "Credential and authentication abuse investigation workflow.",
        "category": "Credential Access",
        "match_type": "CASE_TYPE",
        "match_value": "Credential Access",
        "priority": 50,
        "tasks_text": "\n".join([
            "Validate authentication activity",
            "Review login history",
            "Check MFA status",
            "Identify impacted users",
            "Review account activity",
            "Reset credentials if required",
            "Request closure review",
        ]),
    },
    {
        "name": "Phishing Response Playbook",
        "description": "Phishing validation, mailbox evidence, and user follow-up workflow.",
        "category": "Phishing",
        "match_type": "CASE_TYPE",
        "match_value": "Phishing Incident",
        "priority": 50,
        "tasks_text": "\n".join([
            "Validate phishing activity",
            "Collect email evidence",
            "Identify affected users",
            "Block malicious indicators",
            "Reset credentials if required",
            "User awareness follow-up",
            "Request closure review",
        ]),
    },
    {
        "name": "Threat Hunting Playbook",
        "description": "Hypothesis-led hunt workflow for analyst-driven investigations.",
        "category": "Threat Hunting",
        "match_type": "CASE_TYPE",
        "match_value": "Threat Hunt",
        "priority": 50,
        "tasks_text": "\n".join([
            "Define hunt objective",
            "Collect telemetry",
            "Search for indicators",
            "Analyze findings",
            "Document findings",
            "Escalate if threats identified",
            "Request closure review",
        ]),
    },
    {
        "name": "Compliance Investigation Playbook",
        "description": "Compliance control review and evidence collection workflow.",
        "category": "Compliance",
        "match_type": "CASE_TYPE",
        "match_value": "Compliance Investigation",
        "priority": 50,
        "tasks_text": "\n".join([
            "Define compliance requirement",
            "Review controls",
            "Collect evidence",
            "Document findings",
            "Review remediation gaps",
            "Submit compliance report",
            "Request closure review",
        ]),
    },
    {
        "name": "Manual Investigation Playbook",
        "description": "General manual investigation workflow for analyst-created cases.",
        "category": "Operations",
        "match_type": "CASE_TYPE",
        "match_value": "Manual Investigation",
        "priority": 50,
        "tasks_text": "\n".join([
            "Review case details",
            "Gather evidence",
            "Perform investigation",
            "Document findings",
            "Identify remediation actions",
            "Request closure review",
        ]),
    },
    {
        "name": "Generic SOC Triage",
        "description": "Fallback playbook for alerts without a more specific match.",
        "category": "Generic",
        "match_type": "GENERIC",
        "match_value": "*",
        "priority": 999,
        "tasks_text": "\n".join([
            "Validate alert fidelity and confirm affected asset context",
            "Review raw security event, rule description, and related timeline",
            "Collect initial evidence and preserve relevant logs",
            "Identify users, hosts, source IPs, destination IPs, and IOCs",
            "Assess containment need and document next response action",
            "Prepare closure or escalation summary",
        ]),
    },
    {
        "name": "Authentication Failure Investigation",
        "description": "Account and login anomaly triage.",
        "category": "Credential Access",
        "match_type": "CATEGORY",
        "match_value": "authentication",
        "priority": 40,
        "tasks_text": "\n".join([
            "Confirm failed/successful login pattern and affected account",
            "Review source IP reputation, geolocation, and prior activity",
            "Check for successful login after repeated failures",
            "Validate MFA/password reset indicators where available",
            "Decide whether account disablement or password reset is required",
        ]),
    },
    {
        "name": "Malware / File Execution Investigation",
        "description": "Suspicious file, process, and malware triage.",
        "category": "Malware",
        "match_type": "ALERT_TYPE",
        "match_value": "malware",
        "priority": 35,
        "tasks_text": "\n".join([
            "Identify process, file path, hash, user, and host involved",
            "Check whether the file hash or path appears in other alerts",
            "Collect process tree, command line, and persistence indicators",
            "Assess host isolation or file quarantine requirement",
            "Document eradication and recovery validation steps",
        ]),
    },
    {
        "name": "MITRE Credential Access",
        "description": "Credential theft and account abuse workflow.",
        "category": "Credential Access",
        "match_type": "MITRE_TACTIC",
        "match_value": "Credential Access",
        "priority": 30,
        "tasks_text": "\n".join([
            "Validate credential access tactic and mapped technique",
            "Identify impacted users, sessions, and privilege level",
            "Review recent authentication and lateral movement indicators",
            "Collect evidence for credential dumping, phishing, or token abuse",
            "Determine password reset, session revocation, and containment actions",
        ]),
    },
]


def seed_default_playbooks(actor_id=None):
    count = 0
    for item in DEFAULT_PLAYBOOKS:
        template = PlaybookTemplate.query.filter_by(name=item["name"]).first()
        if template:
            changed = False
            for key in ("description", "category", "match_type", "match_value", "priority", "tasks_text"):
                if getattr(template, key, None) in (None, "", "Generic") or key in {"category"}:
                    new_value = item[key]
                    if getattr(template, key, None) != new_value:
                        setattr(template, key, new_value)
                        changed = True
            if changed:
                template.updated_by_id = actor_id
            continue
        db.session.add(PlaybookTemplate(created_by_id=actor_id, updated_by_id=actor_id, is_active=True, **item))
        count += 1
    return count


def playbook_steps(template):
    return [line.strip(" -\t")[:180] for line in (template.tasks_text or "").splitlines() if line.strip(" -\t")]


def alert_playbook_context(alert):
    raw = alert.raw_json if isinstance(alert.raw_json, dict) else {}
    raw_alert = raw.get("raw_alert") if isinstance(raw.get("raw_alert"), dict) else {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else raw_alert.get("rule") if isinstance(raw_alert.get("rule"), dict) else {}
    groups = rule.get("groups") or raw.get("groups") or []
    if not isinstance(groups, list):
        groups = [groups]
    values = {
        "RULE_ID": [alert.rule_id],
        "MITRE_TACTIC": [alert.mitre_tactic],
        "CATEGORY": [raw.get("category"), raw.get("alert_category"), raw.get("decoder", {}).get("name") if isinstance(raw.get("decoder"), dict) else None, *groups],
        "ALERT_TYPE": [raw.get("type"), raw.get("alert_type"), raw.get("event_type"), alert.title, alert.description],
        "GENERIC": ["*"],
    }
    return {key: [normalize_match_value(value) for value in items if normalize_match_value(value)] for key, items in values.items()}


def case_type_for_playbook(case):
    if getattr(case, "case_type", None):
        return case.case_type
    text = " ".join(filter(None, [case.title, case.description, case.source, case.mitre_tactic, case.mitre_technique])).lower()
    mappings = [
        ("Vulnerability Remediation", ("vulnerability", "cve", "patch", "remediation", "scan")),
        ("Malware Incident", ("malware", "ransom", "trojan", "virus", "infected", "quarantine")),
        ("Phishing Incident", ("phishing", "email", "mailbox", "credential harvest")),
        ("Credential Access", ("credential", "password", "login", "authentication", "mfa", "token")),
        ("Privilege Escalation", ("privilege escalation", "elevation", "admin right", "sudo")),
        ("Lateral Movement", ("lateral movement", "remote logon", "psexec", "rdp", "smb")),
        ("Data Exfiltration", ("exfiltration", "data transfer", "data loss", "large upload")),
        ("Threat Hunt", ("threat hunt", "hunt objective", "hypothesis")),
        ("Compliance Investigation", ("compliance", "audit", "control", "policy")),
        ("Asset Investigation", ("asset", "inventory", "exposure", "critical asset")),
        ("Security Request", ("request", "service request", "security task")),
    ]
    for case_type, keywords in mappings:
        if any(keyword in text for keyword in keywords):
            return case_type
    return "Manual Investigation" if (case.source or "").lower() == "manual" else "Generic"


def case_playbook_context(case, alert=None):
    context = alert_playbook_context(alert) if alert else {}
    case_type = case_type_for_playbook(case)
    context.setdefault("CASE_TYPE", [])
    context["CASE_TYPE"].append(normalize_match_value(case_type))
    context.setdefault("GENERIC", ["*"])
    return context


def normalize_match_value(value):
    text = str(value or "").strip().lower()
    return re.sub(r"\s+", " ", text)


def template_matches(template, context):
    if template.match_type == "GENERIC":
        return True
    expected = normalize_match_value(template.match_value)
    if not expected:
        return False
    candidates = context.get(template.match_type, [])
    return any(expected == candidate or expected in candidate for candidate in candidates)


def select_playbook(alert=None, case=None):
    seed_default_playbooks()
    context = case_playbook_context(case, alert) if case is not None else alert_playbook_context(alert)
    templates = PlaybookTemplate.query.filter_by(is_active=True, is_archived=False).all()
    fallback = None
    matches = []
    for template in templates:
        if template.match_type == "GENERIC":
            fallback = fallback or template
            continue
        if template_matches(template, context):
            matches.append(template)
    if matches:
        matches.sort(key=lambda template: (MATCH_TYPE_RANK.get(template.match_type, 999), template.priority, template.id))
        return matches[0], context
    return fallback, context


def apply_playbook_to_case(case, alert=None, actor_id=None, template=None):
    selected_template = template
    if selected_template:
        context = case_playbook_context(case, alert)
    else:
        seed_default_playbooks(actor_id)
        selected_template, context = select_playbook(alert=alert, case=case)
    if not selected_template:
        return None, []
    existing = {task.title.strip().lower() for task in case.tasks}
    created = []
    for title in playbook_steps(selected_template):
        if title.lower() in existing:
            continue
        task = Task(case=case, title=title, source="Auto", playbook_template_id=selected_template.id, playbook_name=selected_template.name)
        db.session.add(task)
        created.append(task)
        existing.add(title.lower())
    details = json.dumps(context, sort_keys=True)[:500]
    selected_template.usage_count = (selected_template.usage_count or 0) + 1
    selected_template.last_applied_at = utcnow()
    timeline(case, "Playbook applied", f"{selected_template.name} generated {len(created)} investigation task(s).", actor_id)
    audit("playbook_applied", f"Playbook {selected_template.name} applied to case {tracking_label(case)}; {len(created)} tasks generated. Match context: {details}", actor_id)
    return selected_template, created


def active_case_playbook(case):
    counts = {}
    for task in case.tasks:
        if not task.playbook_name:
            continue
        key = task.playbook_name
        counts[key] = counts.get(key, 0) + 1
    if not counts:
        return None
    name = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return PlaybookTemplate.query.filter_by(name=name).first()


def playbook_aligned_with_case(template, case):
    if not template:
        return False
    if template.match_type == "GENERIC":
        return True
    context = case_playbook_context(case)
    return template_matches(template, context)


def aligned_case_tasks(case):
    template = active_case_playbook(case)
    if template and playbook_aligned_with_case(template, case):
        return [task for task in case.tasks if task.playbook_name == template.name or task.playbook_template_id == template.id]
    case_type = case_type_for_playbook(case)
    expected = normalize_match_value(case_type)
    aligned_templates = PlaybookTemplate.query.filter_by(is_active=True, is_archived=False, match_type="CASE_TYPE").all()
    aligned_names = {
        template.name
        for template in aligned_templates
        if normalize_match_value(template.match_value) == expected
    }
    if aligned_names:
        tasks = [task for task in case.tasks if task.playbook_name in aligned_names]
        if tasks:
            return tasks
    return [task for task in case.tasks if not task.playbook_name or task.source == "Analyst"]
