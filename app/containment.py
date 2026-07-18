import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from app.models import utcnow

CONTAINMENT_STATUSES = {
    "DRAFT": "Draft",
    "PENDING_APPROVAL": "Pending Approval",
    "APPROVED": "Approved",
    "REJECTED": "Rejected",
    "QUEUED": "Queued",
    "EXECUTING": "Executing",
    "EXECUTED": "Executed",
    "FAILED": "Failed",
    "CANCELLED": "Cancelled",
    "ROLLED_BACK": "Rolled Back",
}

ACTION_DEFINITIONS = {
    "BLOCK_IP": {"label": "Block IP", "target": "IP", "rollback": True, "command": "firewall-drop"},
    "DISABLE_USER": {"label": "Disable User", "target": "USER", "rollback": True, "command": "disable-account"},
    "KILL_PROCESS": {"label": "Kill Process", "target": "PROCESS", "rollback": False, "command": "kill-process"},
    "ISOLATE_HOST": {"label": "Isolate Host", "target": "HOST", "rollback": True, "command": "isolate-host"},
    "ADD_FIREWALL_RULE": {"label": "Add Firewall Rule", "target": "RULE", "rollback": True, "command": "firewall-rule"},
    "QUARANTINE_FILE": {"label": "Quarantine File", "target": "FILE", "rollback": True, "command": "quarantine-file"},
    "CUSTOM_SCRIPT": {"label": "Custom Script", "target": "SCRIPT", "rollback": False, "command": "custom-script"},
}

EXECUTION_PROVIDERS = {
    "MANUAL": {"label": "Manual Execution", "enabled": True},
    "WAZUH_ACTIVE_RESPONSE": {"label": "Wazuh Active Response", "enabled": False},
    "SHUFFLE": {"label": "Shuffle SOAR", "enabled": False},
    "POWERSHELL": {"label": "PowerShell Runner", "enabled": False},
    "SSH": {"label": "SSH Runner", "enabled": False},
    "FIREWALL_API": {"label": "Firewall API", "enabled": False},
    "EDR": {"label": "EDR Platform", "enabled": False},
    "SOAR_PLAYBOOK": {"label": "SOAR Playbook", "enabled": False},
}

SAFE_TARGET = re.compile(r"^[A-Za-z0-9@._:/\\=\- ]{2,255}$")
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9_.-]{2,80}$")


def action_label(action_type):
    return ACTION_DEFINITIONS.get(action_type, {}).get("label", action_type.replace("_", " ").title())


def containment_status_label(status):
    return CONTAINMENT_STATUSES.get(status, (status or "").replace("_", " ").title())


def containment_action_id(action):
    if getattr(action, "containment_id", None):
        return action.containment_id
    if getattr(action, "id", None):
        return f"CA-{action.id:06d}"
    return "CA-PENDING"


def provider_label(provider):
    return EXECUTION_PROVIDERS.get(provider or "MANUAL", {}).get("label", (provider or "MANUAL").replace("_", " ").title())


def action_supports_rollback(action_type):
    return bool(ACTION_DEFINITIONS.get(action_type, {}).get("rollback"))


def validate_containment_input(action_type, target, target_host=None):
    if action_type not in ACTION_DEFINITIONS:
        raise ValueError("Unsupported containment action.")
    target = clean_field(target)
    target_host = clean_field(target_host)
    if not target or not SAFE_TARGET.fullmatch(target):
        raise ValueError("Target contains unsafe characters.")
    if target_host and not SAFE_TARGET.fullmatch(target_host):
        raise ValueError("Target host contains unsafe characters.")
    if action_type == "CUSTOM_SCRIPT" and not SCRIPT_NAME.fullmatch(target):
        raise ValueError("Custom script must be a whitelisted script name, not a raw command.")
    return target, target_host


def clean_field(value):
    if value is None:
        return ""
    value = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    return re.sub(r"\s+", " ", value).strip().strip("\"'`")


def append_action_history(action, actor, event, details=None):
    history = json.loads(action.execution_history or "[]")
    history.append({
        "at": utcnow().isoformat(),
        "actor": getattr(actor, "full_name", None) or getattr(actor, "username", None) or "System",
        "event": event,
        "status": action.status,
        "details": (details or "")[:1200],
    })
    action.execution_history = json.dumps(history[-40:])
    return action


def approve_containment_action(action, actor, notes=None):
    action.status = "APPROVED"
    action.approved_by_id = actor.id
    action.approved_at = utcnow()
    append_action_history(action, actor, "Approved", notes)
    return action


def reject_containment_action(action, actor, notes=None):
    action.status = "REJECTED"
    action.rejected_by_id = actor.id
    action.rejected_at = utcnow()
    action.execution_result = notes or "Rejected by approver."
    append_action_history(action, actor, "Rejected", notes)
    return action


def cancel_containment_action(action, actor, notes=None):
    action.status = "CANCELLED"
    action.cancelled_by_id = actor.id
    action.cancelled_at = utcnow()
    action.execution_result = notes or "Cancelled before execution."
    append_action_history(action, actor, "Cancelled", notes)
    return action


def execute_manual_containment_action(action, actor, result, succeeded=True):
    action.status = "QUEUED"
    append_action_history(action, actor, "Queued for manual execution")
    action.status = "EXECUTING"
    action.started_at = utcnow()
    append_action_history(action, actor, "Executing")
    action.status = "EXECUTED" if succeeded else "FAILED"
    action.executed_by_id = actor.id
    action.completed_at = utcnow()
    action.execution_result = clean_result(result) or ("Manual execution completed." if succeeded else "Manual execution failed.")
    action.output = action.execution_result
    append_action_history(action, actor, "Execution completed" if succeeded else "Execution failed", action.execution_result)
    return action


def mark_containment_rolled_back(action, actor, result=None):
    action.status = "ROLLED_BACK"
    action.rollback_status = "SUCCESS"
    action.rolled_back_by_id = actor.id
    action.rolled_back_at = utcnow()
    action.rollback_result = clean_result(result) or "Manual rollback completed."
    action.execution_result = ((action.execution_result or "") + "\nRollback: " + action.rollback_result).strip()
    action.output = action.execution_result
    append_action_history(action, actor, "Rolled back", result)
    return action


def clean_result(value):
    if value is None:
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", str(value)).strip()[:4000]


def execute_containment_action(action):
    """Future integration hook for automated runners. Manual execution is used now."""
    action.started_at = utcnow()
    action.status = "EXECUTING"
    endpoint = os.environ.get("WAZUH_API_URL", "").rstrip("/")
    token = os.environ.get("WAZUH_API_TOKEN", "")
    if not endpoint or not token:
        action.status = "FAILED"
        action.completed_at = utcnow()
        action.output = "Wazuh active response connector is not configured. Set WAZUH_API_URL and WAZUH_API_TOKEN."
        return action

    definition = ACTION_DEFINITIONS[action.action_type]
    payload = {
        "command": definition["command"],
        "custom": False,
        "arguments": [action.target],
        "alert": {
            "case_id": action.case.tracking_id or action.case.public_id,
            "action_type": action.action_type,
            "target": action.target,
            "target_host": action.target_host,
        },
    }
    agent_selector = action.target_host or "000"
    url = f"{endpoint}/active-response?agents_list={urllib.parse.quote(agent_selector)}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            body = response.read(8192).decode("utf-8", "replace")
            action.status = "EXECUTED" if 200 <= response.status < 300 else "FAILED"
            action.output = body[:4000]
    except urllib.error.HTTPError as exc:
        action.status = "FAILED"
        action.output = f"Wazuh API HTTP {exc.code}: {exc.read(2048).decode('utf-8', 'replace')}"
    except (urllib.error.URLError, TimeoutError) as exc:
        action.status = "FAILED"
        action.output = f"Wazuh API request failed: {exc}"
    action.completed_at = utcnow()
    return action


def rollback_containment_action(action):
    if not action.rollback_supported:
        action.rollback_status = "UNSUPPORTED"
        return action
    endpoint = os.environ.get("WAZUH_API_URL", "").rstrip("/")
    token = os.environ.get("WAZUH_API_TOKEN", "")
    if not endpoint or not token:
        action.rollback_status = "FAILED"
        action.output = ((action.output or "") + "\nRollback failed: Wazuh active response connector is not configured.").strip()
        return action
    definition = ACTION_DEFINITIONS[action.action_type]
    payload = {
        "command": definition["command"],
        "custom": False,
        "arguments": ["rollback", action.target],
        "alert": {"case_id": action.case.tracking_id or action.case.public_id, "rollback": True},
    }
    agent_selector = action.target_host or "000"
    request = urllib.request.Request(
        f"{endpoint}/active-response?agents_list={urllib.parse.quote(agent_selector)}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            action.rollback_status = "SUCCESS" if 200 <= response.status < 300 else "FAILED"
            action.output = ((action.output or "") + "\nRollback: " + response.read(2048).decode("utf-8", "replace")).strip()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        action.rollback_status = "FAILED"
        action.output = ((action.output or "") + f"\nRollback failed: {exc}").strip()
    return action
