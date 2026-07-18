import hashlib
import json
import re


SOURCE_IP_PATHS = [
    "source_ip", "src_ip", "srcip", "src", "source.ip", "data.srcip", "data.src_ip", "data.src",
    "event.src_ip", "event.source_ip", "SrcIpAddr", "SourceIP", "sourceAddress", "sourceip", "id.orig_h",
]

DESTINATION_IP_PATHS = [
    "destination_ip", "dst_ip", "dstip", "dst", "destination.ip", "data.dstip", "data.dst_ip",
    "event.dst_ip", "DestinationIP", "destinationAddress", "destinationip", "id.resp_h",
]

USERNAME_PATHS = [
    "username", "user.name", "user", "data.dstuser", "data.srcuser",
    "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
    "TargetUserName", "SubjectUserName", "account_name",
]

HOST_PATHS = [
    "host.name", "host", "hostname", "agent.name", "agent.hostname", "computer", "computer_name",
    "data.win.system.computer", "winlog.computer_name",
]

AGENT_IP_PATHS = ["agent.ip", "agent_ip", "agent.address", "host.ip", "host_ip", "observer.ip"]

RULE_NAME_PATHS = [
    "rule.description", "rule.name", "title", "alert.title", "event.action", "signature", "detection.name",
]

RULE_ID_PATHS = ["rule.id", "rule_id", "alert.rule_id", "event.code", "signature_id", "detection.id", "id"]
MITRE_TACTIC_PATHS = ["mitre_tactic", "rule.mitre.tactic", "rule.mitre.tactics", "mitre.tactic", "mitre.tactics"]
MITRE_TECHNIQUE_PATHS = ["mitre_technique", "rule.mitre.technique", "rule.mitre.techniques", "mitre.technique", "mitre.techniques"]


def normalize_alert(payload):
    payload = payload if isinstance(payload, dict) else {}
    raw_alert = as_dict(first_value(payload, ["raw_alert", "alert.original", "original_alert"])) or payload
    source = source_label(first_value(payload, ["source", "integration", "provider", "vendor", "product", "sourcetype"]) or first_value(raw_alert, ["source", "integration"]))
    rule_name = clean(first_value(payload, RULE_NAME_PATHS) or first_value(raw_alert, RULE_NAME_PATHS), 180)
    title = clean(first_value(payload, ["title", "alert_title"]) or rule_name or "Incoming security alert", 180)
    rule_id = clean(first_value(payload, RULE_ID_PATHS) or first_value(raw_alert, RULE_ID_PATHS), 120)
    source_ip = clean_ip(first_value(payload, SOURCE_IP_PATHS) or first_value(raw_alert, SOURCE_IP_PATHS))
    destination_ip = clean_ip(first_value(payload, DESTINATION_IP_PATHS) or first_value(raw_alert, DESTINATION_IP_PATHS))
    agent_ip = clean_ip(first_value(payload, AGENT_IP_PATHS) or first_value(raw_alert, AGENT_IP_PATHS))
    host = clean(first_value(payload, HOST_PATHS) or first_value(raw_alert, HOST_PATHS), 120)
    username = clean(first_value(payload, USERNAME_PATHS) or first_value(raw_alert, USERNAME_PATHS), 120)
    severity = normalize_severity(first_value(payload, ["severity", "level", "rule.level", "event.severity", "risk_score"]) or first_value(raw_alert, ["severity", "rule.level"]))
    mitre_tactic = clean(first_item(first_value(payload, MITRE_TACTIC_PATHS) or first_value(raw_alert, MITRE_TACTIC_PATHS)), 120)
    mitre_technique = clean(first_item(first_value(payload, MITRE_TECHNIQUE_PATHS) or first_value(raw_alert, MITRE_TECHNIQUE_PATHS)), 120)
    event_id = clean(first_value(payload, ["event.id", "event_id", "id", "uuid", "alert.id"]) or first_value(raw_alert, ["id", "event.id"]), 160)
    if not event_id:
        event_id = stable_event_id(payload)
    description = clean_multiline(first_value(payload, ["description", "message", "full_log", "event.original"]) or first_value(raw_alert, ["full_log", "message"]) or json.dumps(payload, indent=2, default=str), 4000)
    asset_identifier = clean(first_value(payload, ["asset_identifier", "asset", "asset.name"]) or host or agent_ip or destination_ip or source_ip, 160)
    return {
        "event_id": event_id,
        "source": source,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": title,
        "description": description,
        "severity": severity,
        "host": host,
        "hostname": host,
        "agent_name": clean(first_value(payload, ["agent.name", "agent.hostname"]) or first_value(raw_alert, ["agent.name", "agent.hostname"]), 120),
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "agent_ip": agent_ip,
        "host_ip": clean_ip(first_value(payload, ["host.ip", "host_ip"]) or first_value(raw_alert, ["host.ip", "host_ip"])),
        "asset_identifier": asset_identifier,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "raw_alert": raw_alert,
    }


def first_value(data, paths):
    for path in paths:
        value = path_value(data, path)
        if value not in (None, "", [], {}):
            return value
    return None


def path_value(data, path):
    if not isinstance(data, dict):
        return None
    if path in data:
        return data[path]
    lowered = {str(key).lower(): key for key in data.keys()}
    if path.lower() in lowered:
        return data[lowered[path.lower()]]
    current = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        if part in current:
            current = current[part]
            continue
        lowered = {str(key).lower(): key for key in current.keys()}
        key = lowered.get(part.lower())
        if key is None:
            return None
        current = current[key]
    return current


def as_dict(value):
    return value if isinstance(value, dict) else {}


def first_item(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def clean(value, limit):
    if isinstance(value, list):
        value = first_item(value)
    if isinstance(value, dict):
        return None
    if value in (None, ""):
        return None
    text = re.sub(r"[\r\n\t]+", " ", str(value)).strip(" '\"[](){}")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] if text else None


def clean_multiline(value, limit):
    if value in (None, ""):
        return ""
    return str(value).replace("\x00", "").strip()[:limit]


def clean_ip(value):
    text = clean(value, 80)
    if not text:
        return None
    return text.split(",")[0].strip()


def source_label(value):
    text = clean(value, 80) or "Custom"
    lowered = text.lower()
    if "wazuh" in lowered:
        return "Wazuh"
    if "splunk" in lowered:
        return "Splunk"
    if "sentinel" in lowered or "azure" in lowered or "microsoft" in lowered:
        return "Sentinel"
    if "qradar" in lowered:
        return "QRadar"
    if "elastic" in lowered:
        return "Elastic"
    if "security onion" in lowered or "securityonion" in lowered:
        return "Security Onion"
    if "graylog" in lowered:
        return "Graylog"
    return text[:40] if text else "Custom"


def normalize_severity(value):
    try:
        level = int(value)
        if level >= 12:
            return "Critical"
        if level >= 8:
            return "High"
        if level >= 4:
            return "Medium"
        return "Low"
    except (TypeError, ValueError):
        text = str(value or "Medium").strip().lower()
        mapping = {"critical": "Critical", "crit": "Critical", "high": "High", "medium": "Medium", "med": "Medium", "low": "Low", "informational": "Low", "info": "Low"}
        return mapping.get(text, "Medium")


def stable_event_id(payload):
    material = json.dumps(payload, sort_keys=True, default=str)[:12000]
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:40]
