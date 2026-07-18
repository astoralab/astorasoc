import hashlib
import ipaddress
import json
import os
import re
import secrets
import base64
from datetime import datetime, timedelta, timezone

from flask import current_app
from flask_login import current_user
from cryptography.fernet import Fernet
from markupsafe import Markup, escape
from sqlalchemy import or_
from werkzeug.datastructures import FileStorage

from app import db
from app.ioc_intel import canonical_ioc_type, extract_iocs, normalize_ioc, sanitize_ioc_value
from app.models import Alert, AppSetting, AuditLog, Case, CaseAssignment, IOC, Notification, Task, TimelineEvent, User, utcnow
from app.security import client_ip, safe_original_name

ROLE_DEFINITIONS = {
    "Admin": {
        "color": "#b7ff33",
        "permissions": "Platform administration, users, settings, audit logs, playbooks, integrations, and system oversight.",
        "preset": "Admin",
    },
    "Lead": {
        "color": "#ff496d",
        "permissions": "SOC lead authority for alert promotion, review queues, case assignment, closure approval, and containment approval.",
        "preset": "Lead",
    },
    "Analyst": {
        "color": "#ff66ff",
        "permissions": "Cases, assigned investigations, review handoff, and chats.",
        "preset": "Analyst",
    },
    "Junior Analyst": {
        "color": "#f5d742",
        "permissions": "Dashboard, alerts triage, false-positive closure, and chats.",
        "preset": "Junior Analyst",
    },
    "Viewer": {
        "color": "#ffc2a6",
        "permissions": "Main dashboard only.",
        "preset": "Viewer",
    },
}

DEFAULT_TASKS = [
    "Validate alert and scope affected assets",
    "Collect triage evidence",
    "Identify and record IOCs",
    "Contain affected account or host",
    "Document actions taken",
    "Prepare closure summary",
]

INSECURE_WEBHOOK_KEYS = {"", "change-this-webhook-key", "replace-with-a-long-random-api-key"}

UPLOAD_RULES = {
    "profiles": {"extensions": {"jpg", "jpeg", "png", "webp"}, "max_bytes": 5 * 1024 * 1024},
    "role_icons": {"extensions": {"jpg", "jpeg", "png", "webp"}, "max_bytes": 2 * 1024 * 1024},
    "chat_emojis": {"extensions": {"jpg", "jpeg", "png", "webp", "gif"}, "max_bytes": 1024 * 1024},
    "report_templates": {"extensions": {"docx"}, "max_bytes": 5 * 1024 * 1024},
    "evidence": {"extensions": {"pdf", "txt", "log", "csv", "json", "png", "jpg", "jpeg", "zip"}, "max_bytes": 25 * 1024 * 1024},
}

def audit(action, details=None, actor_id=None):
    db.session.add(AuditLog(action=action, details=details, actor_id=actor_id, ip_address=client_ip()))


def fernet():
    digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_text(value):
    return fernet().encrypt((value or "").encode("utf-8")).decode("utf-8")


def decrypt_text(value):
    if not value:
        return ""
    return fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def parse_datetime_value(value):
    if not isinstance(value, str):
        return value
    cleaned = value.strip()
    if not cleaned:
        return None
    normalized = cleaned.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = f"{normalized[:-5]}{normalized[-5:-2]}:{normalized[-2:]}"
    for candidate in (normalized, normalized.replace("T", " ")):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def local_datetime(value):
    if not value:
        return None
    if isinstance(value, str):
        value = parse_datetime_value(value)
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone(timedelta(hours=5, minutes=30)))


def format_chat_time(value):
    local = local_datetime(value)
    return local.strftime("%H:%M") if local else ""


def format_short_datetime(value):
    local = local_datetime(value)
    return local.strftime("%d.%m.%y %H:%M") if local else "-"


def due_state(value):
    if not value:
        return "none"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    now = utcnow()
    if value < now:
        return "overdue"
    if value <= now + timedelta(hours=24):
        return "soon"
    return "ok"


def relative_time(value):
    if not value:
        return "just now"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = utcnow() - value
    seconds = max(int(delta.total_seconds()), 0)
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''} ago"


def online_cutoff():
    timeout_minutes = int(setting("session_timeout_minutes", 5))
    heartbeat_window = max(1, timeout_minutes)
    return utcnow() - timedelta(minutes=heartbeat_window)


def user_is_online(user):
    if not user or not user.session_active or not user.last_seen_at:
        return False
    seen = user.last_seen_at
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return seen >= online_cutoff()


def expire_stale_user_sessions():
    cutoff = online_cutoff()
    stale = User.query.filter(User.session_active.is_(True)).filter((User.last_seen_at.is_(None)) | (User.last_seen_at < cutoff)).all()
    for user in stale:
        user.session_active = False
    return len(stale)


def render_chat_mentions(text, users):
    values = {role: {"id": None, "role": role} for role in role_config()}
    for user in users:
        values[user.username] = {"id": user.id, "role": user.role}
        values[user.full_name] = {"id": user.id, "role": user.role}
    names = sorted((value for value in values if value), key=len, reverse=True)
    if not names:
        return escape(text or "")
    pattern = re.compile(r"@(" + "|".join(re.escape(value) for value in names) + r")(?=$|[\s.,!?;:])")
    parts = []
    cursor = 0
    for match in pattern.finditer(text or ""):
        parts.append(escape((text or "")[cursor : match.start()]))
        meta = values.get(match.group(1)) or {}
        user_id = meta.get("id")
        role_class = "role-" + role_slug(meta.get("role") or "")
        if user_id:
            parts.append(Markup('<button type="button" class="mention-token ') + escape(role_class) + Markup('" data-profile-card="') + escape(user_id) + Markup('">') + escape(match.group(0)) + Markup("</button>"))
        else:
            parts.append(Markup('<span class="mention-token ') + escape(role_class) + Markup('">') + escape(match.group(0)) + Markup("</span>"))
        cursor = match.end()
    parts.append(escape((text or "")[cursor:]))
    return Markup("").join(parts)


def notify_user(user_id, category, message, target_url=None):
    user = User.query.get(user_id)
    if user and getattr(user, "notification_preference", "EMAIL_IN_APP") == "DISABLED":
        return
    db.session.add(Notification(user_id=user_id, category=category, message=message[:240], target_url=target_url))


def notify_roles(roles, category, message, target_url=None):
    for user in User.query.filter(User.is_active.is_(True)).all():
        if not role_allows(user.role, *roles):
            continue
        if current_user.is_authenticated and user.id == current_user.id:
            continue
        notify_user(user.id, category, message, target_url)


def mark_notifications(category):
    if not current_user.is_authenticated:
        return
    Notification.query.filter_by(user_id=current_user.id, category=category, read_at=None).update({"read_at": utcnow()})


def timeline(case, event_type, description, actor_id=None):
    db.session.add(TimelineEvent(case=case, event_type=event_type, description=description, actor_id=actor_id))


def add_default_tasks(case):
    for title in DEFAULT_TASKS:
        db.session.add(Task(case=case, title=title, source="Auto", playbook_name="Default Checklist"))


def role_letter(role):
    return "L" if role == "Lead" else "A" if role == "Admin" else "U"


def case_label(case):
    return tracking_label(case)


TRACKING_PREFIX = "AST"
LEGACY_TRACKING_PREFIX = "RVN"


def normalize_tracking_id(value):
    if not value:
        return None
    text = str(value)
    if text.startswith(f"{LEGACY_TRACKING_PREFIX}-"):
        return f"{TRACKING_PREFIX}-{text.split('-', 1)[1]}"
    return text


def tracking_label(item):
    if not item:
        return f"{TRACKING_PREFIX}-UNKNOWN"
    existing = normalize_tracking_id(getattr(item, "tracking_id", None) or getattr(item, "public_id", None))
    return existing or f"{TRACKING_PREFIX}-PENDING-{getattr(item, 'id', 'NEW')}"


def generate_tracking_id(created_at=None):
    year = (created_at or utcnow()).year
    prefix = f"{TRACKING_PREFIX}-{year}-"
    legacy_prefix = f"{LEGACY_TRACKING_PREFIX}-{year}-"
    highest = 0
    for model in (Alert, Case):
        for (value,) in db.session.query(model.tracking_id).filter(or_(model.tracking_id.like(f"{prefix}%"), model.tracking_id.like(f"{legacy_prefix}%"))).all():
            try:
                highest = max(highest, int((value or "").rsplit("-", 1)[-1]))
            except ValueError:
                continue
    return f"{prefix}{highest + 1:06d}"


def ensure_tracking_id(item):
    if not getattr(item, "tracking_id", None):
        item.tracking_id = generate_tracking_id(getattr(item, "created_at", None))
    if isinstance(item, Case):
        item.public_id = item.tracking_id
    return item.tracking_id


def set_case_assignees(case, user_ids, actor_id=None):
    clean_ids = []
    for user_id in user_ids:
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            continue
        if user_id and user_id not in clean_ids:
            clean_ids.append(user_id)
    users = []
    if clean_ids:
        users = [
            user
            for user in User.query.filter(User.id.in_(clean_ids), User.is_active.is_(True)).order_by(User.full_name).all()
            if role_allows(user.role, "Analyst")
        ]
    case.assignments = [CaseAssignment(user_id=user.id, assigned_by_id=actor_id) for user in users]
    case.assignee_id = users[0].id if users else None
    return users


def case_is_assigned_to(case, user):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if case.assignee_id == user.id:
        return True
    return any(assignment.user_id == user.id for assignment in case.assignments)


def generate_case_public_id(role, numeric_id=None):
    base = f"{utcnow():%d%m%Y}{role_letter(role)}"
    if not Case.query.filter_by(public_id=base).first():
        return base
    suffix = numeric_id or (Case.query.count() + 1)
    return f"{base}-{suffix}"


def setting(key, default=None):
    item = AppSetting.query.get(key)
    return item.value if item and item.value else default


def set_setting(key, value):
    item = AppSetting.query.get(key)
    if not item:
        item = AppSetting(key=key)
        db.session.add(item)
    item.value = value


def generate_webhook_api_key():
    return f"ast_{secrets.token_urlsafe(48)}"


def configured_webhook_api_key():
    return setting("webhook_api_key") or current_app.config.get("WEBHOOK_API_KEY")


def webhook_api_key_is_insecure(value):
    return not value or value in INSECURE_WEBHOOK_KEYS


def ensure_webhook_api_key(actor_id=None):
    key = configured_webhook_api_key()
    if not webhook_api_key_is_insecure(key):
        return key, False
    key = generate_webhook_api_key()
    set_setting("webhook_api_key", key)
    audit("webhook_api_key_generated", "Webhook API key generated automatically.", actor_id)
    return key, True


def role_slug(role):
    return re.sub(r"[^a-z0-9]+", "-", role.lower()).strip("-")


def role_config():
    try:
        saved = json.loads(setting("role_config", "{}") or "{}")
    except json.JSONDecodeError:
        saved = {}
    config = {}
    for role, defaults in ROLE_DEFINITIONS.items():
        config[role] = {
            "color": saved.get(role, {}).get("color") or defaults["color"],
            "icon": saved.get(role, {}).get("icon") or "",
            "permissions": saved.get(role, {}).get("permissions") or defaults["permissions"],
            "preset": defaults["preset"],
            "slug": role_slug(role),
            "system": True,
        }
    for role, values in saved.items():
        if role in config:
            continue
        preset = values.get("preset") if values.get("preset") in ROLE_DEFINITIONS else "Viewer"
        config[role] = {
            "color": values.get("color") or ROLE_DEFINITIONS[preset]["color"],
            "icon": values.get("icon") or "",
            "permissions": values.get("permissions") or ROLE_DEFINITIONS[preset]["permissions"],
            "preset": preset,
            "slug": role_slug(role),
            "system": False,
        }
    return config


def set_role_config(values):
    clean = {}
    current = role_config()
    merged = {**current, **values}
    for role, meta in merged.items():
        color = (values.get(role, {}).get("color") or meta["color"]).strip()
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            color = meta["color"]
        preset = values.get(role, {}).get("preset") or meta["preset"]
        if preset not in ROLE_DEFINITIONS:
            preset = "Viewer"
        permissions = (values.get(role, {}).get("permissions") or meta["permissions"]).strip()
        clean[role] = {"color": color, "preset": preset, "permissions": permissions}
        if values.get(role, {}).get("icon") or meta.get("icon"):
            clean[role]["icon"] = values.get(role, {}).get("icon") or meta.get("icon")
    set_setting("role_config", json.dumps(clean, sort_keys=True))


def add_role(name, color, preset, permissions):
    name = re.sub(r"\s+", " ", (name or "").strip())[:20]
    if not name or name in ROLE_DEFINITIONS:
        return False
    config = role_config()
    if name in config:
        return False
    config[name] = {
        "color": color or ROLE_DEFINITIONS.get(preset, ROLE_DEFINITIONS["Viewer"])["color"],
        "preset": preset if preset in ROLE_DEFINITIONS else "Viewer",
        "permissions": permissions or ROLE_DEFINITIONS.get(preset, ROLE_DEFINITIONS["Viewer"])["permissions"],
        "icon": "",
        "slug": role_slug(name),
        "system": False,
    }
    set_role_config({role: meta for role, meta in config.items()})
    return True


def delete_role(name):
    if name in ROLE_DEFINITIONS:
        return False
    config = role_config()
    if name not in config:
        return False
    del config[name]
    clean = {
        role: {"color": meta["color"], "preset": meta["preset"], "permissions": meta["permissions"], "icon": meta.get("icon", "")}
        for role, meta in config.items()
    }
    set_setting("role_config", json.dumps(clean, sort_keys=True))
    return True


def role_base(role):
    return role_config().get(role, {"preset": role}).get("preset", role)


def role_allows(role, *allowed):
    return role in allowed or role_base(role) in allowed


def random_filename(original):
    ext = ""
    if "." in original:
        ext = "." + original.rsplit(".", 1)[1].lower()
    return f"{secrets.token_hex(24)}{ext}"


def upload_extension(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def save_upload(file: FileStorage, subdir):
    original = safe_original_name(file.filename)
    rule = UPLOAD_RULES.get(subdir)
    ext = upload_extension(original)
    if rule and ext not in rule["extensions"]:
        raise ValueError("Unsupported file type.")
    stored = random_filename(original)
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], subdir)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, stored)
    sha = hashlib.sha256()
    total = 0
    max_bytes = rule["max_bytes"] if rule else current_app.config.get("MAX_CONTENT_LENGTH", 25 * 1024 * 1024)
    file.stream.seek(0)
    try:
        with open(path, "wb") as handle:
            while True:
                chunk = file.stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("File is too large.")
                sha.update(chunk)
                handle.write(chunk)
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    file.stream.seek(0)
    return original, stored, sha.hexdigest()


def extract_iocs_from_text(text):
    return [(ioc.type, ioc.value) for ioc in extract_iocs(text)]


def create_iocs(case=None, values=None, actor_id=None, source="Auto extraction", alert=None, source_system=None, analyst_notes=None):
    created = []
    for item in values or []:
        if hasattr(item, "type"):
            kind, value, normalized, confidence = item.type, item.value, item.normalized, item.confidence
        else:
            kind, value = item
            normalized = ""
            confidence = "Medium"
        kind = canonical_ioc_type(kind)
        value = sanitize_ioc_value(kind, value)
        if not value:
            continue
        normalized = normalize_ioc(kind, value)
        if not normalized:
            continue
        query = IOC.query.filter(IOC.type == kind, IOC.normalized_value == normalized)
        if case is not None:
            query = query.filter(IOC.case_id == case.id)
        else:
            query = query.filter(IOC.case_id.is_(None))
        if alert is not None:
            query = query.filter(IOC.alert_id == alert.id)
        else:
            query = query.filter(IOC.alert_id.is_(None))
        existing = query.first()
        if existing:
            existing.last_seen_at = utcnow()
            if analyst_notes and not existing.analyst_notes:
                existing.analyst_notes = analyst_notes
            continue
        ioc = IOC(
            case=case,
            alert=alert,
            source_alert=alert,
            type=kind,
            value=value,
            normalized_value=normalized,
            confidence=confidence,
            source=source,
            source_system=source_system or (alert.source if alert else (case.source if case else None)),
            analyst_notes=analyst_notes,
            added_by_id=actor_id,
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.session.add(ioc)
        created.append(ioc)
    return created


def ioc_related_counts(ioc):
    value = sanitize_ioc_value(ioc.type, ioc.value)
    normalized = ioc.normalized_value or normalize_ioc(ioc.type, value)
    if not normalized:
        return {"cases": 0, "alerts": 0, "occurrences": 0}
    query = IOC.query.filter(IOC.type == ioc.type, IOC.normalized_value == normalized)
    case_count = query.filter(IOC.case_id.isnot(None)).with_entities(IOC.case_id).distinct().count()
    alert_count = query.filter(IOC.alert_id.isnot(None)).with_entities(IOC.alert_id).distinct().count()
    total = query.count()
    return {"cases": case_count, "alerts": alert_count, "occurrences": total}


def find_duplicate_case(rule_id, host, source_ip):
    cutoff = utcnow() - timedelta(minutes=30)
    return (
        Case.query.filter(Case.rule_id == rule_id, Case.affected_host == host, Case.source_ip == source_ip, Case.created_at >= cutoff)
        .order_by(Case.created_at.desc())
        .first()
    )
