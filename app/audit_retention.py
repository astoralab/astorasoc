import csv
import os
import zipfile
from datetime import date, datetime, timedelta, timezone
from io import StringIO

from flask import current_app

from app import db
from app.models import AuditLog
from app.utils import audit, setting, set_setting

LOGIN_LOGOUT_ACTIONS = {"login", "logout"}
FAILED_LOGIN_ACTIONS = {"login_failed"}

DEFAULT_RETENTION = {
    "login_logout_retention_days": "90",
    "failed_login_retention_days": "180",
    "case_admin_security_retention_days": "365",
    "archive_retention_years": "7",
    "enable_auto_archive": "true",
    "enable_auto_delete": "false",
}


def get_retention_settings():
    return {key: setting(key, value) for key, value in DEFAULT_RETENTION.items()}


def set_retention_settings(values, actor_id=None):
    old = get_retention_settings()
    for key, value in values.items():
        set_setting(key, str(value).lower() if isinstance(value, bool) else str(value))
    changed = {key: values[key] for key in values if str(old.get(key)) != str(values[key]).lower()}
    if changed:
        audit("retention_settings_updated", f"Audit retention settings changed: {changed}", actor_id)


def archive_logs(logs, label, actor_id=None):
    logs = list(logs)
    if not logs:
        return None, True

    archive_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], "audit_archives")
    os.makedirs(archive_dir, exist_ok=True)
    filename = f"audit-{label}-{datetime.now(timezone.utc):%Y%m%d%H%M%S}.zip"
    path = os.path.join(archive_dir, filename)

    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["id", "created_at", "actor", "action", "details", "ip_address"])
    for log in logs:
        writer.writerow(
            [
                log.id,
                log.created_at.isoformat() if log.created_at else "",
                log.actor.username if log.actor else "System",
                log.action,
                log.details or "",
                log.ip_address or "",
            ]
        )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{label}.csv", csv_buffer.getvalue())

    verified = verify_archive(path)
    audit("audit_logs_archived", f"Archived {len(logs)} audit logs to {filename}. Verified={verified}.", actor_id)
    return path, verified


def verify_archive(path):
    try:
        with zipfile.ZipFile(path, "r") as archive:
            return archive.testzip() is None
    except zipfile.BadZipFile:
        return False


def logs_for_period(day=None, month=None, year=None):
    query = AuditLog.query.filter(~AuditLog.action.like("chat_%"))
    if day:
        start = datetime.combine(day, datetime.min.time(), timezone.utc)
        end = start + timedelta(days=1)
        return query.filter(AuditLog.created_at >= start, AuditLog.created_at < end).order_by(AuditLog.created_at.desc()).all()
    if month and year:
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc) if month == 12 else datetime(year, month + 1, 1, tzinfo=timezone.utc)
        return query.filter(AuditLog.created_at >= start, AuditLog.created_at < end).order_by(AuditLog.created_at.desc()).all()
    if year:
        start = datetime(year, 1, 1, tzinfo=timezone.utc)
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        return query.filter(AuditLog.created_at >= start, AuditLog.created_at < end).order_by(AuditLog.created_at.desc()).all()
    return query.order_by(AuditLog.created_at.desc()).all()


def run_scheduled_retention():
    today = date.today().isoformat()
    settings = get_retention_settings()
    changed = False

    if settings["enable_auto_archive"] == "true":
        month_key = date.today().strftime("%Y-%m")
        if setting("last_audit_archive_month") != month_key:
            archive_logs(AuditLog.query.order_by(AuditLog.created_at.asc()).all(), f"monthly-{month_key}")
            set_setting("last_audit_archive_month", month_key)
            changed = True

    if settings["enable_auto_delete"] == "true" and setting("last_audit_cleanup_date") != today:
        cleanup_old_logs(actor_id=None)
        cleanup_old_archives(int(settings["archive_retention_years"]))
        set_setting("last_audit_cleanup_date", today)
        changed = True

    if changed:
        db.session.commit()


def cleanup_old_logs(actor_id=None):
    settings = get_retention_settings()
    now = datetime.now(timezone.utc)
    candidates = []

    for log in AuditLog.query.order_by(AuditLog.created_at.asc()).all():
        created_at = ensure_aware(log.created_at)
        age_days = (now - created_at).days if created_at else 0
        if log.action in LOGIN_LOGOUT_ACTIONS:
            limit = int(settings["login_logout_retention_days"])
        elif log.action in FAILED_LOGIN_ACTIONS:
            limit = int(settings["failed_login_retention_days"])
        else:
            limit = int(settings["case_admin_security_retention_days"])
        if age_days > limit:
            candidates.append(log)

    if not candidates:
        audit("audit_cleanup_skipped", "No audit logs exceeded retention.", actor_id)
        return 0

    _, verified = archive_logs(candidates, "pre-delete", actor_id)
    if not verified:
        audit("audit_cleanup_blocked", "Audit deletion blocked because archive verification failed.", actor_id)
        return 0

    count = len(candidates)
    for log in candidates:
        db.session.delete(log)
    audit("audit_logs_deleted", f"Deleted {count} audit logs after archive verification.", actor_id)
    return count


def cleanup_old_archives(retention_years, actor_id=None):
    archive_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], "audit_archives")
    if not os.path.isdir(archive_dir):
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_years * 365)
    removed = 0
    for name in os.listdir(archive_dir):
        if not name.endswith(".zip"):
            continue
        path = os.path.join(archive_dir, name)
        modified = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
        if modified < cutoff:
            os.remove(path)
            removed += 1
    if removed:
        audit("audit_archives_deleted", f"Deleted {removed} expired audit archive files.", actor_id)
    return removed


def ensure_aware(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
