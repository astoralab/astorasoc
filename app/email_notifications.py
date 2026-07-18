import smtplib
import ssl
from email.message import EmailMessage
from html import escape

from flask import current_app, url_for

from app import db
from app.models import EmailDeliveryLog, User, utcnow
from app.utils import decrypt_text, encrypt_text, setting, set_setting, tracking_label


EMAIL_SETTING_KEYS = {
    "smtp_host": "email_smtp_host",
    "smtp_port": "email_smtp_port",
    "smtp_username": "email_smtp_username",
    "smtp_password": "email_smtp_password",
    "use_tls": "email_use_tls",
    "use_ssl": "email_use_ssl",
    "from_name": "email_from_name",
    "from_email": "email_from_email",
}


def bool_setting(key, default=False):
    value = setting(key, "true" if default else "false")
    return str(value).lower() in {"1", "true", "yes", "on"}


def email_config():
    password = setting(EMAIL_SETTING_KEYS["smtp_password"], "")
    return {
        "smtp_host": setting(EMAIL_SETTING_KEYS["smtp_host"], ""),
        "smtp_port": int(setting(EMAIL_SETTING_KEYS["smtp_port"], "587") or 587),
        "smtp_username": setting(EMAIL_SETTING_KEYS["smtp_username"], ""),
        "smtp_password": decrypt_text(password) if password else "",
        "use_tls": bool_setting(EMAIL_SETTING_KEYS["use_tls"], True),
        "use_ssl": bool_setting(EMAIL_SETTING_KEYS["use_ssl"], False),
        "from_name": setting(EMAIL_SETTING_KEYS["from_name"], "AstoraSOC"),
        "from_email": setting(EMAIL_SETTING_KEYS["from_email"], ""),
    }


def save_email_config(form):
    set_setting(EMAIL_SETTING_KEYS["smtp_host"], (form.smtp_host.data or "").strip())
    set_setting(EMAIL_SETTING_KEYS["smtp_port"], str(form.smtp_port.data or 587))
    set_setting(EMAIL_SETTING_KEYS["smtp_username"], (form.smtp_username.data or "").strip())
    if form.smtp_password.data:
        set_setting(EMAIL_SETTING_KEYS["smtp_password"], encrypt_text(form.smtp_password.data))
    set_setting(EMAIL_SETTING_KEYS["use_tls"], str(bool(form.use_tls.data)).lower())
    set_setting(EMAIL_SETTING_KEYS["use_ssl"], str(bool(form.use_ssl.data)).lower())
    set_setting(EMAIL_SETTING_KEYS["from_name"], (form.from_name.data or "AstoraSOC").strip())
    set_setting(EMAIL_SETTING_KEYS["from_email"], (form.from_email.data or "").strip())


def load_email_form(form):
    config = email_config()
    form.smtp_host.data = config["smtp_host"]
    form.smtp_port.data = config["smtp_port"]
    form.smtp_username.data = config["smtp_username"]
    form.smtp_password.data = ""
    form.use_tls.data = config["use_tls"]
    form.use_ssl.data = config["use_ssl"]
    form.from_name.data = config["from_name"]
    form.from_email.data = config["from_email"]


def email_enabled(config=None):
    config = config or email_config()
    return bool(config["smtp_host"] and config["smtp_port"] and config["from_email"])


def absolute_url(endpoint, **values):
    try:
        return url_for(endpoint, _external=True, **values)
    except RuntimeError:
        base = current_app.config.get("PUBLIC_BASE_URL") or "http://localhost:5000"
        path = url_for(endpoint, _external=False, **values)
        return base.rstrip("/") + path


def render_email_html(title, subtitle, fields, action_url=None, action_label="Open AstoraSOC", severity=None):
    badge = ""
    if severity:
        sev = escape(str(severity))
        colors = {"Critical": "#ff355d", "High": "#ff8a2a", "Medium": "#ffd84d", "Low": "#4da3ff"}
        badge = f'<span style="display:inline-block;padding:7px 12px;border-radius:999px;background:{colors.get(severity, "#24d6a3")};color:#07100f;font-weight:800;font-size:12px;">{sev}</span>'
    rows = "".join(
        f'<tr><td style="padding:10px 0;color:#8aa0a7;font-size:13px;">{escape(str(label))}</td>'
        f'<td style="padding:10px 0;color:#f6fffb;font-weight:700;text-align:right;">{escape(str(value or "Not Available"))}</td></tr>'
        for label, value in fields
    )
    button = ""
    if action_url:
        button = (
            f'<a href="{escape(action_url)}" style="display:inline-block;margin-top:20px;padding:13px 18px;'
            'border-radius:10px;background:linear-gradient(135deg,#24d6a3,#3b82f6);color:#06110f;'
            'font-weight:900;text-decoration:none;">'
            f"{escape(action_label)}</a>"
        )
    return f"""<!doctype html>
<html><body style="margin:0;background:#050608;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f6fffb;">
  <div style="max-width:680px;margin:0 auto;padding:28px;">
    <div style="background:linear-gradient(135deg,#07100f,#111827);border:1px solid rgba(36,214,163,.28);border-radius:18px;overflow:hidden;">
      <div style="padding:24px 26px;border-bottom:1px solid rgba(255,255,255,.08);">
        <div style="letter-spacing:.18em;text-transform:uppercase;color:#24d6a3;font-size:12px;font-weight:900;">AstoraSOC</div>
        <h1 style="margin:10px 0 6px;font-size:26px;line-height:1.2;color:#ffffff;">{escape(title)}</h1>
        <p style="margin:0;color:#b7c8ce;font-size:15px;">{escape(subtitle or "")}</p>
      </div>
      <div style="padding:24px 26px;">
        {badge}
        <table style="width:100%;border-collapse:collapse;margin-top:16px;">{rows}</table>
        {button}
      </div>
      <div style="padding:16px 26px;background:rgba(255,255,255,.035);color:#8aa0a7;font-size:12px;">
        This notification was generated by AstoraSOC. Use the AstoraSOC investigation workspace for approvals, audit trail, and response history.
      </div>
    </div>
  </div>
</body></html>"""


def send_raw_email(recipient_email, subject, html_body, notification_type="test", recipient_user=None):
    log = EmailDeliveryLog(
        recipient_user_id=recipient_user.id if recipient_user else None,
        recipient_email=recipient_email,
        notification_type=notification_type,
        subject=subject[:180],
        status="QUEUED",
    )
    db.session.add(log)
    db.session.flush()
    config = email_config()
    if not email_enabled(config):
        log.status = "SKIPPED"
        log.error = "SMTP settings are incomplete."
        return log
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"{config['from_name']} <{config['from_email']}>" if config["from_name"] else config["from_email"]
        msg["To"] = recipient_email
        msg.set_content("Open AstoraSOC to view this security notification.")
        msg.add_alternative(html_body, subtype="html")
        if config["use_ssl"]:
            server = smtplib.SMTP_SSL(config["smtp_host"], config["smtp_port"], timeout=15, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=15)
            if config["use_tls"]:
                server.starttls(context=ssl.create_default_context())
        with server:
            if config["smtp_username"]:
                server.login(config["smtp_username"], config["smtp_password"])
            server.send_message(msg)
        log.status = "SENT"
        log.delivered_at = utcnow()
    except Exception as exc:  # noqa: BLE001 - delivery errors must be logged for admins.
        log.status = "FAILED"
        log.error = str(exc)[:2000]
    return log


def send_workflow_email(user, notification_type, subject, title, subtitle, fields, action_url=None, action_label="Open AstoraSOC", severity=None):
    if not user or not user.email:
        return None
    if getattr(user, "notification_preference", "EMAIL_IN_APP") != "EMAIL_IN_APP":
        return None
    html = render_email_html(title, subtitle, fields, action_url, action_label, severity)
    return send_raw_email(user.email, subject, html, notification_type, user)


def users_for_roles(*roles):
    return [user for user in User.query.filter(User.is_active.is_(True), User.role.in_(roles)).all()]


def alert_review_email(alert):
    action_url = absolute_url("cases.review", view="alerts")
    fields = [
        ("Alert ID", tracking_label(alert)),
        ("Severity", alert.severity),
        ("Rule", alert.title or alert.rule_id),
        ("Rule ID", alert.rule_id),
        ("Affected Asset", alert.asset.hostname if alert.asset else alert.affected_host),
        ("Timestamp", alert.updated_at or alert.created_at),
    ]
    for user in users_for_roles("Lead"):
        send_workflow_email(user, "alert_review_required", "Alert Review Required", "Alert Review Required", "A triaged alert is waiting for Lead validation.", fields, action_url, "Review Alert", alert.severity)


def case_assigned_email(case, assignee, assigned_by):
    action_url = absolute_url("cases.case_detail", case_id=case.id)
    fields = [
        ("Case ID", tracking_label(case)),
        ("Severity", case.severity),
        ("Status", case.status),
        ("Assigned By", assigned_by.full_name if assigned_by else "System"),
        ("Summary", case.title),
    ]
    send_workflow_email(assignee, "case_assigned", "Case Assigned", "Case Assigned", "A case has been assigned for investigation.", fields, action_url, "Open Case", case.severity)


def closure_review_email(case):
    action_url = absolute_url("cases.review_detail", case_id=case.id)
    fields = [("Case ID", tracking_label(case)), ("Severity", case.severity), ("Status", case.status), ("Summary", case.title)]
    for user in users_for_roles("Lead"):
        send_workflow_email(user, "closure_review_requested", "Closure Review Requested", "Closure Review Requested", "An analyst requested closure review.", fields, action_url, "View Investigation", case.severity)


def containment_email(action, subject, title, subtitle, recipients, action_label="View Investigation"):
    case = action.case
    action_url = absolute_url("cases.case_detail", case_id=case.id)
    fields = [
        ("Case ID", tracking_label(case)),
        ("Action ID", action.containment_id),
        ("Action Type", action.action_type.replace("_", " ").title()),
        ("Target", action.target),
        ("Risk", action.risk_level),
        ("Status", action.status.replace("_", " ").title()),
    ]
    for user in recipients:
        send_workflow_email(user, subject.lower().replace(" ", "_"), subject, title, subtitle, fields, action_url, action_label, action.risk_level)


def case_closed_email(case):
    action_url = absolute_url("cases.case_detail", case_id=case.id)
    fields = [("Case ID", tracking_label(case)), ("Severity", case.severity), ("Status", case.status), ("Closure Reason", case.closure_reason or "Closed")]
    recipients = list(case.assigned_users)
    if case.assignee and case.assignee not in recipients:
        recipients.append(case.assignee)
    recipients.extend(users_for_roles("Lead"))
    seen = set()
    for user in recipients:
        if user.id in seen:
            continue
        seen.add(user.id)
        send_workflow_email(user, "case_closed", "Case Closed", "Case Closed", "An AstoraSOC case has been closed.", fields, action_url, "View Investigation", case.severity)
