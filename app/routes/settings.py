import os
from datetime import date
from pathlib import Path

from flask import Blueprint, current_app, flash, jsonify, render_template, redirect, request, send_file, url_for
from flask_login import current_user

from app import db
from app.audit_retention import archive_logs, cleanup_old_logs, get_retention_settings, logs_for_period, set_retention_settings
from app.ai_catalog import AI_PROVIDERS, default_endpoint, model_label, models_for_provider, provider_label, provider_requires_endpoint, provider_requires_key, valid_model
from app.ai_reports import AIReportError, test_ai_connection
from app.date_filters import active_date_filter, apply_date_filter
from app.decorators import roles_required
from app.email_notifications import email_config, load_email_form, render_email_html, save_email_config, send_raw_email
from app.forms import EmailSettingsForm, SettingsForm
from app.models import AuditLog, EmailDeliveryLog, User, utcnow
from app.system_update import last_system_update_status, run_system_update
from app.utils import audit, decrypt_text, encrypt_text, ensure_webhook_api_key, generate_webhook_api_key, save_upload, set_setting, setting

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings", methods=["GET", "POST"])
@roles_required("Admin")
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        provider = (form.ai_provider.data or "openai").strip()
        model = (form.ai_model.data or "").strip()
        endpoint = (form.ai_endpoint.data or "").strip()
        existing_ai_key = bool(setting("ai_api_key"))
        if not valid_model(provider, model):
            flash("Select a valid AI model for the chosen provider.", "danger")
            return render_template("settings.html", form=form, **settings_template_context())
        if form.ai_enabled.data and provider_requires_endpoint(provider) and not endpoint:
            flash("Custom endpoint is required for the selected AI provider.", "danger")
            return render_template("settings.html", form=form, **settings_template_context())
        if form.ai_enabled.data and provider_requires_key(provider) and not (form.ai_api_key.data or existing_ai_key):
            flash("API key is required before AI report generation can be enabled.", "danger")
            return render_template("settings.html", form=form, **settings_template_context())
        if form.report_template.data:
            try:
                original, stored, _ = save_upload(form.report_template.data, "report_templates")
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("settings.html", form=form, **settings_template_context())
            set_setting("report_template_name", original)
            set_setting("report_template_file", stored)
        set_setting("session_timeout_minutes", form.session_timeout_minutes.data)
        set_setting("ai_reports_enabled", str(bool(form.ai_enabled.data)).lower())
        set_setting("ai_provider", provider)
        set_setting("ai_model", model)
        set_setting("ai_endpoint", endpoint)
        if form.ai_api_key.data:
            set_setting("ai_api_key", encrypt_text(form.ai_api_key.data.strip()))
            audit("ai_api_key_updated", f"AI report API key updated for {provider_label(provider)}.", current_user.id)
        set_retention_settings(
            {
                "login_logout_retention_days": form.login_logout_retention_days.data,
                "failed_login_retention_days": form.failed_login_retention_days.data,
                "case_admin_security_retention_days": form.case_admin_security_retention_days.data,
                "archive_retention_years": form.archive_retention_years.data,
                "enable_auto_archive": form.enable_auto_archive.data,
                "enable_auto_delete": form.enable_auto_delete.data,
            },
            current_user.id,
        )
        audit("settings_updated", "Application settings updated.", current_user.id)
        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("settings.settings"))
    webhook_key, generated = ensure_webhook_api_key(current_user.id)
    if generated:
        db.session.commit()
    form.webhook_api_key.data = webhook_key
    form.ai_enabled.data = setting("ai_reports_enabled", "false") == "true"
    form.ai_provider.data = setting("ai_provider", "openai")
    saved_model = setting("ai_model", "") or ""
    form.ai_model.data = saved_model if valid_model(form.ai_provider.data, saved_model) else models_for_provider(form.ai_provider.data)[0][0]
    form.ai_endpoint.data = setting("ai_endpoint", "")
    form.ai_api_key.data = ""
    form.session_timeout_minutes.data = int(setting("session_timeout_minutes", 30))
    retention = get_retention_settings()
    form.login_logout_retention_days.data = int(retention["login_logout_retention_days"])
    form.failed_login_retention_days.data = int(retention["failed_login_retention_days"])
    form.case_admin_security_retention_days.data = int(retention["case_admin_security_retention_days"])
    form.archive_retention_years.data = int(retention["archive_retention_years"])
    form.enable_auto_archive.data = retention["enable_auto_archive"] == "true"
    form.enable_auto_delete.data = retention["enable_auto_delete"] == "true"
    return render_template("settings.html", form=form, **settings_template_context())


@settings_bp.route("/settings/ai/test", methods=["POST"])
@roles_required("Admin")
def test_ai_settings():
    provider = (request.form.get("ai_provider") or setting("ai_provider", "openai") or "openai").strip()
    model = (request.form.get("ai_model") or setting("ai_model", "") or "").strip()
    if not valid_model(provider, model):
        model = models_for_provider(provider)[0][0]
    endpoint = (request.form.get("ai_endpoint") or setting("ai_endpoint", "") or "").strip()
    raw_key = (request.form.get("ai_api_key") or "").strip()
    encrypted_key = setting("ai_api_key", "")
    api_key = raw_key or (decrypt_text(encrypted_key) if encrypted_key else "")
    try:
        result = test_ai_connection(provider, model, api_key, endpoint)
    except AIReportError as exc:
        audit("ai_connection_test_failed", f"AI connection test failed. Provider={provider_label(provider)} Model={model_label(provider, model)} Error={exc}", current_user.id)
        db.session.commit()
        return jsonify({"ok": False, "message": str(exc), "provider": provider_label(provider), "model": model_label(provider, model)}), 400
    audit("ai_connection_test_success", f"AI connection test succeeded. Provider={result['provider']} Model={result['model']} Latency={result['latency_ms']}ms", current_user.id)
    db.session.commit()
    return jsonify(result)


@settings_bp.route("/settings/webhook/regenerate", methods=["POST"])
@roles_required("Admin")
def regenerate_webhook_key():
    old_key = ensure_webhook_api_key(current_user.id)[0]
    new_key = generate_webhook_api_key()
    while new_key == old_key:
        new_key = generate_webhook_api_key()
    set_setting("webhook_api_key", new_key)
    audit("webhook_api_key_regenerated", "Webhook API key regenerated. Previous key invalidated immediately.", current_user.id)
    db.session.commit()
    flash("Webhook API key regenerated. Old key is no longer valid.", "success")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/settings/update-system", methods=["POST"])
@roles_required("Admin")
def update_system():
    result = run_system_update(current_user.id)
    db.session.commit()
    if result["status"] == "success":
        flash("Update successful.", "success")
    elif result["status"] == "manual_required":
        flash("Backup completed. Docker deployment requires the host update commands shown below.", "warning")
    else:
        flash("Update failed. Review the status details below.", "danger")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/settings/email", methods=["GET", "POST"])
@roles_required("Admin")
def email_settings():
    form = EmailSettingsForm()
    if form.validate_on_submit():
        action = request.form.get("action", "save")
        has_any_config = any([form.smtp_host.data, form.smtp_username.data, form.smtp_password.data, form.from_email.data])
        if form.use_tls.data and form.use_ssl.data:
            flash("Choose either STARTTLS or SSL, not both.", "danger")
            return render_template("email_settings.html", form=form, config=email_config(), logs=EmailDeliveryLog.query.order_by(EmailDeliveryLog.created_at.desc()).limit(50).all(), pending_users=User.query.filter(User.pending_email.isnot(None), User.pending_email != "").order_by(User.full_name).all())
        if (action == "test" or has_any_config) and not (form.smtp_host.data and form.smtp_port.data and form.from_email.data):
            flash("SMTP Host, SMTP Port, and From Email are required for email delivery.", "danger")
            return render_template("email_settings.html", form=form, config=email_config(), logs=EmailDeliveryLog.query.order_by(EmailDeliveryLog.created_at.desc()).limit(50).all(), pending_users=User.query.filter(User.pending_email.isnot(None), User.pending_email != "").order_by(User.full_name).all())
        save_email_config(form)
        audit("email_settings_updated", "Email notification settings updated.", current_user.id)
        db.session.flush()
        if action == "test":
            recipient = (form.test_email.data or current_user.email or "").strip()
            html = render_email_html(
                "AstoraSOC Test Email",
                "SMTP delivery is configured for AstoraSOC workflow notifications.",
                [("SMTP Host", form.smtp_host.data), ("Security", "SSL" if form.use_ssl.data else "STARTTLS" if form.use_tls.data else "Plain"), ("Requested By", current_user.full_name)],
                url_for("settings.email_settings", _external=True),
                "Open Email Settings",
            )
            send_raw_email(recipient, "AstoraSOC Test Email", html, "smtp_test", current_user)
            flash(f"Test email queued for {recipient}. Check delivery logs below.", "success")
        else:
            flash("Email settings saved.", "success")
        db.session.commit()
        return redirect(url_for("settings.email_settings"))
    load_email_form(form)
    logs = EmailDeliveryLog.query.order_by(EmailDeliveryLog.created_at.desc()).limit(50).all()
    pending_users = User.query.filter(User.pending_email.isnot(None), User.pending_email != "").order_by(User.full_name).all()
    return render_template("email_settings.html", form=form, config=email_config(), logs=logs, pending_users=pending_users)


@settings_bp.route("/settings/email/approve/<int:user_id>", methods=["POST"])
@roles_required("Admin")
def approve_profile_email(user_id):
    user = User.query.get_or_404(user_id)
    if not user.pending_email:
        flash("No pending email change for that user.", "info")
        return redirect(url_for("settings.email_settings"))
    duplicate = User.query.filter(User.email == user.pending_email, User.id != user.id).first()
    if duplicate:
        flash("Pending email is already used by another account.", "danger")
        return redirect(url_for("settings.email_settings"))
    old = user.email
    user.email = user.pending_email
    user.pending_email = None
    user.email_verified_at = utcnow()
    audit("profile_email_approved", f"Email changed for {user.username}: {old} -> {user.email}", current_user.id)
    db.session.commit()
    flash("Profile email change approved.", "success")
    return redirect(url_for("settings.email_settings"))


@settings_bp.route("/settings/email/reject/<int:user_id>", methods=["POST"])
@roles_required("Admin")
def reject_profile_email(user_id):
    user = User.query.get_or_404(user_id)
    user.pending_email = None
    audit("profile_email_rejected", f"Pending email rejected for {user.username}.", current_user.id)
    db.session.commit()
    flash("Pending email change rejected.", "success")
    return redirect(url_for("settings.email_settings"))


@settings_bp.route("/audit-logs")
@roles_required("Admin")
def audit_logs():
    page = max(int(request.args.get("page", 1)), 1)
    per_page = 15
    query = AuditLog.query.filter(~AuditLog.action.like("chat_%"))
    query = apply_date_filter(query, AuditLog.created_at, request.args)
    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template("audit_logs.html", logs=logs, page=page, pages=pages, date_filter=active_date_filter(request.args))


@settings_bp.route("/audit-logs/download")
@roles_required("Admin")
def download_audit_logs():
    day_text = request.args.get("date")
    month = int(request.args.get("month") or 0) or None
    year = int(request.args.get("year") or 0) or None
    day = date.fromisoformat(day_text) if day_text else None
    logs = logs_for_period(day=day, month=month, year=year)
    label = day.isoformat() if day else f"{year or 'all'}-{month or 'all'}"
    path, verified = archive_logs(logs, f"manual-{label}", current_user.id)
    db.session.commit()
    if not path or not verified:
        flash("No logs found for that period, or archive verification failed.", "warning")
        return redirect(url_for("settings.audit_logs"))
    return send_file(path, as_attachment=True, download_name=Path(path).name)


@settings_bp.route("/audit-logs/cleanup", methods=["POST"])
@roles_required("Admin")
def manual_audit_cleanup():
    deleted = cleanup_old_logs(current_user.id)
    db.session.commit()
    if deleted:
        flash(f"Cleanup completed. Deleted {deleted} logs after archive verification.", "success")
    else:
        flash("No expired audit logs matched the current retention rules.", "info")
    return redirect(url_for("settings.audit_logs"))


@settings_bp.route("/audit-logs/delete-all", methods=["POST"])
@roles_required("Admin")
def delete_all_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.asc()).all()
    path, verified = archive_logs(logs, "manual-delete-all", current_user.id)
    if not logs:
        flash("No audit logs to delete.", "info")
        return redirect(url_for("settings.audit_logs"))
    if not path or not verified:
        db.session.commit()
        flash("Deletion blocked because archive verification failed.", "danger")
        return redirect(url_for("settings.audit_logs"))
    count = len(logs)
    for log in logs:
        db.session.delete(log)
    audit("audit_logs_deleted_manual", f"Admin deleted all audit logs after archive verification. Count={count}.", current_user.id)
    db.session.commit()
    flash(f"Deleted {count} audit logs after archive verification.", "success")
    return redirect(url_for("settings.audit_logs"))


def settings_template_context():
    provider = setting("ai_provider", "openai") or "openai"
    model = setting("ai_model", "") or ""
    enabled = setting("ai_reports_enabled", "false") == "true"
    key_configured = bool(setting("ai_api_key"))
    endpoint = setting("ai_endpoint", "") or default_endpoint(provider)
    return {
        "report_template": report_template_card(),
        "ai_key_configured": key_configured,
        "ai_saved_enabled": enabled,
        "ai_saved_status": "Enabled" if enabled else "Disabled",
        "ai_saved_key_status": "Saved encrypted" if key_configured else "Not configured",
        "ai_saved_endpoint": endpoint,
        "ai_provider_models": {
            key: [{"value": value, "label": label} for value, label in config["models"]]
            for key, config in AI_PROVIDERS.items()
        },
        "ai_provider_requirements": {
            key: {
                "requires_endpoint": bool(config.get("requires_endpoint")),
                "requires_key": bool(config.get("requires_key", True)),
                "default_endpoint": config.get("endpoint", ""),
            }
            for key, config in AI_PROVIDERS.items()
        },
        "ai_current_provider_label": provider_label(provider),
        "ai_current_model_label": model_label(provider, model),
        "ai_endpoint_default": default_endpoint(provider),
        "system_update_status": last_system_update_status(),
    }


def report_template_card():
    stored = setting("report_template_file")
    original = setting("report_template_name")
    if not stored:
        default_path = os.path.join(current_app.root_path, "static", "templates", "default-report-template.docx")
        if not os.path.exists(default_path):
            return None
        return {
            "name": "Default-template.docx",
            "stored": "default-report-template.docx",
            "exists": True,
            "is_docx": True,
            "is_default": True,
        }
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], "report_templates", stored)
    return {
        "name": original or stored,
        "stored": stored,
        "exists": os.path.exists(path),
        "is_docx": stored.lower().endswith(".docx"),
    }
