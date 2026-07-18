import json
import secrets

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from app import csrf, db, limiter
from app.alert_normalizer import normalize_alert
from app.asset_matching import link_alert_asset
from app.models import Alert
from app.ioc_intel import extract_iocs
from app.utils import audit, configured_webhook_api_key, create_iocs, ensure_tracking_id, notify_roles, tracking_label, webhook_api_key_is_insecure
from app.workflow import ALERT_NEW

webhook_bp = Blueprint("webhook", __name__)


@webhook_bp.route("/api/webhook/alert", methods=["POST"])
@csrf.exempt
@limiter.limit("30 per minute")
def alert_webhook():
    api_key = configured_webhook_api_key()
    provided_key = request.headers.get("X-API-Key", "")
    if webhook_api_key_is_insecure(api_key) or not provided_key or not secrets.compare_digest(provided_key, api_key):
        return reject_webhook("webhook_alert_unauthorized", "Unauthorized webhook alert request.", "unauthorized", 401)

    if not request.is_json:
        return reject_webhook("webhook_alert_invalid", "Rejected webhook alert with non-JSON content.", "json_required", 415)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not payload:
        return reject_webhook("webhook_alert_invalid", "Rejected webhook alert with invalid JSON object.", "invalid_json", 400)

    try:
        parsed = parse_alert(payload)
        duplicate = find_duplicate_alert(parsed["event_id"])
        if duplicate:
            audit("webhook_alert_duplicate", f"Duplicate webhook alert event {parsed['event_id']} matched alert {tracking_label(duplicate)}.")
            db.session.commit()
            return jsonify({"alert_id": duplicate.id, "tracking_id": tracking_label(duplicate), "case_id": duplicate.case_id, "duplicate": True}), 200

        alert = Alert(
            title=parsed["title"],
            description=parsed["description"],
            severity=parsed["severity"],
            status=ALERT_NEW,
            source=parsed["source"],
            event_id=parsed["event_id"],
            rule_id=parsed["rule_id"],
            affected_host=parsed["affected_host"],
            affected_user=parsed["affected_user"],
            source_ip=parsed["source_ip"],
            destination_ip=parsed["destination_ip"],
            mitre_tactic=parsed["mitre_tactic"],
            mitre_technique=parsed["mitre_technique"],
            raw_json=payload,
        )
        db.session.add(alert)
        db.session.flush()
        link_alert_asset(alert)
        ensure_tracking_id(alert)
        explicit_iocs = []
        if parsed["source_ip"]:
            explicit_iocs.append(("IP", parsed["source_ip"]))
        if parsed["destination_ip"]:
            explicit_iocs.append(("IP", parsed["destination_ip"]))
        if parsed["affected_host"]:
            explicit_iocs.append(("Hostname", parsed["affected_host"]))
        if parsed["affected_user"]:
            explicit_iocs.append(("Username", parsed["affected_user"]))
        create_iocs(
            alert=alert,
            values=extract_iocs(json.dumps(payload, default=str)) + explicit_iocs,
            source="Webhook alert",
            source_system=alert.source,
        )
        notify_roles(("Admin", "Lead", "Junior Analyst"), "alerts", f"New {alert.severity} alert {tracking_label(alert)} from {alert.source}.", "/alerts")
        audit("webhook_alert_received", f"Alert {tracking_label(alert)} received from {alert.source}.")
        db.session.commit()
        return jsonify({"alert_id": alert.id, "tracking_id": tracking_label(alert), "case_id": None, "status": alert.status, "duplicate": False}), 201
    except (SQLAlchemyError, ValueError, TypeError, AttributeError):
        db.session.rollback()
        current_app.logger.exception("Webhook alert processing failed")
        return jsonify({"error": "processing_failed"}), 500


def reject_webhook(action, details, error, status):
    audit(action, details)
    db.session.commit()
    return jsonify({"error": error}), status


def parse_alert(payload):
    normalized = normalize_alert(payload)
    payload["normalized"] = {key: value for key, value in normalized.items() if key != "raw_alert"}
    return {
        "event_id": normalized["event_id"],
        "title": normalized["title"],
        "description": normalized["description"],
        "severity": normalized["severity"],
        "source": normalized["source"],
        "rule_id": normalized["rule_id"] or "",
        "affected_host": normalized["host"],
        "affected_user": normalized["username"],
        "source_ip": normalized["source_ip"],
        "destination_ip": normalized["destination_ip"],
        "mitre_tactic": normalized["mitre_tactic"],
        "mitre_technique": normalized["mitre_technique"],
    }


def as_dict(value):
    return value if isinstance(value, dict) else {}


def clean_optional(value, limit):
    if value in (None, ""):
        return None
    return str(value)[:limit]


def first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


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
        text = str(value or "Medium").title()
        return text if text in {"Low", "Medium", "High", "Critical"} else "Medium"


def find_duplicate_alert(event_id):
    if not event_id:
        return None
    return (
        Alert.query.filter(Alert.event_id == event_id)
        .order_by(Alert.created_at.desc())
        .first()
    )
