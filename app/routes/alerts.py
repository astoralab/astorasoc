import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_
from sqlalchemy.orm import selectinload

from app import db
from app.alert_normalizer import normalize_alert
from app.asset_matching import link_alert_asset, link_case_asset
from app.date_filters import active_date_filter, apply_date_filter
from app.decorators import roles_required
from app.email_notifications import alert_review_email, case_assigned_email
from app.ioc_intel import canonical_ioc_type, extract_iocs, normalize_ioc, sanitize_ioc_value
from app.models import Alert, Case, IOC, Task, User, utcnow
from app.playbooks import apply_playbook_to_case
from app.utils import audit, create_iocs, ensure_tracking_id, mark_notifications, notify_roles, role_allows, set_case_assignees, timeline, tracking_label
from app.workflow import ALERT_FALSE_POSITIVE, ALERT_NEW, ALERT_PENDING_REVIEW, ALERT_PROMOTED, CASE_ASSIGNED, CASE_SUBMITTED_FOR_REVIEW, alert_statuses, status_label

alerts_bp = Blueprint("alerts", __name__)
ALERT_PAGE_SIZE = 40


def analyst_choices():
    users = [user for user in User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all() if role_allows(user.role, "Analyst")]
    return [(0, "Unassigned")] + [(user.id, f"{user.full_name} ({user.role})") for user in users]


def load_alert(alert_id):
    return Alert.query.get_or_404(alert_id)


@alerts_bp.route("/alerts", methods=["GET", "POST"])
@roles_required("Admin", "Lead", "Junior Analyst")
def alerts():
    mark_notifications("alerts")
    if request.method == "GET":
        db.session.commit()
    if request.method == "POST":
        alert = load_alert(int(request.form["alert_id"]))
        action = request.form["action"]
        if action == "severity":
            if not role_allows(current_user.role, "Lead", "Junior Analyst"):
                abort(403)
            new_severity = request.form.get("severity")
            if new_severity in {"Low", "Medium", "High", "Critical"}:
                alert.severity = new_severity
                alert.reviewed_by_id = current_user.id
                audit("alert_severity_updated", f"Alert {tracking_label(alert)} severity set to {new_severity}.", current_user.id)
        elif action == "task_plan":
            if not role_allows(current_user.role, "Lead", "Junior Analyst"):
                abort(403)
            alert.task_plan = request.form.get("task_plan", "").strip()
            alert.reviewed_by_id = current_user.id
            audit("alert_task_plan_updated", f"Alert {tracking_label(alert)} task plan updated.", current_user.id)
        elif action == "false_positive":
            if not role_allows(current_user.role, "Lead", "Junior Analyst"):
                abort(403)
            reason = request.form.get("reason", "").strip()
            if not reason:
                flash("Reason is required.", "warning")
                return redirect(url_for("alerts.alerts"))
            alert.status = ALERT_FALSE_POSITIVE
            alert.task_plan = reason
            alert.reviewed_by_id = current_user.id
            audit("alert_false_positive", f"Alert {tracking_label(alert)} marked false positive. Reason: {reason or '-'}", current_user.id)
        elif action == "submit_review":
            if not role_allows(current_user.role, "Lead", "Junior Analyst"):
                abort(403)
            reason = request.form.get("reason", "").strip()
            if not reason:
                flash("Review comment is required.", "warning")
                return redirect(url_for("alerts.alerts"))
            alert.status = ALERT_PENDING_REVIEW
            alert.reviewed_by_id = current_user.id
            alert.task_plan = reason
            notify_roles(("Admin", "Lead"), "review", f"Alert {tracking_label(alert)} was sent to review.", url_for("cases.review"))
            alert_review_email(alert)
            audit("alert_submitted_review", f"Alert {tracking_label(alert)} sent to review.", current_user.id)
        elif action == "create_case":
            if not role_allows(current_user.role, "Lead"):
                abort(403)
            case = promote_alert(alert)
            for assignment in case.assignments:
                case_assigned_email(case, assignment.user, current_user)
            db.session.commit()
            flash(f"Alert promoted to case {tracking_label(case)}.", "success")
            return redirect(url_for("cases.case_detail", case_id=case.id))
        alert.updated_at = utcnow()
        db.session.commit()
        return redirect(url_for("alerts.alerts"))

    status = request.args.get("status", ALERT_NEW)
    query = Alert.query.options(selectinload(Alert.iocs), selectinload(Alert.asset))
    asset_id = request.args.get("asset_id", type=int)
    if asset_id:
        query = query.filter(Alert.asset_id == asset_id)
    if status:
        query = query.filter(Alert.status.in_(alert_statuses(status)))
    query = apply_date_filter(query, Alert.created_at, request.args)
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Alert.tracking_id.ilike(like), Alert.title.ilike(like), Alert.event_id.ilike(like), Alert.rule_id.ilike(like)))
    ioc_value = request.args.get("ioc", "").strip()
    if ioc_value:
        ioc_type = canonical_ioc_type(request.args.get("type", "IP"))
        clean_ioc = sanitize_ioc_value(ioc_type, ioc_value)
        normalized = normalize_ioc(ioc_type, clean_ioc) if clean_ioc else ""
        if normalized:
            matching_alert_ids = IOC.query.filter(IOC.normalized_value == normalized, IOC.alert_id.isnot(None)).with_entities(IOC.alert_id)
            query = query.filter(Alert.id.in_(matching_alert_ids))
    page = max(request.args.get("page", 1, type=int), 1)
    total = query.count()
    items = (
        query.order_by(Alert.updated_at.desc(), Alert.created_at.desc())
        .limit(ALERT_PAGE_SIZE)
        .offset((page - 1) * ALERT_PAGE_SIZE)
        .all()
    )
    linked_any = False
    for alert in items:
        if not alert.asset_id and link_alert_asset(alert):
            linked_any = True
    if linked_any:
        db.session.commit()
    has_prev = page > 1
    has_next = page * ALERT_PAGE_SIZE < total
    return render_template(
        "alerts/list.html",
        alerts=items,
        alert_context=build_alert_context(items),
        analysts=analyst_choices(),
        status=status,
        page=page,
        page_size=ALERT_PAGE_SIZE,
        total=total,
        has_prev=has_prev,
        has_next=has_next,
        date_filter=active_date_filter(request.args),
    )


@alerts_bp.route("/api/alerts/workflow")
@roles_required("Admin", "Lead", "Junior Analyst")
def alerts_workflow():
    return {
        "alerts": [
            {
                "id": alert.id,
                "tracking_id": tracking_label(alert),
                "status": alert.status,
                "status_label": status_label(alert.status),
                "updated": alert.updated_at.isoformat() if alert.updated_at else alert.created_at.isoformat(),
            }
            for alert in Alert.query.order_by(Alert.updated_at.desc(), Alert.created_at.desc()).limit(100).all()
        ]
    }


def build_alert_context(alerts):
    return {alert.id: alert_detail_context(alert) for alert in alerts}


def alert_detail_context(alert):
    raw = alert.raw_json if isinstance(alert.raw_json, dict) else {}
    normalized = raw.get("normalized") if isinstance(raw.get("normalized"), dict) else normalize_alert(raw)
    raw_alert = raw.get("raw_alert") if isinstance(raw.get("raw_alert"), dict) else {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    if not rule:
        rule = raw_alert.get("rule") if isinstance(raw_alert.get("rule"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    if not data:
        data = raw_alert.get("data") if isinstance(raw_alert.get("data"), dict) else {}
    event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    mitre = rule.get("mitre") or data.get("mitre") or raw.get("mitre") or raw_alert.get("mitre") or {}
    if not isinstance(mitre, dict):
        mitre = {}
    raw_text = json.dumps(raw, indent=2, sort_keys=True, default=str)
    stored_iocs = list(alert.iocs[:16])
    preview_iocs = [] if stored_iocs else extract_iocs(alert.description or "")[:8]
    return {
        "normalized": normalized,
        "source": normalized.get("source") or alert.source,
        "detection_name": normalized.get("rule_name") or alert.title,
        "rule_id": normalized.get("rule_id") or alert.rule_id,
        "host": normalized.get("host") or alert.affected_host,
        "username": normalized.get("username") or alert.affected_user,
        "source_ip": normalized.get("source_ip") or alert.source_ip,
        "destination_ip": normalized.get("destination_ip") or alert.destination_ip,
        "mitre_tactic": normalized.get("mitre_tactic") or alert.mitre_tactic,
        "mitre_technique": normalized.get("mitre_technique") or alert.mitre_technique,
        "event_timestamp": event.get("timestamp") or raw.get("timestamp"),
        "full_log": raw.get("full_log") or raw_alert.get("full_log") or alert.description or "Not Available",
        "raw_json": raw_text,
        "mitre_tactics": mitre_values(mitre.get("tactic") or mitre.get("tactics") or alert.mitre_tactic),
        "mitre_techniques": mitre_values(mitre.get("technique") or mitre.get("techniques") or alert.mitre_technique),
        "mitre_ids": mitre_values(mitre.get("id") or mitre.get("ids")),
        "iocs": preview_iocs,
        "stored_iocs": stored_iocs,
        "ioc_counts": {},
        "history": [],
    }


def mitre_values(value):
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if value in (None, ""):
        return []
    return [str(value)]


def promote_alert(alert):
    if alert.case_id:
        return alert.case

    assignee_ids = request.form.getlist("assignee_ids") or request.form.getlist("assignee_id")
    case = Case(
        tracking_id=ensure_tracking_id(alert),
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=CASE_SUBMITTED_FOR_REVIEW,
        source=alert.source,
        rule_id=alert.rule_id,
        affected_host=alert.affected_host,
        affected_user=alert.affected_user,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        mitre_tactic=alert.mitre_tactic,
        mitre_technique=alert.mitre_technique,
        created_by_id=current_user.id,
    )
    db.session.add(case)
    db.session.flush()
    case.public_id = case.tracking_id
    case.asset_id = alert.asset_id
    link_case_asset(case)
    users = set_case_assignees(case, assignee_ids, current_user.id)
    case.status = CASE_ASSIGNED if users else CASE_SUBMITTED_FOR_REVIEW
    alert.case_id = case.id
    alert.status = ALERT_PROMOTED
    alert.promoted_by_id = current_user.id
    alert.reviewed_by_id = current_user.id

    playbook, generated_tasks = apply_playbook_to_case(case, alert=alert, actor_id=current_user.id)
    task_plan = (request.form.get("task_plan") or alert.task_plan or "").strip()
    alert.task_plan = task_plan
    for line in task_plan.splitlines():
        title = line.strip(" -\t")
        if title:
            db.session.add(Task(case=case, title=title[:180], source="Analyst", created_by_id=current_user.id))

    explicit_iocs = []
    if alert.source_ip:
        explicit_iocs.append(("IP", alert.source_ip))
    if alert.destination_ip:
        explicit_iocs.append(("IP", alert.destination_ip))
    if alert.affected_host:
        explicit_iocs.append(("Hostname", alert.affected_host))
    if alert.affected_user:
        explicit_iocs.append(("Username", alert.affected_user))
    create_iocs(case=case, values=extract_iocs(str(alert.raw_json)) + explicit_iocs, source="Alert triage", alert=alert, source_system=alert.source)
    for ioc in alert.iocs:
        create_iocs(case=case, values=[(ioc.type, ioc.value)], source=ioc.source or "Alert triage", alert=alert, source_system=ioc.source_system or alert.source)
    timeline(case, "Alert received", f"{alert.source} alert {tracking_label(alert)} received for investigation.", alert.reviewed_by_id or current_user.id)
    timeline(case, "Case created from alert", f"Alert {tracking_label(alert)} promoted by {current_user.role}.", current_user.id)
    playbook_name = playbook.name if playbook else "No playbook"
    audit("alert_promoted", f"Alert {tracking_label(alert)} promoted to case {tracking_label(case)} with playbook {playbook_name} ({len(generated_tasks)} tasks).", current_user.id)
    return case
