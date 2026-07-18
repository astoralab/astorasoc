from datetime import timedelta

from flask import Blueprint, jsonify, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import func, or_
from sqlalchemy.orm import selectinload

from app import db
from app.date_filters import active_date_filter, apply_date_filter, date_filter_label, has_date_filter
from app.ioc_intel import ioc_type_label
from app.models import Alert, Asset, Case, ContainmentAction, IOC, TimelineEvent, User
from app.utils import format_short_datetime, tracking_label
from app.workflow import (
    CASE_ASSIGNED,
    CASE_CLOSED,
    CASE_INVESTIGATING,
    CASE_SUBMITTED_FOR_REVIEW,
    PERIODS,
    SEVERITY_LABELS,
    case_statuses,
    alert_statuses,
    normalize_period,
    period_cutoff,
    status_label,
)

dashboard_bp = Blueprint("dashboard", __name__)


CASE_STATUS_ORDER = [
    (CASE_ASSIGNED, "Assigned"),
    (CASE_INVESTIGATING, "Investigating"),
    (CASE_SUBMITTED_FOR_REVIEW, "Pending Review"),
    (CASE_CLOSED, "Closed"),
    ("FALSE_POSITIVE", "False Positive"),
]


def scoped(query, model, period, args=None):
    if has_date_filter(args or {}):
        return apply_date_filter(query, model.created_at, args or {})
    cutoff = period_cutoff(period)
    if cutoff is None:
        return apply_date_filter(query, model.created_at, args or {})
    return apply_date_filter(query.filter(model.created_at >= cutoff), model.created_at, args or {})


def previous_scoped(query, model, period):
    period = normalize_period(period)
    delta = PERIODS[period][1]
    if not delta:
        return None
    cutoff = period_cutoff(period)
    return query.filter(model.created_at >= cutoff - delta, model.created_at < cutoff)


def count_cases(period, args=None, status=None, severity=None, open_only=False):
    query = scoped(Case.query, Case, period, args)
    if status:
        query = query.filter(Case.status.in_(case_statuses(status)))
    if severity:
        query = query.filter(Case.severity == severity)
    if open_only:
        query = query.filter(~Case.status.in_(case_statuses(CASE_CLOSED)))
    return query.count()


def count_false_positive_cases(period, args=None):
    return scoped(Case.query, Case, period, args).filter(or_(Case.closure_reason.ilike("%false positive%"), Case.status == "False Positive")).count()


def count_closed_cases(period, args=None):
    return (
        scoped(Case.query, Case, period, args)
        .filter(Case.status.in_(case_statuses(CASE_CLOSED)))
        .filter(Case.status != "False Positive")
        .filter(or_(Case.closure_reason.is_(None), ~Case.closure_reason.ilike("%false positive%")))
        .count()
    )


def trend_for(period, current, model=Case, status=None, open_only=False, args=None):
    if has_date_filter(args or {}):
        return {"direction": "flat", "value": "Filtered"}
    query = previous_scoped(model.query, model, period)
    if query is None:
        return {"direction": "flat", "value": "All time"}
    if status and model is Case:
        query = query.filter(Case.status.in_(case_statuses(status)))
    if status and model is Alert:
        query = query.filter(Alert.status.in_(alert_statuses(status)))
    if open_only and model is Case:
        query = query.filter(~Case.status.in_(case_statuses(CASE_CLOSED)))
    previous = query.count()
    change = current - previous
    direction = "up" if change > 0 else "down" if change < 0 else "flat"
    return {"direction": direction, "value": f"{change:+d}"}


def average_duration(items):
    values = [seconds for seconds in items if seconds is not None and seconds >= 0]
    if not values:
        return None
    return sum(values) / len(values)


def duration_label(seconds):
    if seconds is None:
        return "-"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    remaining = minutes % 60
    if hours < 48:
        return f"{hours}h {remaining}m"
    days = hours // 24
    return f"{days}d {hours % 24}h"


def mttd_seconds(period, args=None):
    alerts = (
        scoped(Alert.query.filter(Alert.case_id.isnot(None)), Alert, period, args)
        .join(Case, Alert.case_id == Case.id)
        .with_entities(Alert.created_at, Case.created_at)
        .all()
    )
    return average_duration([(case_created - alert_created).total_seconds() for alert_created, case_created in alerts if alert_created and case_created])


def mttr_seconds(period, args=None):
    cases = (
        scoped(Case.query.filter(Case.closed_at.isnot(None)), Case, period, args)
        .with_entities(Case.created_at, Case.closed_at)
        .all()
    )
    return average_duration([(closed_at - created_at).total_seconds() for created_at, closed_at in cases if created_at and closed_at])


def list_rows(query, limit=5):
    return [{"label": label or "Not Available", "value": int(value or 0)} for label, value in query.limit(limit).all()]


def top_rules(period, args=None):
    rows = (
        scoped(Alert.query, Alert, period, args)
        .with_entities(Alert.title, Alert.source, Alert.rule_id, func.count(Alert.id))
        .group_by(Alert.title, Alert.source, Alert.rule_id)
        .order_by(func.count(Alert.id).desc(), Alert.title.asc())
        .limit(6)
        .all()
    )
    items = []
    for title, source, rule_id, count in rows:
        detection = title or rule_id or "Unnamed detection"
        query = rule_id or detection
        items.append({
            "detection": detection,
            "source": source or "Custom",
            "rule_id": rule_id or "",
            "count": int(count or 0),
            "alerts_url": url_for("alerts.alerts", status="", q=query),
            "cases_url": url_for("cases.cases", q=query),
        })
    return items


def affected_assets(period, args=None):
    from app.routes.assets import asset_risk_score

    assets = Asset.query.options(selectinload(Asset.alerts), selectinload(Asset.cases)).all()
    rows = []
    for asset in assets:
        risk = asset_risk_score(asset)
        open_alerts = sum(1 for alert in asset.alerts if alert.status in alert_statuses("NEW") + alert_statuses("PENDING_REVIEW"))
        open_cases = sum(1 for case in asset.cases if not case.status in case_statuses(CASE_CLOSED) and case.status != "False Positive")
        if open_alerts or open_cases or risk["score"] > 0:
            rows.append({
                "id": asset.id,
                "name": asset.asset_name or asset.hostname or asset.ip_address or "Unnamed asset",
                "criticality": asset.criticality or "Medium",
                "open_alerts": open_alerts,
                "open_cases": open_cases,
                "risk_score": risk["score"],
                "risk_label": risk["label"],
                "risk_tone": risk["tone"],
                "asset_url": url_for("assets.asset_detail", asset_id=asset.id),
                "alerts_url": url_for("alerts.alerts", status="", asset_id=asset.id),
                "cases_url": url_for("cases.cases", asset_id=asset.id),
            })
    rows.sort(key=lambda row: (-row["risk_score"], -row["open_cases"], -row["open_alerts"], row["name"].lower()))
    return rows[:6]


def asset_metrics():
    active_alert_asset_ids = [
        row[0]
        for row in db.session.query(Alert.asset_id)
        .filter(Alert.asset_id.isnot(None), Alert.status.in_(alert_statuses("NEW") + alert_statuses("PENDING_REVIEW")))
        .distinct()
        .all()
    ]
    open_case_asset_ids = [
        row[0]
        for row in db.session.query(Case.asset_id)
        .filter(Case.asset_id.isnot(None), ~Case.status.in_(case_statuses(CASE_CLOSED)))
        .distinct()
        .all()
    ]
    high_risk = (
        Asset.query.filter(or_(Asset.criticality == "Critical", Asset.id.in_(open_case_asset_ids or [0]), Asset.id.in_(active_alert_asset_ids or [0])))
        .distinct()
        .count()
    )
    return {
        "total_assets": Asset.query.count(),
        "critical_assets": Asset.query.filter(Asset.criticality == "Critical").count(),
        "high_risk_assets": high_risk,
        "assets_with_open_cases": len(open_case_asset_ids),
        "assets_with_active_alerts": len(active_alert_asset_ids),
    }


def ioc_overview(period, args=None):
    cutoff = period_cutoff(period)
    base = IOC.query
    if cutoff is not None and not has_date_filter(args or {}):
        base = base.filter(IOC.added_at >= cutoff)
    base = apply_date_filter(base, IOC.added_at, args or {})
    by_type = list_rows(
        base.with_entities(IOC.type, func.count(IOC.id))
        .group_by(IOC.type)
        .order_by(func.count(IOC.id).desc(), IOC.type.asc()),
        6,
    )
    for row in by_type:
        row["label"] = ioc_type_label(row["label"])
    return {
        "total": base.count(),
        "high_confidence": base.filter(IOC.confidence == "High").count(),
        "linked_to_cases": base.filter(IOC.case_id.isnot(None)).count(),
        "by_type": by_type,
    }


def containment_metrics(period, args=None):
    base = scoped(ContainmentAction.query, ContainmentAction, period, args)
    return {
        "pending": base.filter(ContainmentAction.status == "PENDING_APPROVAL").count(),
        "approved": base.filter(ContainmentAction.status == "APPROVED").count(),
        "executed": base.filter(ContainmentAction.status == "EXECUTED").count(),
        "failed": base.filter(ContainmentAction.status == "FAILED").count(),
        "rolled_back": base.filter(ContainmentAction.status == "ROLLED_BACK").count(),
    }


def analyst_workload(period, args=None):
    users = [user for user in User.query.filter(User.is_active.is_(True)).order_by(User.full_name.asc()).all()]
    rows = []
    for user in users:
        base = scoped(Case.query, Case, period, args).filter(
            or_(Case.assignee_id == user.id, Case.assignments.any(user_id=user.id))
        )
        assigned = base.filter(Case.status.in_(case_statuses(CASE_ASSIGNED))).count()
        investigating = base.filter(Case.status.in_(case_statuses(CASE_INVESTIGATING))).count()
        pending = base.filter(Case.status.in_(case_statuses(CASE_SUBMITTED_FOR_REVIEW))).count()
        total = assigned + investigating + pending
        if total:
            rows.append({
                "id": user.id,
                "name": user.full_name or user.username,
                "assigned": assigned,
                "investigating": investigating,
                "pending_review": pending,
                "total": total,
                "cases_url": url_for("cases.cases", assignee_id=user.id),
            })
    rows.sort(key=lambda row: (-row["total"], row["name"].lower()))
    return rows[:6]


def recent_activity(period, args=None):
    interesting = [
        "Case created",
        "Case created from alert",
        "Review requested",
        "Containment action requested",
        "Containment action approved",
        "Containment action rejected",
        "Containment action executed",
        "Containment action failed",
        "Containment action rolled back",
        "Case closed",
        "Case false positive",
    ]
    events = (
        scoped(TimelineEvent.query, TimelineEvent, period, args)
        .filter(TimelineEvent.event_type.in_(interesting))
        .order_by(TimelineEvent.created_at.desc())
        .limit(8)
        .all()
    )
    return [
        {
            "kind": event.event_type,
            "case": tracking_label(event.case),
            "description": event.description,
            "time": format_short_datetime(event.created_at),
            "severity": event.case.severity if event.case else "Medium",
            "status": status_label(event.case.status) if event.case else "Unknown",
        }
        for event in events
    ]


def analytics_payload(period, args=None):
    period = normalize_period(period)
    open_cases = count_cases(period, args, open_only=True)
    pending_review = count_cases(period, args, CASE_SUBMITTED_FOR_REVIEW)
    assigned = count_cases(period, args, CASE_ASSIGNED)
    investigating = count_cases(period, args, CASE_INVESTIGATING)
    false_positive = count_false_positive_cases(period, args)
    closed = count_closed_cases(period, args)
    case_total = count_cases(period, args)
    mttd = mttd_seconds(period, args)
    mttr = mttr_seconds(period, args)

    cards = {
        "open_cases": {"value": open_cases, "trend": trend_for(period, open_cases, open_only=True, args=args)},
        "pending_review": {"value": pending_review, "trend": trend_for(period, pending_review, status=CASE_SUBMITTED_FOR_REVIEW, args=args)},
        "assigned": {"value": assigned, "trend": trend_for(period, assigned, status=CASE_ASSIGNED, args=args)},
        "investigating": {"value": investigating, "trend": trend_for(period, investigating, status=CASE_INVESTIGATING, args=args)},
        "closed": {"value": closed, "trend": trend_for(period, closed, status=CASE_CLOSED, args=args)},
        "false_positive": {"value": false_positive, "trend": {"direction": "flat", "value": "Case FP"}},
        "mttd": {"value": duration_label(mttd), "trend": {"direction": "flat", "value": "Mean detect"}},
        "mttr": {"value": duration_label(mttr), "trend": {"direction": "flat", "value": "Mean respond"}},
    }
    severity_series = [count_cases(period, args, severity=label) for label in SEVERITY_LABELS]
    status_labels = [label for _, label in CASE_STATUS_ORDER]
    status_series = [false_positive if status == "FALSE_POSITIVE" else closed if status == CASE_CLOSED else count_cases(period, args, status) for status, _ in CASE_STATUS_ORDER]
    containment = containment_metrics(period, args)
    iocs = ioc_overview(period, args)
    assets = asset_metrics()

    return {
        "period": period,
        "period_label": date_filter_label(args or {}) or PERIODS[period][0],
        "cards": cards,
        "case_total": case_total,
        "severity": {"labels": SEVERITY_LABELS, "series": severity_series},
        "status": {"labels": status_labels, "series": status_series},
        "top_rules": top_rules(period, args),
        "affected_assets": affected_assets(period, args),
        "iocs": iocs,
        "containment": containment,
        "assets": assets,
        "workload": analyst_workload(period, args),
        "activity": recent_activity(period, args),
    }


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    period = normalize_period(request.args.get("period", "all"))
    return render_template("dashboard.html", analytics=analytics_payload(period, request.args), periods=PERIODS, active_period=period, date_filter=active_date_filter(request.args))


@dashboard_bp.route("/api/dashboard/threat-analytics")
@login_required
def threat_analytics():
    period = normalize_period(request.args.get("period", "all"))
    return jsonify(analytics_payload(period, request.args))
