import json
import os
from datetime import timedelta, timezone

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_
from sqlalchemy.orm import selectinload

from app import db
from app.ai_reports import case_allows_report
from app.asset_matching import link_case_asset
from app.containment import action_label, action_supports_rollback, append_action_history, approve_containment_action, cancel_containment_action, containment_action_id, containment_status_label, execute_manual_containment_action, mark_containment_rolled_back, provider_label, reject_containment_action, validate_containment_input
from app.date_filters import active_date_filter, apply_date_filter
from app.decorators import case_investigation_required, case_write_required, roles_required
from app.email_notifications import case_assigned_email, case_closed_email, closure_review_email, containment_email, users_for_roles
from app.forms import CaseForm, CaseResolutionForm, ContainmentActionForm, EvidenceForm, IOCForm, ManualCaseForm, NoteForm, TaskForm
from app.ioc_intel import canonical_ioc_type, extract_iocs, normalize_ioc, sanitize_ioc_value
from app.models import Alert, Asset, Case, CaseAssignment, CaseNote, ContainmentAction, Evidence, IOC, PlaybookTemplate, Task, User, utcnow
from app.playbooks import active_case_playbook, apply_playbook_to_case
from app.utils import audit, case_is_assigned_to, case_label, create_iocs, ensure_tracking_id, format_short_datetime, ioc_related_counts, local_datetime, mark_notifications, notify_roles, notify_user, role_allows, save_upload, set_case_assignees, timeline, tracking_label
from app.workflow import ALERT_FALSE_POSITIVE, ALERT_PENDING_REVIEW, CASE_ASSIGNED, CASE_CLOSED, CASE_INVESTIGATING, CASE_SUBMITTED_FOR_REVIEW, alert_statuses, case_statuses, status_label

cases_bp = Blueprint("cases", __name__)


def analyst_choices():
    users = [user for user in User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all() if role_allows(user.role, "Analyst")]
    return [(0, "Unassigned")] + [(user.id, f"{user.full_name} ({user.role})") for user in users]


def load_case(case_id):
    case = Case.query.get_or_404(case_id)
    if current_user.is_authenticated and current_user.role == "Analyst" and not case_is_assigned_to(case, current_user):
        abort(403)
    return case


def notify_user_if_other(user_id, category, message, target_url=None):
    if not user_id:
        return
    if current_user.is_authenticated and user_id == current_user.id:
        return
    notify_user(user_id, category, message, target_url)


def populate_case_form(form):
    form.assignee_id.choices = analyst_choices()


def analyst_required_choices():
    return [(user.id, f"{user.full_name} ({user.role})") for user in User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all() if role_allows(user.role, "Analyst")]


def playbook_choices():
    from app.playbooks import seed_default_playbooks

    seed_default_playbooks(current_user.id if current_user.is_authenticated else None)
    templates = PlaybookTemplate.query.filter_by(is_active=True, is_archived=False).order_by(PlaybookTemplate.priority.asc(), PlaybookTemplate.name.asc()).all()
    return [(0, "Auto-match by Case Type")] + [(template.id, f"{template.name} ({template.category})") for template in templates]


def asset_choices():
    assets = Asset.query.order_by(Asset.hostname.asc(), Asset.ip_address.asc()).all()
    return [
        (asset.id, f"{asset.asset_name or asset.hostname or 'Unnamed asset'}{f' / {asset.hostname}' if asset.asset_name and asset.hostname else ''}{f' / {asset.ip_address}' if asset.ip_address else ''} ({asset.criticality})")
        for asset in assets
    ]


def local_due_to_utc(value):
    if not value:
        return None
    return value.replace(tzinfo=timezone(timedelta(hours=5, minutes=30))).astimezone(timezone.utc)


def case_duration_label(start, end=None):
    if not start:
        return ""
    end = end or utcnow()
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    seconds = max(0, int((end - start).total_seconds()))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def first_assignment_time(case):
    times = [assignment.assigned_at for assignment in case.assignments if assignment.assigned_at]
    return min(times) if times else None


def first_response_time(case):
    response_events = ("Investigation started", "Note added", "Evidence uploaded", "Task completed", "IOC added")
    for event in sorted(case.timeline, key=lambda item: item.created_at or utcnow()):
        if event.event_type in response_events:
            return event.created_at
    return None


def case_metrics(case):
    assigned_at = first_assignment_time(case)
    first_response_at = first_response_time(case)
    closed_at = case.closed_at if case.status in case_statuses(CASE_CLOSED) else None
    return [
        {"label": "Case Age", "value": case_duration_label(case.created_at)},
        {"label": "Time To Assignment", "value": case_duration_label(case.created_at, assigned_at) if assigned_at else ""},
        {"label": "Time To First Response", "value": case_duration_label(case.created_at, first_response_at) if first_response_at else ""},
        {"label": "Time To Resolution", "value": case_duration_label(case.created_at, closed_at) if closed_at else ""},
        {"label": "MTTR", "value": case_duration_label(case.created_at, case.closed_at) if case.closed_at else ""},
    ]


def closure_readiness(case):
    has_iocs = bool(case.iocs)
    has_ioc_review = not has_iocs or any(
        text in f"{event.event_type} {event.description}".lower()
        for event in case.timeline
        for text in ("ioc", "indicator", "finding")
    )
    items = [
        ("Evidence Attached", bool(case.evidence), True),
        ("IOC Reviewed", has_ioc_review, False),
        ("Asset Linked", bool(case.asset), True),
        ("Notes Added", bool(case.notes), True),
        ("Root Cause Documented", bool((case.root_cause or "").strip()), True),
        ("Resolution Documented", bool((case.resolution_summary or "").strip()), True),
        ("Lead Approval Completed", bool(case.reviewed_by_id and case.closed_at), False),
    ]
    return [{"label": label, "ready": ready, "required": required} for label, ready, required in items]


def missing_closure_requirements(case):
    return [item["label"] for item in closure_readiness(case) if item["required"] and not item["ready"]]


@cases_bp.route("/cases")
@roles_required("Admin", "Lead", "Analyst")
def cases():
    mark_notifications("cases")
    db.session.commit()
    status = request.args.get("status")
    query = Case.query.options(selectinload(Case.asset))
    if current_user.role == "Analyst":
        query = query.filter(or_(Case.assignee_id == current_user.id, Case.assignments.any(CaseAssignment.user_id == current_user.id)))
    if status:
        query = query.filter_by(status=status)
    asset_id = request.args.get("asset_id", type=int)
    if asset_id:
        query = query.filter(Case.asset_id == asset_id)
    assignee_id = request.args.get("assignee_id", type=int)
    if assignee_id:
        query = query.filter(or_(Case.assignee_id == assignee_id, Case.assignments.any(CaseAssignment.user_id == assignee_id)))
    query = apply_date_filter(query, Case.created_at, request.args)
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Case.tracking_id.ilike(like), Case.public_id.ilike(like), Case.title.ilike(like), Case.rule_id.ilike(like)))
    ioc_value = request.args.get("ioc", "").strip()
    if ioc_value:
        ioc_type = canonical_ioc_type(request.args.get("type", "IP"))
        clean_ioc = sanitize_ioc_value(ioc_type, ioc_value)
        normalized = normalize_ioc(ioc_type, clean_ioc) if clean_ioc else ""
        if normalized:
            matching_case_ids = IOC.query.filter(IOC.normalized_value == normalized, IOC.case_id.isnot(None)).with_entities(IOC.case_id)
            query = query.filter(Case.id.in_(matching_case_ids))
    items = query.order_by(Case.updated_at.desc()).all()
    users = User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all()
    return render_template("cases/list.html", cases=items, status=status, users=users, analysts=analyst_choices(), date_filter=active_date_filter(request.args))


@cases_bp.route("/api/cases/workflow")
@roles_required("Admin", "Lead", "Analyst")
def cases_workflow():
    query = Case.query
    if current_user.role == "Analyst":
        query = query.filter(or_(Case.assignee_id == current_user.id, Case.assignments.any(CaseAssignment.user_id == current_user.id)))
    return {
        "cases": [
            {
                "id": case.id,
                "tracking_id": tracking_label(case),
                "status": case.status,
                "status_label": status_label(case.status),
                "updated": format_short_datetime(case.updated_at),
            }
            for case in query.order_by(Case.updated_at.desc()).limit(100).all()
        ]
    }


@cases_bp.route("/cases/new", methods=["GET", "POST"])
@roles_required("Admin", "Lead")
def new_case():
    form = ManualCaseForm()
    form.assignee_ids.choices = analyst_required_choices()
    form.asset_id.choices = asset_choices()
    form.playbook_id.choices = playbook_choices()
    if request.method == "GET" and not form.due_at.data:
        form.due_at.data = local_datetime(utcnow() + timedelta(days=1)).replace(second=0, microsecond=0, tzinfo=None)
    preview_case_id = tracking_label(None).replace("UNKNOWN", "NEW")
    try:
        from app.utils import generate_tracking_id

        preview_case_id = generate_tracking_id()
    except Exception:
        pass
    if form.validate_on_submit():
        due_at = local_due_to_utc(form.due_at.data)
        if due_at <= utcnow():
            form.due_at.errors.append("Due date must be in the future.")
            return render_template("cases/form.html", form=form, title="Create Case", preview_case_id=preview_case_id, playbook_count=len(form.playbook_id.choices), asset_count=len(form.asset_id.choices), created_preview_at=utcnow(), due_preview_at=due_at)
        asset = Asset.query.get(form.asset_id.data)
        case = Case(
            title=form.title.data,
            description=form.description.data,
            severity=form.severity.data,
            status=CASE_ASSIGNED,
            source="Manual",
            case_type=form.case_type.data,
            incident_type=form.case_type.data,
            due_at=due_at,
            asset_id=asset.id if asset else None,
            affected_host=asset.hostname if asset else None,
            source_ip=asset.ip_address if asset else None,
            created_by_id=current_user.id,
        )
        db.session.add(case)
        db.session.flush()
        ensure_tracking_id(case)
        selected_playbook = PlaybookTemplate.query.get(form.playbook_id.data) if form.playbook_id.data else None
        apply_playbook_to_case(case, actor_id=current_user.id, template=selected_playbook)
        assigned_users = set_case_assignees(case, form.assignee_ids.data, current_user.id)
        if assigned_users:
            case.assignee_id = assigned_users[0].id
        link_case_asset(case)
        explicit_iocs = []
        if asset and asset.hostname:
            explicit_iocs.append(("HOST", asset.hostname))
        if asset and asset.ip_address:
            explicit_iocs.append(("IP", asset.ip_address))
        create_iocs(case=case, values=extract_iocs(" ".join([case.title, case.description or ""])) + explicit_iocs, actor_id=current_user.id, source="Manual case", source_system=case.source)
        due_text = f" Due {format_short_datetime(case.due_at)}." if case.due_at else ""
        timeline(case, "Case created", f"Case manually created and assigned.{due_text}", current_user.id)
        audit("case_created", f"Case {tracking_label(case)} created.", current_user.id)
        for user in assigned_users:
            notify_user(user.id, "cases", f"Case {tracking_label(case)} assigned to you. Due {format_short_datetime(case.due_at)}.", url_for("cases.case_detail", case_id=case.id))
            case_assigned_email(case, user, current_user)
        db.session.commit()
        flash("Case created.", "success")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    return render_template("cases/form.html", form=form, title="Create Case", preview_case_id=preview_case_id, playbook_count=len(form.playbook_id.choices), asset_count=len(form.asset_id.choices), created_preview_at=utcnow(), due_preview_at=local_due_to_utc(form.due_at.data) if form.due_at.data else None)


@cases_bp.route("/cases/<int:case_id>")
@roles_required("Admin", "Lead", "Analyst")
def case_detail(case_id):
    case = load_case(case_id)
    if current_user.role == "Analyst" and case.status == CASE_ASSIGNED:
        case.status = CASE_INVESTIGATING
        timeline(case, "Investigation started", f"{current_user.full_name} opened the assigned case.", current_user.id)
        audit("case_investigation_started", f"Case {tracking_label(case)} moved to investigating.", current_user.id)
        db.session.commit()
    ioc_counts = {ioc.id: ioc_related_counts(ioc) for ioc in case.iocs}
    active_tasks = [task for task in case.tasks if not task.is_complete]
    completed_tasks = [task for task in case.tasks if task.is_complete]
    containment_history = {action.id: json.loads(action.execution_history or "[]") for action in case.containment_actions}
    active_playbook = active_case_playbook(case)
    return render_template(
        "cases/detail.html",
        case=case,
        ioc_counts=ioc_counts,
        evidence_meta=case_evidence_meta(case),
        related_activity=case_related_activity(case),
        related_cases=case_related_cases(case),
        active_tasks=active_tasks,
        completed_tasks=completed_tasks,
        note_form=NoteForm(),
        resolution_form=CaseResolutionForm(obj=case),
        ioc_form=IOCForm(),
        evidence_form=EvidenceForm(),
        task_form=TaskForm(),
        containment_form=ContainmentActionForm(),
        action_label=action_label,
        containment_action_id=containment_action_id,
        containment_status_label=containment_status_label,
        provider_label=provider_label,
        containment_history=containment_history,
        active_playbook=active_playbook,
        case_metrics=case_metrics(case),
        case_times={"assigned_at": first_assignment_time(case), "first_response_at": first_response_time(case)},
        closure_readiness=closure_readiness(case),
        report_available=case_allows_report(case),
        review_mode=False,
    )


@cases_bp.route("/review/cases/<int:case_id>")
@roles_required("Admin", "Lead")
def review_detail(case_id):
    case = load_case(case_id)
    ioc_counts = {ioc.id: ioc_related_counts(ioc) for ioc in case.iocs}
    active_tasks = [task for task in case.tasks if not task.is_complete]
    completed_tasks = [task for task in case.tasks if task.is_complete]
    containment_history = {action.id: json.loads(action.execution_history or "[]") for action in case.containment_actions}
    active_playbook = active_case_playbook(case)
    return render_template(
        "cases/detail.html",
        case=case,
        ioc_counts=ioc_counts,
        evidence_meta=case_evidence_meta(case),
        related_activity=case_related_activity(case),
        related_cases=case_related_cases(case),
        active_tasks=active_tasks,
        completed_tasks=completed_tasks,
        note_form=NoteForm(),
        resolution_form=CaseResolutionForm(obj=case),
        ioc_form=IOCForm(),
        evidence_form=EvidenceForm(),
        task_form=TaskForm(),
        containment_form=ContainmentActionForm(),
        action_label=action_label,
        containment_action_id=containment_action_id,
        containment_status_label=containment_status_label,
        provider_label=provider_label,
        containment_history=containment_history,
        active_playbook=active_playbook,
        case_metrics=case_metrics(case),
        case_times={"assigned_at": first_assignment_time(case), "first_response_at": first_response_time(case)},
        closure_readiness=closure_readiness(case),
        report_available=case_allows_report(case),
        review_mode=True,
    )


@cases_bp.route("/cases/<int:case_id>/edit", methods=["GET", "POST"])
@roles_required("Admin", "Lead")
def edit_case(case_id):
    case = load_case(case_id)
    form = CaseForm(obj=case)
    populate_case_form(form)
    if request.method == "GET":
        form.assignee_id.data = case.assignee_id or 0
    if form.validate_on_submit():
        old_status = case.status
        old_severity = case.severity
        apply_case_form(case, form)
        link_case_asset(case)
        if old_status != case.status:
            timeline(case, "Status changed", f"Status changed from {old_status} to {case.status}.", current_user.id)
        if old_severity != case.severity:
            timeline(case, "Severity changed", f"Severity changed from {old_severity} to {case.severity}.", current_user.id)
        audit("case_updated", f"Case {tracking_label(case)} updated.", current_user.id)
        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    return render_template("cases/form.html", form=form, title=f"Edit case {case_label(case)}")


@cases_bp.route("/cases/<int:case_id>/workflow", methods=["POST"])
@roles_required("Lead")
def case_workflow_action(case_id):
    case = load_case(case_id)
    action = request.form.get("action")
    if action == "assign":
        assignee_ids = request.form.getlist("assignee_ids")
        users = set_case_assignees(case, assignee_ids, current_user.id)
        if users and case.status in case_statuses(CASE_SUBMITTED_FOR_REVIEW):
            case.status = CASE_ASSIGNED
        elif not users:
            case.status = CASE_SUBMITTED_FOR_REVIEW
        for user in users:
            notify_user(user.id, "cases", f"Case {tracking_label(case)} assigned to you.", url_for("cases.case_detail", case_id=case.id))
            case_assigned_email(case, user, current_user)
        timeline(case, "Case assigned", "Case assignment updated from Cases.", current_user.id)
        audit("case_assigned", f"Case {tracking_label(case)} assignment updated.", current_user.id)
        flash("Assignment updated.", "success")
    elif action == "reopen":
        case.status = CASE_INVESTIGATING
        case.closed_at = None
        for assignment in case.assignments:
            notify_user(assignment.user_id, "cases", f"More work requested on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
        timeline(case, "Case reopened", "More work requested from Cases.", current_user.id)
        audit("case_more_work_requested", f"More work requested on case {tracking_label(case)}.", current_user.id)
        flash("Case sent back for more work.", "success")
    else:
        flash("Unsupported case action.", "warning")
    db.session.commit()
    return redirect(url_for("cases.cases", status=request.args.get("status")))


def apply_case_form(case, form):
    for field in [
        "title",
        "description",
        "severity",
        "status",
        "source",
        "incident_type",
        "business_impact",
        "root_cause",
        "resolution_summary",
        "lessons_learned",
        "validation_performed",
        "closure_notes",
        "cve_id",
        "cvss_score",
        "affected_software",
        "affected_version",
        "fixed_version",
        "patch_status",
        "remediation_owner",
        "rule_id",
        "mitre_tactic",
        "mitre_technique",
        "affected_host",
        "affected_user",
        "source_ip",
        "destination_ip",
        "closure_reason",
    ]:
        setattr(case, field, getattr(form, field).data)
    case.assignee_id = form.assignee_id.data or None
    set_case_assignees(case, [case.assignee_id], current_user.id)
    if case.status in case_statuses(CASE_CLOSED) and not case.closed_at:
        case.closed_at = utcnow()
        case.closed_by_id = current_user.id
    if case.status in case_statuses(CASE_SUBMITTED_FOR_REVIEW):
        case.reviewed_by_id = None


@cases_bp.route("/cases/<int:case_id>/resolution", methods=["POST"])
@case_investigation_required
def update_resolution(case_id):
    case = load_case(case_id)
    form = CaseResolutionForm()
    if form.validate_on_submit():
        changed = []
        for field in ["business_impact", "root_cause", "resolution_summary", "lessons_learned", "validation_performed", "closure_notes"]:
            value = (getattr(form, field).data or "").strip()
            if (getattr(case, field) or "") != value:
                setattr(case, field, value)
                changed.append(field.replace("_", " "))
        if changed:
            timeline(case, "Resolution updated", f"Updated {', '.join(changed)}.", current_user.id)
            audit("case_resolution_updated", f"Resolution fields updated on case {tracking_label(case)}: {', '.join(changed)}.", current_user.id)
            db.session.commit()
            flash("Resolution details updated.", "success")
        else:
            flash("No resolution changes to save.", "info")
    else:
        flash("Resolution details could not be saved.", "warning")
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-resolution")


@cases_bp.route("/cases/<int:case_id>/notes", methods=["POST"])
@case_investigation_required
def add_note(case_id):
    case = load_case(case_id)
    form = NoteForm()
    if form.validate_on_submit():
        db.session.add(CaseNote(case=case, body=form.body.data, created_by_id=current_user.id))
        create_iocs(case=case, values=extract_iocs(form.body.data), actor_id=current_user.id, source="Case note", source_system=case.source)
        timeline(case, "Note added", "Investigation note added.", current_user.id)
        audit("note_added", f"Note added to case {tracking_label(case)}.", current_user.id)
        db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-journal")


@cases_bp.route("/cases/<int:case_id>/notes/<int:note_id>/edit", methods=["POST"])
@case_investigation_required
def edit_note(case_id, note_id):
    case = load_case(case_id)
    note = CaseNote.query.filter_by(id=note_id, case_id=case.id).first_or_404()
    if note.created_by_id != current_user.id:
        abort(403)
    new_body = (request.form.get("body") or "").strip()
    if not new_body:
        flash("Note cannot be empty.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-journal")
    history = json.loads(note.edit_history or "[]")
    history.append({
        "edited_at": utcnow().isoformat(),
        "edited_by": current_user.username,
        "previous": note.body[:2000],
    })
    note.body = new_body
    note.updated_by_id = current_user.id
    note.updated_at = utcnow()
    note.is_pinned = bool(request.form.get("is_pinned"))
    note.edit_history = json.dumps(history[-10:])
    timeline(case, "Note updated", "Investigation journal entry updated.", current_user.id)
    audit("note_updated", f"Note updated on case {tracking_label(case)}.", current_user.id)
    db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-journal")


@cases_bp.route("/cases/<int:case_id>/notes/<int:note_id>/delete", methods=["POST"])
@case_investigation_required
def delete_note(case_id, note_id):
    case = load_case(case_id)
    note = CaseNote.query.filter_by(id=note_id, case_id=case.id).first_or_404()
    if note.created_by_id != current_user.id:
        abort(403)
    preview = note.body[:120]
    db.session.delete(note)
    timeline(case, "Note deleted", f"Investigation journal entry deleted: {preview}", current_user.id)
    audit("note_deleted", f"Note deleted from case {tracking_label(case)}.", current_user.id)
    db.session.commit()
    flash("Note deleted.", "success")
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-journal")


@cases_bp.route("/cases/<int:case_id>/iocs", methods=["POST"])
@case_investigation_required
def add_ioc(case_id):
    case = load_case(case_id)
    form = IOCForm()
    if form.validate_on_submit():
        ioc_type = canonical_ioc_type(form.type.data)
        value = sanitize_ioc_value(ioc_type, form.value.data)
        normalized = normalize_ioc(ioc_type, value) if value else ""
        if not normalized:
            flash("Invalid IOC value.", "warning")
            return redirect(url_for("cases.case_detail", case_id=case.id))
        existing = IOC.query.filter_by(case_id=case.id, type=ioc_type, normalized_value=normalized).first()
        if existing:
            existing.last_seen_at = utcnow()
            existing.confidence = form.confidence.data
            existing.source = form.source.data
            existing.tags = form.tags.data
            existing.analyst_notes = form.analyst_notes.data
        else:
            db.session.add(IOC(case=case, type=ioc_type, value=value, normalized_value=normalized, confidence=form.confidence.data, source=form.source.data, source_system=case.source, tags=form.tags.data, analyst_notes=form.analyst_notes.data, added_by_id=current_user.id, first_seen_at=utcnow(), last_seen_at=utcnow()))
        timeline(case, "IOC added", f"{ioc_type} IOC added.", current_user.id)
        audit("ioc_added", f"IOC added to case {tracking_label(case)}.", current_user.id)
        db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/evidence", methods=["POST"])
@case_investigation_required
def add_evidence(case_id):
    case = load_case(case_id)
    form = EvidenceForm()
    if form.validate_on_submit():
        try:
            original, stored, sha256 = save_upload(form.file.data, "evidence")
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-evidence")
        db.session.add(Evidence(case=case, original_filename=original, stored_filename=stored, sha256=sha256, uploaded_by_id=current_user.id))
        evidence_text = read_evidence_text(stored) if evidence_kind(original) == "text" else ""
        extracted = extract_iocs(evidence_text) if evidence_text else []
        if extracted:
            create_iocs(case=case, values=extracted, actor_id=current_user.id, source="Evidence content", source_system=case.source)
        timeline(case, "Evidence uploaded", original, current_user.id)
        audit("evidence_uploaded", f"Evidence uploaded to case {tracking_label(case)}: {original}", current_user.id)
        db.session.commit()
        flash("Evidence uploaded.", "success")
    else:
        flash("Unsupported evidence file.", "danger")
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-evidence")


@cases_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/download")
@login_required
def download_evidence(case_id, evidence_id):
    case = load_case(case_id)
    item = Evidence.query.filter_by(id=evidence_id, case_id=case.id).first_or_404()
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence")
    return send_from_directory(folder, item.stored_filename, as_attachment=True, download_name=item.original_filename)


@cases_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/preview")
@login_required
def preview_evidence(case_id, evidence_id):
    case = load_case(case_id)
    item = Evidence.query.filter_by(id=evidence_id, case_id=case.id).first_or_404()
    if evidence_kind(item.original_filename) not in {"image", "pdf"}:
        abort(404)
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence")
    response = send_from_directory(folder, item.stored_filename, as_attachment=False, download_name=item.original_filename)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@cases_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/delete", methods=["POST"])
@case_write_required
def delete_evidence(case_id, evidence_id):
    case = load_case(case_id)
    item = Evidence.query.filter_by(id=evidence_id, case_id=case.id).first_or_404()
    original = item.original_filename
    stored = item.stored_filename
    db.session.delete(item)
    timeline(case, "Evidence deleted", original, current_user.id)
    audit("evidence_deleted", f"Evidence deleted from case {tracking_label(case)}: {original}", current_user.id)
    db.session.commit()
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence", stored)
    try:
        os.remove(path)
    except OSError:
        pass
    flash("Evidence deleted.", "success")
    return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-evidence")


@cases_bp.route("/iocs/<int:ioc_id>/export")
@login_required
def export_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    if ioc.case_id:
        load_case(ioc.case_id)
    counts = ioc_related_counts(ioc)
    source_alert = ioc.source_alert or ioc.alert
    return jsonify({
        "type": ioc.type,
        "value": sanitize_ioc_value(ioc.type, ioc.value) or ioc.value,
        "normalized_value": ioc.normalized_value,
        "confidence": ioc.confidence,
        "source": ioc.source,
        "source_system": ioc.source_system,
        "source_alert_tracking_id": tracking_label(source_alert) if source_alert else None,
        "first_seen": ioc.first_seen_at.isoformat() if ioc.first_seen_at else None,
        "last_seen": ioc.last_seen_at.isoformat() if ioc.last_seen_at else None,
        "related_cases": counts["cases"],
        "related_alerts": counts["alerts"],
        "occurrences": counts["occurrences"],
        "analyst_notes": ioc.analyst_notes,
    })


@cases_bp.route("/cases/<int:case_id>/containment", methods=["POST"])
@case_investigation_required
def add_containment_action(case_id):
    case = load_case(case_id)
    form = ContainmentActionForm()
    if not form.validate_on_submit():
        flash("Containment action details are required.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    try:
        target, target_host = validate_containment_input(form.action_type.data, form.target.data, form.target_host.data)
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    action = ContainmentAction(
        case=case,
        action_type=form.action_type.data,
        target=target,
        target_host=target_host,
        status="PENDING_APPROVAL",
        asset_id=case.asset_id,
        reason=form.reason.data.strip(),
        notes=form.notes.data.strip() if form.notes.data else None,
        risk_level=form.risk_level.data,
        approval_requirement=form.approval_requirement.data,
        execution_provider="MANUAL",
        requested_by_id=current_user.id,
        rollback_supported=action_supports_rollback(form.action_type.data),
    )
    db.session.add(action)
    db.session.flush()
    action.containment_id = f"CA-{action.id:06d}"
    append_action_history(action, current_user, "Requested", action.reason)
    timeline(case, "Containment action requested", f"{action.containment_id} {action_label(action.action_type)} requested for {action.target} ({containment_status_label(action.status)}).", current_user.id)
    audit("containment_action_requested", f"{action.containment_id} {action_label(action.action_type)} requested on case {tracking_label(case)} for {action.target}; risk {action.risk_level}; status {action.status}; approval {action.approval_requirement}; provider {action.execution_provider}.", current_user.id)
    if action.status == "PENDING_APPROVAL":
        notify_roles(("Admin", "Lead"), "cases", f"{action.containment_id} needs approval on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
        containment_email(action, "Containment Approval Required", "Containment Approval Required", "A containment action requires Lead approval.", users_for_roles("Lead", "Admin"), "Approve Request")
    elif action.status == "APPROVED":
        notify_roles(("Admin", "Lead"), "cases", f"{action.containment_id} is approved for manual execution on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
    db.session.commit()
    flash(f"Containment action {containment_status_label(action.status).lower()}.", "success")
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/containment/<int:action_id>/decision", methods=["POST"])
@case_write_required
def containment_decision(case_id, action_id):
    case = load_case(case_id)
    if not role_allows(current_user.role, "Lead"):
        abort(403)
    action = ContainmentAction.query.filter_by(id=action_id, case_id=case.id).first_or_404()
    decision = request.form.get("decision")
    notes = (request.form.get("notes") or "").strip()
    if action.status not in {"PENDING_APPROVAL", "APPROVED"}:
        flash("This containment action cannot be changed from its current status.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    if decision == "approve":
        approve_containment_action(action, current_user, notes)
        event = "Containment action approved"
        audit_action = "containment_action_approved"
    elif decision == "reject":
        if not notes:
            flash("Rejection notes are required.", "warning")
            return redirect(url_for("cases.case_detail", case_id=case.id))
        reject_containment_action(action, current_user, notes)
        event = "Containment action rejected"
        audit_action = "containment_action_rejected"
    elif decision == "cancel":
        cancel_containment_action(action, current_user, notes)
        event = "Containment action cancelled"
        audit_action = "containment_action_cancelled"
    else:
        flash("Unsupported containment decision.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    timeline(case, event, f"{containment_action_id(action)} {action_label(action.action_type)} for {action.target}: {containment_status_label(action.status)}.", current_user.id)
    audit(audit_action, f"{containment_action_id(action)} {action_label(action.action_type)} on case {tracking_label(case)} is {action.status}. Notes: {notes or '-'}", current_user.id)
    if decision == "approve":
        notify_user_if_other(action.requested_by_id, "cases", f"{containment_action_id(action)} approved on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
        notify_roles(("Admin", "Lead"), "cases", f"{containment_action_id(action)} is ready for execution on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
        containment_email(action, "Containment Approved", "Containment Approved", "A containment action has been approved.", [action.requested_by] if action.requested_by else [], "View Investigation")
    elif decision == "reject":
        notify_user_if_other(action.requested_by_id, "cases", f"{containment_action_id(action)} rejected on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
        containment_email(action, "Containment Rejected", "Containment Rejected", "A containment action was rejected.", [action.requested_by] if action.requested_by else [], "View Investigation")
    elif decision == "cancel":
        notify_user_if_other(action.requested_by_id, "cases", f"{containment_action_id(action)} cancelled on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
    db.session.commit()
    flash(containment_status_label(action.status), "success")
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/containment/<int:action_id>/execute", methods=["POST"])
@case_write_required
def execute_containment(case_id, action_id):
    case = load_case(case_id)
    if not role_allows(current_user.role, "Admin", "Lead"):
        abort(403)
    action = ContainmentAction.query.filter_by(id=action_id, case_id=case.id).first_or_404()
    if action.status not in {"APPROVED", "QUEUED", "FAILED"}:
        flash("Only approved containment actions can be executed.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    result = (request.form.get("execution_result") or "").strip()
    if not result:
        flash("Execution result is required.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    succeeded = request.form.get("result_status") != "failed"
    execute_manual_containment_action(action, current_user, result, succeeded=succeeded)
    timeline(case, "Containment action executed" if succeeded else "Containment action failed", f"{containment_action_id(action)} {action_label(action.action_type)} for {action.target}: {containment_status_label(action.status)}.", current_user.id)
    audit("containment_action_executed" if succeeded else "containment_action_failed", f"{containment_action_id(action)} {action_label(action.action_type)} on case {tracking_label(case)} finished with {action.status}. Result: {result[:500]}", current_user.id)
    notify_user_if_other(action.requested_by_id, "cases", f"{containment_action_id(action)} {'executed' if succeeded else 'failed'} on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
    db.session.commit()
    flash(f"Containment action {containment_status_label(action.status).lower()}.", "success" if succeeded else "warning")
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/containment/<int:action_id>/rollback", methods=["POST"])
@case_write_required
def rollback_containment(case_id, action_id):
    case = load_case(case_id)
    if not role_allows(current_user.role, "Admin", "Lead"):
        abort(403)
    action = ContainmentAction.query.filter_by(id=action_id, case_id=case.id).first_or_404()
    if action.status != "EXECUTED" or not action.rollback_supported:
        flash("This containment action cannot be rolled back.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    result = (request.form.get("rollback_result") or "").strip()
    mark_containment_rolled_back(action, current_user, result)
    timeline(case, "Containment action rolled back", f"{containment_action_id(action)} {action_label(action.action_type)} rollback for {action.target}: {action.rollback_status}.", current_user.id)
    audit("containment_action_rollback", f"{containment_action_id(action)} {action_label(action.action_type)} rollback on case {tracking_label(case)} finished with {action.rollback_status}. Result: {result[:500] or '-'}", current_user.id)
    notify_user_if_other(action.requested_by_id, "cases", f"{containment_action_id(action)} rolled back on case {tracking_label(case)}.", url_for("cases.case_detail", case_id=case.id))
    db.session.commit()
    flash("Containment action rolled back.", "success")
    return redirect(url_for("cases.case_detail", case_id=case.id))


def read_evidence_text(stored_filename):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence")
    path = os.path.join(folder, stored_filename)
    try:
        if os.path.getsize(path) > 1024 * 1024:
            return ""
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", errors="ignore")
    except OSError:
        return ""


def evidence_kind(filename):
    ext = (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    if ext in {"png", "jpg", "jpeg", "webp", "gif"}:
        return "image"
    if ext == "pdf":
        return "pdf"
    if ext in {"txt", "log", "csv", "json"}:
        return "text"
    return "file"


def format_bytes(size):
    if size is None:
        return "Unknown"
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def case_evidence_meta(case):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "evidence")
    meta = {}
    for item in case.evidence:
        path = os.path.join(folder, item.stored_filename)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = None
        kind = evidence_kind(item.original_filename)
        meta[item.id] = {
            "size": size,
            "size_label": format_bytes(size),
            "kind": kind,
            "previewable": kind in {"image", "pdf"},
        }
    return meta


def case_related_activity(case):
    related = []
    if case.rule_id:
        count = Case.query.filter(Case.id != case.id, Case.rule_id == case.rule_id).count()
        if count:
            related.append({"label": "Same Rule ID", "value": case.rule_id, "count": count})
    if case.affected_host:
        count = Case.query.filter(Case.id != case.id, Case.affected_host == case.affected_host).count()
        if count:
            related.append({"label": "Same Host", "value": case.affected_host, "count": count})
    if case.affected_user:
        count = Case.query.filter(Case.id != case.id, Case.affected_user == case.affected_user).count()
        if count:
            related.append({"label": "Same Username", "value": case.affected_user, "count": count})
    if case.source_ip:
        count = Case.query.filter(Case.id != case.id, Case.source_ip == case.source_ip).count()
        if count:
            related.append({"label": "Same Source IP", "value": case.source_ip, "count": count})
    normalized_iocs = [ioc.normalized_value for ioc in case.iocs if ioc.normalized_value]
    if normalized_iocs:
        count = (
            IOC.query.filter(IOC.case_id.isnot(None), IOC.case_id != case.id, IOC.normalized_value.in_(normalized_iocs))
            .with_entities(IOC.case_id)
            .distinct()
            .count()
        )
        if count:
            related.insert(0, {"label": "Same IOC", "value": "Shared indicators", "count": count})
    return related[:5]


def case_related_cases(case, limit=6):
    filters = []
    if case.asset_id:
        filters.append(Case.asset_id == case.asset_id)
    if case.rule_id:
        filters.append(Case.rule_id == case.rule_id)
    if case.affected_host:
        filters.append(Case.affected_host == case.affected_host)
    if case.affected_user:
        filters.append(Case.affected_user == case.affected_user)
    if getattr(case, "cve_id", None):
        filters.append(Case.cve_id == case.cve_id)
    ioc_values = [ioc.normalized_value for ioc in case.iocs if ioc.normalized_value]
    ioc_case_ids = []
    if ioc_values:
        ioc_case_ids = [
            row[0]
            for row in IOC.query.filter(IOC.case_id.isnot(None), IOC.case_id != case.id, IOC.normalized_value.in_(ioc_values))
            .with_entities(IOC.case_id)
            .distinct()
            .limit(limit)
            .all()
        ]
    if ioc_case_ids:
        filters.append(Case.id.in_(ioc_case_ids))
    if not filters:
        return []
    return Case.query.filter(Case.id != case.id, or_(*filters)).order_by(Case.updated_at.desc()).limit(limit).all()


@cases_bp.route("/cases/<int:case_id>/tasks", methods=["POST"])
@case_investigation_required
def add_task(case_id):
    case = load_case(case_id)
    form = TaskForm()
    if form.validate_on_submit():
        db.session.add(Task(case=case, title=form.title.data, source="Analyst", created_by_id=current_user.id))
        timeline(case, "Task added", form.title.data, current_user.id)
        audit("task_added", f"Task added to case {tracking_label(case)}.", current_user.id)
        db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/tasks/<int:task_id>/edit", methods=["POST"])
@case_investigation_required
def edit_task(case_id, task_id):
    case = load_case(case_id)
    task = Task.query.filter_by(id=task_id, case_id=case.id).first_or_404()
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Task title is required.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    old_title = task.title
    task.title = title[:180]
    if task.source != "Auto":
        task.source = "Analyst"
    timeline(case, "Task updated", f"{old_title} -> {task.title}", current_user.id)
    audit("task_updated", f"Task #{task.id} updated on case {tracking_label(case)}.", current_user.id)
    db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/tasks/<int:task_id>/toggle", methods=["POST"])
@case_investigation_required
def toggle_task(case_id, task_id):
    case = load_case(case_id)
    task = Task.query.filter_by(id=task_id, case_id=case.id).first_or_404()
    task.is_complete = not task.is_complete
    task.completed_by_id = current_user.id if task.is_complete else None
    task.completed_at = utcnow() if task.is_complete else None
    if task.is_complete:
        timeline(case, "Task completed", task.title, current_user.id)
    else:
        timeline(case, "Task reopened", task.title, current_user.id)
    audit("task_toggled", f"Task #{task.id} toggled on case {tracking_label(case)}.", current_user.id)
    db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/tasks/<int:task_id>/delete", methods=["POST"])
@case_investigation_required
def delete_task(case_id, task_id):
    case = load_case(case_id)
    task = Task.query.filter_by(id=task_id, case_id=case.id).first_or_404()
    title = task.title
    db.session.delete(task)
    timeline(case, "Task deleted", title, current_user.id)
    audit("task_deleted", f"Task deleted from case {tracking_label(case)}.", current_user.id)
    db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/cases/<int:case_id>/submit", methods=["POST"])
@case_investigation_required
def submit_review(case_id):
    case = load_case(case_id)
    missing = missing_closure_requirements(case)
    if missing:
        flash("Closure review is not ready. Complete: " + ", ".join(missing) + ".", "warning")
        return redirect(url_for("cases.case_detail", case_id=case.id) + "#case-resolution")
    case.status = CASE_SUBMITTED_FOR_REVIEW
    notify_roles(("Admin", "Lead"), "review", f"Case {tracking_label(case)} is ready for closure review.", url_for("cases.review_detail", case_id=case.id))
    closure_review_email(case)
    timeline(case, "Review requested", "Analyst requested closure review.", current_user.id)
    audit("case_submitted", f"Case {tracking_label(case)} submitted for review.", current_user.id)
    db.session.commit()
    return redirect(url_for("cases.case_detail", case_id=case.id))


@cases_bp.route("/review", methods=["GET", "POST"])
@roles_required("Admin", "Lead")
def review():
    mark_notifications("review")
    if request.method == "GET":
        db.session.commit()
    if request.method == "POST":
        if not role_allows(current_user.role, "Lead"):
            abort(403)
        if request.form.get("alert_id"):
            alert = Alert.query.get_or_404(int(request.form["alert_id"]))
            action = request.form["action"]
            if action == "create_case":
                from app.routes.alerts import promote_alert

                case = promote_alert(alert)
                for assignment in case.assignments:
                    notify_user(assignment.user_id, "cases", f"Case {tracking_label(case)} assigned to you.", url_for("cases.case_detail", case_id=case.id))
                    case_assigned_email(case, assignment.user, current_user)
                db.session.commit()
                return redirect(url_for("cases.case_detail", case_id=case.id))
            if action == "false_positive":
                reason = request.form.get("reason", "").strip()
                if not reason:
                    flash("False positive reason is required.", "warning")
                    return redirect(url_for("cases.review", view=request.args.get("view", "all")))
                alert.status = ALERT_FALSE_POSITIVE
                alert.task_plan = reason
                alert.reviewed_by_id = current_user.id
                audit("alert_false_positive_review", f"Alert {tracking_label(alert)} closed false positive. Reason: {reason or '-'}", current_user.id)
                db.session.commit()
                return redirect(url_for("cases.review", view=request.args.get("view", "all")))
        case = load_case(int(request.form["case_id"]))
        action = request.form["action"]
        if action == "assign":
            assignee_ids = request.form.getlist("assignee_ids") or request.form.getlist("assignee_id")
            users = set_case_assignees(case, assignee_ids, current_user.id)
            case.status = CASE_ASSIGNED if users else CASE_SUBMITTED_FOR_REVIEW
            for user in users:
                notify_user(user.id, "cases", f"Case {tracking_label(case)} assigned to you.", url_for("cases.case_detail", case_id=case.id))
                case_assigned_email(case, user, current_user)
            timeline(case, "Case assigned", "Case assignment updated.", current_user.id)
        elif action == "false_positive":
            case.status = CASE_CLOSED
            case.closure_reason = "False Positive"
            case.closed_by_id = current_user.id
            case.closed_at = utcnow()
            timeline(case, "Case closed", "Marked as false positive.", current_user.id)
            case_closed_email(case)
        elif action == "approve_close":
            missing = missing_closure_requirements(case)
            if missing:
                flash("Closure blocked. Complete: " + ", ".join(missing) + ".", "warning")
                return redirect(url_for("cases.review_detail", case_id=case.id))
            case.status = CASE_CLOSED
            case.reviewed_by_id = current_user.id
            case.closed_by_id = current_user.id
            case.closed_at = utcnow()
            timeline(case, "Case closed", "Lead approved closure.", current_user.id)
            case_closed_email(case)
        elif action == "reopen":
            case.status = CASE_INVESTIGATING
            case.closed_at = None
            timeline(case, "Case reopened", "Case reopened for more work.", current_user.id)
        elif action == "escalate":
            case.severity = "Critical"
            timeline(case, "Severity changed", "Case escalated to Critical.", current_user.id)
        elif action == "severity":
            new_severity = request.form.get("severity")
            if new_severity in {"Low", "Medium", "High", "Critical"}:
                old = case.severity
                case.severity = new_severity
                timeline(case, "Severity changed", f"Severity changed from {old} to {new_severity}.", current_user.id)
        elif action == "merge":
            target_id = int(request.form.get("target_case_id") or 0)
            target = Case.query.get(target_id) if target_id and target_id != case.id else None
            if not target:
                flash("Choose a valid target case to merge into.", "danger")
                return redirect(url_for("cases.review", view=request.args.get("view", "all")))
            merge_case(case, target)
            timeline(target, "Case merged", f"Case {tracking_label(case)} merged into this case.", current_user.id)
            timeline(case, "Case closed", f"Merged into case {tracking_label(target)}.", current_user.id)
        audit("case_review_action", f"{action} on case {tracking_label(case)}.", current_user.id)
        db.session.commit()
        return redirect(url_for("cases.review", view=request.args.get("view", "all")))
    view = request.args.get("view", "all")
    if view not in {"all", "alerts", "cases"}:
        view = "all"
    review_statuses = case_statuses(CASE_SUBMITTED_FOR_REVIEW)
    items = Case.query.options(selectinload(Case.asset)).filter(Case.status.in_(review_statuses)).order_by(Case.updated_at.desc()).all()
    alert_items = Alert.query.options(selectinload(Alert.asset)).filter(Alert.status.in_(alert_statuses(ALERT_PENDING_REVIEW))).order_by(Alert.updated_at.desc()).all()
    users = User.query.filter(User.is_active.is_(True)).order_by(User.full_name).all()
    return render_template("cases/review.html", cases=items, alerts=alert_items, analysts=analyst_choices(), view=view, users=users)


def merge_case(source, target):
    for collection in [source.alerts, source.iocs, source.evidence, source.notes, source.tasks]:
        for item in list(collection):
            item.case_id = target.id
    source.status = CASE_CLOSED
    source.closure_reason = f"Merged duplicate into case {tracking_label(target)}."
    source.closed_by_id = current_user.id
    source.closed_at = utcnow()
