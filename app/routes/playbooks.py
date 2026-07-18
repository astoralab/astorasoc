import json
from io import BytesIO

from flask import Blueprint, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user

from app import db
from app.decorators import roles_required
from app.forms import PlaybookImportForm, PlaybookTemplateForm
from app.models import PlaybookTemplate, Task, utcnow
from app.playbooks import CASE_TYPE_CHOICES, MATCH_LABELS, PLAYBOOK_CATEGORY_CHOICES, playbook_steps, seed_default_playbooks
from app.utils import audit

playbooks_bp = Blueprint("playbooks", __name__, url_prefix="/playbooks")

MITRE_TACTIC_CHOICES = [
    ("Reconnaissance", "Reconnaissance"),
    ("Resource Development", "Resource Development"),
    ("Initial Access", "Initial Access"),
    ("Execution", "Execution"),
    ("Persistence", "Persistence"),
    ("Privilege Escalation", "Privilege Escalation"),
    ("Defense Evasion", "Defense Evasion"),
    ("Credential Access", "Credential Access"),
    ("Discovery", "Discovery"),
    ("Lateral Movement", "Lateral Movement"),
    ("Collection", "Collection"),
    ("Command and Control", "Command and Control"),
    ("Exfiltration", "Exfiltration"),
    ("Impact", "Impact"),
]


@playbooks_bp.route("", methods=["GET", "POST"])
@roles_required("Admin")
def playbooks():
    seed_default_playbooks(current_user.id)
    form = PlaybookTemplateForm()
    import_form = PlaybookImportForm(prefix="import")
    if form.validate_on_submit():
        template = PlaybookTemplate(created_by_id=current_user.id)
        try:
            apply_form(template, form)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("playbooks.playbooks"))
        db.session.add(template)
        audit("playbook_created", f"Playbook {template.name} created.", current_user.id)
        db.session.commit()
        flash("Playbook template created.", "success")
        return redirect(url_for("playbooks.playbooks"))

    search = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    status = (request.args.get("status") or "active").strip()
    sort = (request.args.get("sort") or "priority").strip()
    query = PlaybookTemplate.query
    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(
                PlaybookTemplate.name.ilike(like),
                PlaybookTemplate.description.ilike(like),
                PlaybookTemplate.match_value.ilike(like),
                PlaybookTemplate.tasks_text.ilike(like),
            )
        )
    if category:
        query = query.filter(PlaybookTemplate.category == category)
    if status == "active":
        query = query.filter(PlaybookTemplate.is_active.is_(True), PlaybookTemplate.is_archived.is_(False))
    elif status == "inactive":
        query = query.filter(PlaybookTemplate.is_active.is_(False), PlaybookTemplate.is_archived.is_(False))
    elif status == "archived":
        query = query.filter(PlaybookTemplate.is_archived.is_(True))
    elif status != "all":
        query = query.filter(PlaybookTemplate.is_archived.is_(False))

    if sort == "usage":
        query = query.order_by(PlaybookTemplate.usage_count.desc(), PlaybookTemplate.priority.asc(), PlaybookTemplate.name.asc())
    elif sort == "recent":
        query = query.order_by(PlaybookTemplate.last_applied_at.desc(), PlaybookTemplate.updated_at.desc())
    else:
        query = query.order_by(PlaybookTemplate.is_archived.asc(), PlaybookTemplate.is_active.desc(), PlaybookTemplate.priority.asc(), PlaybookTemplate.name.asc())

    templates = query.all()
    version_counts = {template.id: len(version_history(template)) for template in templates}
    return render_template(
        "playbooks/list.html",
        form=form,
        import_form=import_form,
        templates=templates,
        match_labels=MATCH_LABELS,
        playbook_steps=playbook_steps,
        case_type_choices=CASE_TYPE_CHOICES,
        category_choices=PLAYBOOK_CATEGORY_CHOICES,
        mitre_tactic_choices=MITRE_TACTIC_CHOICES,
        filters={"q": search, "category": category, "status": status, "sort": sort},
        version_counts=version_counts,
    )


@playbooks_bp.route("/<int:template_id>/edit", methods=["GET", "POST"])
@roles_required("Admin")
def edit_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    form = PlaybookTemplateForm(obj=template)
    if request.method == "GET":
        form.is_active.data = template.is_active
    if form.validate_on_submit():
        try:
            apply_form(template, form)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("playbooks.edit_playbook", template_id=template.id))
        audit("playbook_updated", f"Playbook {template.name} updated.", current_user.id)
        db.session.commit()
        flash("Playbook template updated.", "success")
        return redirect(url_for("playbooks.playbooks"))
    return render_template(
        "playbooks/form.html",
        form=form,
        template=template,
        match_labels=MATCH_LABELS,
        case_type_choices=CASE_TYPE_CHOICES,
        category_choices=PLAYBOOK_CATEGORY_CHOICES,
        mitre_tactic_choices=MITRE_TACTIC_CHOICES,
        playbook_steps=playbook_steps,
        template_history=version_history(template),
    )


@playbooks_bp.route("/<int:template_id>/toggle", methods=["POST"])
@roles_required("Admin")
def toggle_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    if template.is_archived:
        flash("Archived playbooks cannot be enabled until restored by editing or cloning.", "error")
        return redirect(url_for("playbooks.playbooks"))
    template.is_active = not template.is_active
    template.updated_by_id = current_user.id
    template.updated_at = utcnow()
    audit("playbook_toggled", f"Playbook {template.name} set to {'active' if template.is_active else 'inactive'}.", current_user.id)
    db.session.commit()
    flash("Playbook status updated.", "success")
    return redirect(url_for("playbooks.playbooks"))


@playbooks_bp.route("/<int:template_id>/clone", methods=["POST"])
@roles_required("Admin")
def clone_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    clone = PlaybookTemplate(
        name=f"Copy of {template.name}"[:120],
        description=template.description,
        category=template.category,
        match_type=template.match_type,
        match_value=template.match_value,
        priority=template.priority,
        is_active=False,
        tasks_text=template.tasks_text,
        created_by_id=current_user.id,
        updated_by_id=current_user.id,
    )
    db.session.add(clone)
    audit("playbook_cloned", f"Playbook {template.name} cloned as {clone.name}.", current_user.id)
    db.session.commit()
    flash("Playbook cloned as inactive draft.", "success")
    return redirect(url_for("playbooks.edit_playbook", template_id=clone.id))


@playbooks_bp.route("/<int:template_id>/archive", methods=["POST"])
@roles_required("Admin")
def archive_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    template.is_archived = True
    template.is_active = False
    template.updated_by_id = current_user.id
    template.updated_at = utcnow()
    audit("playbook_archived", f"Playbook {template.name} archived.", current_user.id)
    db.session.commit()
    flash("Playbook archived.", "success")
    return redirect(url_for("playbooks.playbooks"))


@playbooks_bp.route("/<int:template_id>/export")
@roles_required("Admin")
def export_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    payload = export_payload(template)
    data = json.dumps(payload, indent=2).encode("utf-8")
    filename = f"astorasoc-playbook-{template.name.lower().replace(' ', '-')}.json"
    return send_file(BytesIO(data), mimetype="application/json", as_attachment=True, download_name=filename)


@playbooks_bp.route("/import", methods=["POST"])
@roles_required("Admin")
def import_playbook():
    form = PlaybookImportForm(prefix="import")
    if not form.validate_on_submit():
        flash("Upload a valid playbook JSON file.", "error")
        return redirect(url_for("playbooks.playbooks"))
    try:
        payload = json.load(form.playbook_file.data.stream)
        template = import_payload(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        flash(f"Could not import playbook: {exc}", "error")
        return redirect(url_for("playbooks.playbooks"))
    db.session.add(template)
    audit("playbook_imported", f"Playbook {template.name} imported.", current_user.id)
    db.session.commit()
    flash("Playbook imported as inactive draft.", "success")
    return redirect(url_for("playbooks.edit_playbook", template_id=template.id))


@playbooks_bp.route("/<int:template_id>/delete", methods=["POST"])
@roles_required("Admin")
def delete_playbook(template_id):
    template = PlaybookTemplate.query.get_or_404(template_id)
    name = template.name
    Task.query.filter_by(playbook_template_id=template.id).update({"playbook_template_id": None})
    db.session.delete(template)
    audit("playbook_deleted", f"Playbook {name} deleted.", current_user.id)
    db.session.commit()
    flash("Playbook template deleted.", "success")
    return redirect(url_for("playbooks.playbooks"))


def apply_form(template, form):
    incoming = form_payload(form)
    if template.id:
        remember_version(template)
    template.name = incoming["name"]
    template.category = incoming["category"]
    template.description = incoming["description"]
    template.match_type = incoming["match_type"]
    template.match_value = incoming["match_value"]
    template.priority = incoming["priority"]
    template.is_active = incoming["is_active"]
    template.tasks_text = incoming["tasks_text"]
    template.updated_by_id = current_user.id
    template.updated_at = utcnow()


def form_payload(form):
    match_type = form.match_type.data
    match_value = (form.match_value.data or "").strip()
    valid_match_types = set(MATCH_LABELS)
    valid_categories = {value for value, _label in PLAYBOOK_CATEGORY_CHOICES}
    if match_type not in valid_match_types:
        raise ValueError("Choose a valid playbook match type.")
    if form.category.data not in valid_categories:
        raise ValueError("Choose a valid playbook category.")
    if match_type == "GENERIC":
        match_value = "*"
    elif not match_value:
        raise ValueError("Match value is required unless the playbook is Generic.")
    elif match_type == "CASE_TYPE" and match_value not in {value for value, _label in CASE_TYPE_CHOICES}:
        raise ValueError("Choose a valid Case Type match value.")
    elif match_type == "MITRE_TACTIC" and match_value not in {value for value, _label in MITRE_TACTIC_CHOICES}:
        raise ValueError("Choose a valid MITRE tactic.")

    return {
        "name": form.name.data.strip(),
        "category": form.category.data,
        "description": (form.description.data or "").strip() or None,
        "match_type": match_type,
        "match_value": match_value,
        "priority": form.priority.data,
        "is_active": bool(form.is_active.data),
        "tasks_text": form.tasks_text.data.strip(),
    }


def remember_version(template):
    snapshot = export_payload(template)
    history = []
    if template.version_history:
        try:
            history = json.loads(template.version_history)
        except json.JSONDecodeError:
            history = []
    snapshot["captured_at"] = utcnow().isoformat()
    snapshot["version"] = template.version or 1
    history.append(snapshot)
    template.version_history = json.dumps(history[-20:])
    template.version = (template.version or 1) + 1


def version_history(template):
    if not template.version_history:
        return []
    try:
        history = json.loads(template.version_history)
    except json.JSONDecodeError:
        return []
    return list(reversed(history[-10:]))


def export_payload(template):
    return {
        "name": template.name,
        "description": template.description,
        "category": template.category or "Generic",
        "match_type": template.match_type,
        "match_value": template.match_value,
        "priority": template.priority,
        "is_active": bool(template.is_active),
        "tasks": playbook_steps(template),
        "tasks_text": template.tasks_text,
        "version": template.version or 1,
    }


def import_payload(payload):
    tasks_text = payload.get("tasks_text")
    if not tasks_text and isinstance(payload.get("tasks"), list):
        tasks_text = "\n".join(str(task).strip() for task in payload["tasks"] if str(task).strip())
    fake = type("ImportForm", (), {})()
    fake.name = type("Field", (), {"data": (payload.get("name") or "Imported Playbook")[:120]})()
    fake.category = type("Field", (), {"data": payload.get("category") or "Generic"})()
    fake.description = type("Field", (), {"data": payload.get("description")})()
    fake.match_type = type("Field", (), {"data": payload.get("match_type") or "GENERIC"})()
    fake.match_value = type("Field", (), {"data": payload.get("match_value") or "*"})()
    fake.priority = type("Field", (), {"data": int(payload.get("priority") or 100)})()
    fake.is_active = type("Field", (), {"data": False})()
    fake.tasks_text = type("Field", (), {"data": tasks_text or "Review case details\nGather evidence\nDocument findings\nRequest closure review"})()
    template = PlaybookTemplate(created_by_id=current_user.id, updated_by_id=current_user.id)
    apply_form(template, fake)
    template.is_active = False
    return template
