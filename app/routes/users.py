import os

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from app import db
from app.decorators import roles_required
from app.forms import ChangePasswordForm, UserForm
from app.models import (
    Alert,
    Asset,
    AuditLog,
    Case,
    CaseAssignment,
    CaseNote,
    ChatMessage,
    ChatReaction,
    ContainmentAction,
    EmailDeliveryLog,
    Evidence,
    IOC,
    Notification,
    PlaybookTemplate,
    Report,
    Task,
    TimelineEvent,
    User,
)
from app.utils import ROLE_DEFINITIONS, add_role, audit, delete_role, expire_stale_user_sessions, role_base, role_config, role_slug, save_upload, set_role_config, user_is_online

users_bp = Blueprint("users", __name__)


@users_bp.route("/users")
@roles_required("Admin", "Lead", "Analyst", "Junior Analyst", "Viewer")
def users():
    if expire_stale_user_sessions():
        db.session.commit()
    role_order = {"Admin": 0, "Lead": 1, "Analyst": 2, "Junior Analyst": 3, "Viewer": 4}
    users = sorted(
        User.query.all(),
        key=lambda user: (
            0 if user_is_online(user) else 1,
            role_order.get(role_base(user.role), 9),
            user.full_name.lower(),
        ),
    )
    return render_template("users/list.html", users=users)


@users_bp.route("/users/roles", methods=["GET", "POST"])
@roles_required("Admin")
def roles():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            created = add_role(request.form.get("role_name"), request.form.get("role_color"), request.form.get("role_preset"), request.form.get("role_permissions"))
            flash("Role created." if created else "Role name already exists or is invalid.", "success" if created else "warning")
        elif action == "delete":
            role = request.form.get("role")
            if delete_role(role):
                User.query.filter_by(role=role).update({"role": "Viewer"})
                flash("Role deleted. Users with that role were moved to Viewer.", "success")
            else:
                flash("System roles cannot be deleted.", "warning")
        else:
            values = {}
            for role, meta in role_config().items():
                slug = role_slug(role)
                icon = meta.get("icon", "")
                file = request.files.get(f"icon_{slug}")
                if file and file.filename:
                    try:
                        _, icon, _ = save_upload(file, "role_icons")
                    except ValueError as exc:
                        flash(str(exc), "danger")
                        return redirect(url_for("users.roles"))
                values[role] = {
                    "color": request.form.get(f"color_{slug}", meta["color"]),
                    "preset": request.form.get(f"preset_{slug}", meta["preset"]),
                    "permissions": request.form.get(f"permissions_{slug}", meta["permissions"]),
                    "icon": icon,
                }
            set_role_config(values)
            flash("Role settings updated.", "success")
        audit("role_settings_updated", "Role settings changed.", current_user.id)
        db.session.commit()
        return redirect(url_for("users.roles"))
    return render_template("users/roles.html", roles=role_config(), presets=ROLE_DEFINITIONS)


@users_bp.route("/uploads/role-icons/<path:filename>")
@roles_required("Admin", "Lead", "Analyst", "Junior Analyst", "Viewer")
def role_icon(filename):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "role_icons")
    return send_from_directory(folder, filename)


@users_bp.route("/users/new", methods=["GET", "POST"])
@roles_required("Admin")
def new_user():
    form = UserForm()
    set_role_choices(form)
    if form.validate_on_submit():
        user = User()
        apply_user_form(user, form)
        if not form.password.data:
            flash("Password is required for new users.", "danger")
            return render_template("users/form.html", form=form, title="New user")
        user.set_password(form.password.data)
        user.force_password_change = True
        db.session.add(user)
        try:
            db.session.flush()
            audit("user_created", f"User {user.username} created.", current_user.id)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Username already exists. Choose another username.", "danger")
            return render_template("users/form.html", form=form, title="New user")
        return redirect(url_for("users.users"))
    return render_template("users/form.html", form=form, title="New user")


@users_bp.route("/users/<int:user_id>")
@roles_required("Admin", "Lead", "Analyst", "Junior Analyst", "Viewer")
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    assigned = Case.query.filter(Case.assignments.any(CaseAssignment.user_id == user.id)).count()
    assigned_label = f"{assigned / 1000:.2f}k" if assigned > 999 else str(assigned)
    return render_template("users/detail.html", user=user, assigned=assigned_label)


@users_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@roles_required("Admin")
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    set_role_choices(form)
    if form.validate_on_submit():
        if user.username == "admin" and form.role.data != "Admin":
            flash("The main super admin cannot be demoted.", "danger")
            return render_template("users/form.html", form=form, title=f"Edit {user.username}")
        apply_user_form(user, form)
        if form.password.data:
            user.set_password(form.password.data)
            user.force_password_change = True
        audit("user_updated", f"User {user.username} updated.", current_user.id)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Username already exists. Choose another username.", "danger")
            return render_template("users/form.html", form=form, title=f"Edit {user.username}")
        return redirect(url_for("users.user_detail", user_id=user.id))
    return render_template("users/form.html", form=form, title=f"Edit {user.username}")


@users_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@roles_required("Admin")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id or user.username == "admin":
        flash("That user cannot be deleted.", "warning")
        return redirect(url_for("users.users"))
    username = user.username
    detach_user_references(user.id)
    db.session.delete(user)
    audit("user_deleted", f"User {username} permanently deleted from the user database.", current_user.id)
    db.session.commit()
    flash("User deleted from the database.", "success")
    return redirect(url_for("users.users"))


def apply_user_form(user, form):
    username = form.username.data.strip()
    user.username = username
    user.role = form.role.data
    user.full_name = user.full_name or username
    user.email = user.email or f"{username}@astorasoc.local"
    user.is_active = True


def set_role_choices(form):
    form.role.choices = [(role, role) for role in role_config()]


def detach_user_references(user_id):
    opts = {"synchronize_session": False}

    Asset.query.filter_by(created_by_id=user_id).update({"created_by_id": None}, **opts)
    Case.query.filter_by(assignee_id=user_id).update({"assignee_id": None}, **opts)
    Case.query.filter_by(created_by_id=user_id).update({"created_by_id": None}, **opts)
    Case.query.filter_by(reviewed_by_id=user_id).update({"reviewed_by_id": None}, **opts)
    Case.query.filter_by(closed_by_id=user_id).update({"closed_by_id": None}, **opts)
    CaseAssignment.query.filter_by(assigned_by_id=user_id).update({"assigned_by_id": None}, **opts)
    CaseAssignment.query.filter_by(user_id=user_id).delete(**opts)

    Alert.query.filter_by(reviewed_by_id=user_id).update({"reviewed_by_id": None}, **opts)
    Alert.query.filter_by(promoted_by_id=user_id).update({"promoted_by_id": None}, **opts)
    IOC.query.filter_by(added_by_id=user_id).update({"added_by_id": None}, **opts)
    Evidence.query.filter_by(uploaded_by_id=user_id).update({"uploaded_by_id": None}, **opts)
    TimelineEvent.query.filter_by(actor_id=user_id).update({"actor_id": None}, **opts)
    CaseNote.query.filter_by(created_by_id=user_id).update({"created_by_id": None}, **opts)
    CaseNote.query.filter_by(updated_by_id=user_id).update({"updated_by_id": None}, **opts)
    Task.query.filter_by(created_by_id=user_id).update({"created_by_id": None}, **opts)
    Task.query.filter_by(completed_by_id=user_id).update({"completed_by_id": None}, **opts)
    PlaybookTemplate.query.filter_by(created_by_id=user_id).update({"created_by_id": None}, **opts)
    PlaybookTemplate.query.filter_by(updated_by_id=user_id).update({"updated_by_id": None}, **opts)

    ContainmentAction.query.filter_by(requested_by_id=user_id).update({"requested_by_id": None}, **opts)
    ContainmentAction.query.filter_by(approved_by_id=user_id).update({"approved_by_id": None}, **opts)
    ContainmentAction.query.filter_by(rejected_by_id=user_id).update({"rejected_by_id": None}, **opts)
    ContainmentAction.query.filter_by(executed_by_id=user_id).update({"executed_by_id": None}, **opts)
    ContainmentAction.query.filter_by(cancelled_by_id=user_id).update({"cancelled_by_id": None}, **opts)
    ContainmentAction.query.filter_by(rolled_back_by_id=user_id).update({"rolled_back_by_id": None}, **opts)

    Report.query.filter_by(generated_by_id=user_id).update({"generated_by_id": None}, **opts)
    AuditLog.query.filter_by(actor_id=user_id).update({"actor_id": None}, **opts)
    EmailDeliveryLog.query.filter_by(recipient_user_id=user_id).update({"recipient_user_id": None}, **opts)
    Notification.query.filter_by(user_id=user_id).delete(**opts)

    message_ids = [message_id for (message_id,) in ChatMessage.query.with_entities(ChatMessage.id).filter_by(sender_id=user_id).all()]
    if message_ids:
        ChatMessage.query.filter(ChatMessage.reply_to_id.in_(message_ids)).update({"reply_to_id": None}, **opts)
        ChatReaction.query.filter(ChatReaction.message_id.in_(message_ids)).delete(**opts)
        ChatMessage.query.filter(ChatMessage.id.in_(message_ids)).delete(**opts)
    ChatReaction.query.filter_by(user_id=user_id).delete(**opts)
