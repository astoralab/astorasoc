import os

from flask import Blueprint, current_app, flash, redirect, render_template, send_from_directory, url_for
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app import db
from app.forms import ProfileForm
from app.models import Case, CaseAssignment, User
from app.utils import audit, save_upload

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/profile")
@login_required
def profile():
    assigned = Case.query.filter(Case.assignments.any(CaseAssignment.user_id == current_user.id)).count()
    assigned_label = f"{assigned / 1000:.2f}k" if assigned > 999 else str(assigned)
    return render_template("profile/detail.html", user=current_user, assigned=assigned_label)


@profile_bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        requested_email = (form.email.data or "").strip()
        email_owner = User.query.filter(User.email == requested_email, User.id != current_user.id).first()
        if email_owner:
            flash("That email is already used by another account.", "danger")
            return render_template("profile/form.html", form=form)
        pending_owner = User.query.filter(User.pending_email == requested_email, User.id != current_user.id).first()
        if pending_owner:
            flash("That email is already pending approval for another account.", "danger")
            return render_template("profile/form.html", form=form)
        for field in ["full_name", "phone", "department", "job_title", "organization"]:
            setattr(current_user, field, getattr(form, field).data)
        if requested_email != current_user.email:
            current_user.pending_email = requested_email
            audit("profile_email_change_requested", f"User requested email change to {requested_email}.", current_user.id)
            flash("Profile saved. Email change is pending administrator approval.", "info")
        else:
            current_user.pending_email = None
        if getattr(form.profile_picture.data, "filename", ""):
            try:
                _, stored, _ = save_upload(form.profile_picture.data, "profiles")
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("profile/form.html", form=form)
            current_user.profile_picture = stored
        audit("profile_updated", "User updated own profile.", current_user.id)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Profile could not be saved because one of the values is already used.", "danger")
            return render_template("profile/form.html", form=form)
        flash("Profile updated.", "success")
        return redirect(url_for("profile.profile"))
    if form.errors:
        flash("Profile was not saved. Please fix the highlighted fields.", "danger")
    return render_template("profile/form.html", form=form)


@profile_bp.route("/uploads/profiles/<path:filename>")
@login_required
def profile_picture(filename):
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], "profiles")
    return send_from_directory(folder, filename)
