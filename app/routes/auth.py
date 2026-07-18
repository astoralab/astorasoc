from datetime import timedelta

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, limiter
from app.forms import ChangePasswordForm, LoginForm
from app.models import User, utcnow
from app.utils import audit, setting

auth_bp = Blueprint("auth", __name__)


@auth_bp.before_app_request
def require_password_change():
    if not current_user.is_authenticated:
        return None
    allowed = {"auth.change_password", "auth.logout", "live.live_state", "static"}
    timeout_minutes = int(setting("session_timeout_minutes", 5))
    last_seen = session.get("last_activity")
    now = utcnow()
    if last_seen:
        last_seen = now.fromisoformat(last_seen)
        if now - last_seen > timedelta(minutes=timeout_minutes):
            current_user.session_active = False
            current_user.last_seen_at = now
            audit("session_timeout", "User session expired.", current_user.id)
            db.session.commit()
            logout_user()
            session.clear()
            if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
                return jsonify({"error": "session_expired"}), 401
            flash("Session timed out. Please sign in again.", "warning")
            return redirect(url_for("auth.login"))
    passive_poll = (
        (request.path.startswith("/api/") and request.args.get("active") != "1")
        or (request.endpoint == "chats.chats" and request.args.get("partial") == "stream")
    )
    if passive_poll:
        return None
    session["last_activity"] = now.isoformat()
    current_user.last_seen_at = now
    if current_user.force_password_change and request.endpoint not in allowed:
        db.session.commit()
        if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "password_change_required"}), 403
        flash("Change the default password before continuing.", "warning")
        return redirect(url_for("auth.change_password"))
    if not current_user.session_active:
        current_user.session_active = True
    db.session.commit()
    return None


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.is_active and user.check_password(form.password.data):
            now = utcnow()
            user.last_login_at = now
            user.last_seen_at = now
            user.session_active = True
            login_user(user)
            session["last_activity"] = now.isoformat()
            audit("login", "User signed in.", user.id)
            db.session.commit()
            return redirect(url_for("dashboard.dashboard"))
        audit("login_failed", f"Failed login for {form.username.data}")
        db.session.commit()
        flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    current_user.session_active = False
    current_user.last_seen_at = utcnow()
    audit("logout", "User signed out.", current_user.id)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.force_password_change and not current_user.check_password(form.current_password.data or ""):
            flash("Current password is incorrect.", "danger")
            return render_template("profile/change_password.html", form=form)
        current_user.set_password(form.password.data)
        current_user.force_password_change = False
        audit("password_changed", "User changed password.", current_user.id)
        db.session.commit()
        flash("Password changed.", "success")
        return redirect(url_for("dashboard.dashboard"))
    return render_template("profile/change_password.html", form=form)
