from functools import wraps

from flask import abort
from flask_login import current_user, login_required

from app.utils import role_allows


def roles_required(*roles):
    def outer(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.is_active or not role_allows(current_user.role, *roles):
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return outer


def case_write_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not role_allows(current_user.role, "Admin", "Lead", "Analyst"):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def case_investigation_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not role_allows(current_user.role, "Analyst"):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper
