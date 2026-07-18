from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from app import db
from app.models import Notification, User
from app.utils import expire_stale_user_sessions, user_is_online

live_bp = Blueprint("live", __name__)


@live_bp.route("/api/live/state")
@login_required
def live_state():
    changed = expire_stale_user_sessions()
    if changed:
        db.session.commit()
    categories = ("cases", "alerts", "review", "chats")
    return jsonify(
        {
            "unread_counts": {
                category: Notification.query.filter_by(user_id=current_user.id, category=category, read_at=None).count()
                for category in categories
            },
            "online_users": {str(user.id): user_is_online(user) for user in User.query.all()},
        }
    )
