import os
import re
from datetime import date

from flask import Flask, jsonify, render_template, request
from flask_login import current_user
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFError
from sqlalchemy import inspect, text
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from app.security import get_client_ip

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_client_ip)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    if app.config.get("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=3, x_proto=1, x_host=1, x_port=1)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    @limiter.request_filter
    def skip_low_risk_assets_and_polls():
        endpoint = request.endpoint or ""
        if endpoint == "healthz":
            return True
        if endpoint == "static" or request.path.startswith(("/uploads/", "/chats/emojis/")):
            return True
        if request.method == "GET" and endpoint in {
            "live.live_state",
            "dashboard.threat_analytics",
            "cases.cases_workflow",
            "alerts.alerts_workflow",
        }:
            return True
        return request.method == "GET" and endpoint == "chats.chats" and request.args.get("partial") == "stream"

    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "login_required"}), 401
        from flask import redirect, url_for

        return redirect(url_for("auth.login", next=request.full_path if request.query_string else request.path))

    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.cases import cases_bp
    from app.routes.alerts import alerts_bp
    from app.routes.chats import chats_bp
    from app.routes.assets import assets_bp
    from app.routes.playbooks import playbooks_bp
    from app.routes.users import users_bp
    from app.routes.profile import profile_bp
    from app.routes.reports import reports_bp
    from app.routes.webhook import webhook_bp
    from app.routes.settings import settings_bp
    from app.routes.live import live_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(chats_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(playbooks_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(webhook_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(live_bp)

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.get("/healthz")
    def healthz():
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ok", "database": "ok"}), 200
        except Exception:
            app.logger.exception("Health check failed")
            db.session.rollback()
            return jsonify({"status": "error", "database": "unavailable"}), 503

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    @app.context_processor
    def inject_brand_assets():
        img_dir = os.path.join(app.static_folder, "img")
        from app.ioc_intel import ioc_type_class, ioc_type_label, sanitize_ioc_value
        from app.utils import due_state, format_chat_time, format_short_datetime, local_datetime, relative_time, role_allows, role_config, tracking_label, user_is_online
        from app.workflow import status_label

        return {
            "has_logo": os.path.exists(os.path.join(img_dir, "logo.png")),
            "has_light_logo": os.path.exists(os.path.join(img_dir, "logo-light.png")),
            "has_favicon": os.path.exists(os.path.join(img_dir, "favicon.png")),
            "role_styles": role_config(),
            "role_allows": role_allows,
            "user_is_online": user_is_online,
            "local_datetime": local_datetime,
            "format_chat_time": format_chat_time,
            "format_short_datetime": format_short_datetime,
            "due_state": due_state,
            "relative_time": relative_time,
            "tracking_label": tracking_label,
            "sanitize_ioc_value": sanitize_ioc_value,
            "ioc_type_class": ioc_type_class,
            "ioc_type_label": ioc_type_label,
            "status_label": status_label,
        }

    @app.context_processor
    def inject_notifications():
        if not current_user.is_authenticated:
            return {"unread_counts": {}}
        from app.models import Notification

        categories = ["cases", "alerts", "review", "chats"]
        active_sections = {
            "cases": request.endpoint in {"cases.cases", "cases.case_detail"},
            "alerts": request.endpoint == "alerts.alerts",
            "review": request.endpoint in {"cases.review", "cases.review_detail"},
            "chats": request.endpoint == "chats.chats",
        }
        return {
            "unread_counts": {
                category: 0 if active_sections.get(category) else Notification.query.filter_by(user_id=current_user.id, category=category, read_at=None).count()
                for category in categories
            }
        }

    @app.before_request
    def run_lightweight_audit_schedule():
        from app.audit_retention import run_scheduled_retention

        run_lightweight_audit_schedule.last_checked = getattr(run_lightweight_audit_schedule, "last_checked", None)
        today = date.today()
        if run_lightweight_audit_schedule.last_checked != today:
            run_scheduled_retention()
            run_lightweight_audit_schedule.last_checked = today

    def wants_json_error():
        return request.path.startswith("/api/") or request.headers.get("Accept") == "application/json"

    @app.errorhandler(400)
    def bad_request(error):
        if wants_json_error():
            return jsonify({"error": "bad_request"}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def authentication_required(error):
        if wants_json_error():
            return jsonify({"error": "authentication_required"}), 401
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(error):
        if wants_json_error():
            return jsonify({"error": "forbidden"}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        if wants_json_error():
            return jsonify({"error": "not_found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if wants_json_error():
            return jsonify({"error": "method_not_allowed"}), 405
        return render_template("errors/405.html"), 405

    @app.errorhandler(413)
    def request_entity_too_large(error):
        if wants_json_error():
            return jsonify({"error": "upload_too_large"}), 413
        return render_template("errors/413.html"), 413

    @app.errorhandler(429)
    def too_many_requests(error):
        if wants_json_error():
            return jsonify({"error": "too_many_requests"}), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        if wants_json_error():
            return jsonify({"error": "server_error"}), 500
        return render_template("errors/500.html"), 500

    @app.errorhandler(503)
    def service_unavailable(error):
        if wants_json_error():
            return jsonify({"error": "service_unavailable"}), 503
        return render_template("errors/503.html"), 503

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        if wants_json_error():
            return jsonify({"error": "bad_request"}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(HTTPException)
    def secure_http_error(error):
        code = error.code or 500
        if wants_json_error():
            return jsonify({"error": error.name.lower().replace(" ", "_") if code < 500 else "server_error"}), code
        template = f"errors/{code}.html"
        safe_templates = {400, 401, 403, 404, 405, 413, 429, 500, 503}
        if code in safe_templates:
            return render_template(template), code
        return render_template("errors/404.html"), 404

    register_cli(app)
    return app


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        db.create_all()
        print("Database tables created.")

    @app.cli.command("seed-admin")
    def seed_admin():
        from app.models import AuditLog, User

        user = User.query.filter_by(username="admin").first()
        if user:
            print("Default admin already exists.")
            return

        user = User(
            username="admin",
            email="admin@simpleir.local",
            full_name="AstoraSOC Super Admin",
            role="Admin",
            is_active=True,
            force_password_change=True,
            organization="AstoraSOC",
        )
        user.set_password("ChangeMeNow123!")
        db.session.add(user)
        db.session.flush()
        db.session.add(AuditLog(action="seed_admin", actor_id=user.id, details="Default super admin created."))
        db.session.commit()
        print("Created admin / ChangeMeNow123! and marked it for password change.")

    @app.cli.command("upgrade-db")
    def upgrade_db():
        db.create_all()
        inspector = inspect(db.engine)
        case_columns = {column["name"] for column in inspector.get_columns("cases")}
        alert_columns = {column["name"] for column in inspector.get_columns("alerts")}
        asset_columns = {column["name"] for column in inspector.get_columns("assets")} if inspector.has_table("assets") else set()
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        report_columns = {column["name"] for column in inspector.get_columns("reports")} if inspector.has_table("reports") else set()

        with db.engine.begin() as connection:
            if "public_id" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN public_id VARCHAR(40) NULL"))
                connection.execute(text("CREATE INDEX ix_cases_public_id ON cases (public_id)"))
            if "tracking_id" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN tracking_id VARCHAR(20) NULL"))
            if "asset_id" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN asset_id INT NULL"))
            if "due_at" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN due_at DATETIME NULL"))
            if "case_type" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN case_type VARCHAR(80) NULL"))
                connection.execute(text("CREATE INDEX ix_cases_case_type ON cases (case_type)"))
            case_alters = {
                "incident_type": "ALTER TABLE cases ADD COLUMN incident_type VARCHAR(80) NULL",
                "business_impact": "ALTER TABLE cases ADD COLUMN business_impact VARCHAR(20) NULL",
                "root_cause": "ALTER TABLE cases ADD COLUMN root_cause TEXT NULL",
                "resolution_summary": "ALTER TABLE cases ADD COLUMN resolution_summary TEXT NULL",
                "lessons_learned": "ALTER TABLE cases ADD COLUMN lessons_learned TEXT NULL",
                "validation_performed": "ALTER TABLE cases ADD COLUMN validation_performed TEXT NULL",
                "closure_notes": "ALTER TABLE cases ADD COLUMN closure_notes TEXT NULL",
                "cve_id": "ALTER TABLE cases ADD COLUMN cve_id VARCHAR(80) NULL",
                "cvss_score": "ALTER TABLE cases ADD COLUMN cvss_score VARCHAR(20) NULL",
                "affected_software": "ALTER TABLE cases ADD COLUMN affected_software VARCHAR(160) NULL",
                "affected_version": "ALTER TABLE cases ADD COLUMN affected_version VARCHAR(80) NULL",
                "fixed_version": "ALTER TABLE cases ADD COLUMN fixed_version VARCHAR(80) NULL",
                "patch_status": "ALTER TABLE cases ADD COLUMN patch_status VARCHAR(80) NULL",
                "remediation_owner": "ALTER TABLE cases ADD COLUMN remediation_owner VARCHAR(120) NULL",
            }
            for column, statement in case_alters.items():
                if column not in case_columns:
                    connection.execute(text(statement))
            asset_alters = {
                "owner_phone": "ALTER TABLE assets ADD COLUMN owner_phone VARCHAR(50) NULL",
                "owner_email": "ALTER TABLE assets ADD COLUMN owner_email VARCHAR(120) NULL",
            }
            for column, statement in asset_alters.items():
                if column not in asset_columns:
                    connection.execute(text(statement))
            if "session_active" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN session_active BOOLEAN NOT NULL DEFAULT 0"))
            if "last_seen_at" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN last_seen_at DATETIME NULL"))
            user_alters = {
                "pending_email": "ALTER TABLE users ADD COLUMN pending_email VARCHAR(120) NULL",
                "email_verified_at": "ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL",
                "notification_preference": "ALTER TABLE users ADD COLUMN notification_preference VARCHAR(30) NOT NULL DEFAULT 'EMAIL_IN_APP'",
            }
            for column, statement in user_alters.items():
                if column not in user_columns:
                    connection.execute(text(statement))
            report_alters = {
                "enhanced_by_ai": "ALTER TABLE reports ADD COLUMN enhanced_by_ai BOOLEAN NOT NULL DEFAULT 0",
                "approved_report": "ALTER TABLE reports ADD COLUMN approved_report BOOLEAN NOT NULL DEFAULT 0",
                "report_version": "ALTER TABLE reports ADD COLUMN report_version VARCHAR(40) NULL DEFAULT '1.0'",
            }
            for column, statement in report_alters.items():
                if column not in report_columns:
                    connection.execute(text(statement))
            if not inspector.has_table("email_delivery_logs"):
                connection.execute(text(
                    "CREATE TABLE email_delivery_logs ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "recipient_user_id INT NULL, "
                    "recipient_email VARCHAR(120) NOT NULL, "
                    "notification_type VARCHAR(80) NOT NULL, "
                    "subject VARCHAR(180) NOT NULL, "
                    "status VARCHAR(30) NOT NULL DEFAULT 'QUEUED', "
                    "error TEXT NULL, "
                    "created_at DATETIME NULL, "
                    "delivered_at DATETIME NULL, "
                    "INDEX ix_email_delivery_logs_recipient_user_id (recipient_user_id), "
                    "INDEX ix_email_delivery_logs_recipient_email (recipient_email), "
                    "INDEX ix_email_delivery_logs_notification_type (notification_type), "
                    "INDEX ix_email_delivery_logs_status (status), "
                    "INDEX ix_email_delivery_logs_created_at (created_at), "
                    "FOREIGN KEY(recipient_user_id) REFERENCES users (id)"
                    ")"
                ))
            if not inspector.has_table("case_assignments"):
                connection.execute(text(
                    "CREATE TABLE case_assignments ("
                    "case_id INT NOT NULL, "
                    "user_id INT NOT NULL, "
                    "assigned_by_id INT NULL, "
                    "assigned_at DATETIME NULL, "
                    "PRIMARY KEY (case_id, user_id), "
                    "INDEX ix_case_assignments_user_id (user_id), "
                    "FOREIGN KEY(case_id) REFERENCES cases (id), "
                    "FOREIGN KEY(user_id) REFERENCES users (id), "
                    "FOREIGN KEY(assigned_by_id) REFERENCES users (id)"
                    ")"
                ))
            chat_columns = {column["name"] for column in inspector.get_columns("chat_messages")} if inspector.has_table("chat_messages") else set()
            if "reply_to_id" not in chat_columns:
                connection.execute(text("ALTER TABLE chat_messages ADD COLUMN reply_to_id INT NULL"))
            if inspector.has_table("chat_reactions"):
                connection.execute(text("ALTER TABLE chat_reactions MODIFY emoji VARCHAR(255) NOT NULL"))

            if inspector.has_table("iocs"):
                ioc_columns = {column["name"] for column in inspector.get_columns("iocs")}
                ioc_alters = {
                    "alert_id": "ALTER TABLE iocs ADD COLUMN alert_id INT NULL",
                    "normalized_value": "ALTER TABLE iocs ADD COLUMN normalized_value VARCHAR(500) NULL",
                    "source_system": "ALTER TABLE iocs ADD COLUMN source_system VARCHAR(80) NULL",
                    "source_alert_id": "ALTER TABLE iocs ADD COLUMN source_alert_id INT NULL",
                    "analyst_notes": "ALTER TABLE iocs ADD COLUMN analyst_notes TEXT NULL",
                    "first_seen_at": "ALTER TABLE iocs ADD COLUMN first_seen_at DATETIME NULL",
                    "last_seen_at": "ALTER TABLE iocs ADD COLUMN last_seen_at DATETIME NULL",
                }
                for column, statement in ioc_alters.items():
                    if column not in ioc_columns:
                        connection.execute(text(statement))
                connection.execute(text("ALTER TABLE iocs MODIFY case_id INT NULL"))
                index_names = {index["name"] for index in inspector.get_indexes("iocs")}
                if "ix_iocs_alert_id" not in index_names:
                    connection.execute(text("CREATE INDEX ix_iocs_alert_id ON iocs (alert_id)"))
                if "ix_iocs_normalized_value" not in index_names:
                    connection.execute(text("CREATE INDEX ix_iocs_normalized_value ON iocs (normalized_value)"))
                if "ix_iocs_first_seen_at" not in index_names:
                    connection.execute(text("CREATE INDEX ix_iocs_first_seen_at ON iocs (first_seen_at)"))
                if "ix_iocs_last_seen_at" not in index_names:
                    connection.execute(text("CREATE INDEX ix_iocs_last_seen_at ON iocs (last_seen_at)"))

            if inspector.has_table("assets"):
                asset_columns = {column["name"] for column in inspector.get_columns("assets")}
                asset_alters = {
                    "asset_name": "ALTER TABLE assets ADD COLUMN asset_name VARCHAR(120) NULL",
                    "status": "ALTER TABLE assets ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'Unknown'",
                    "last_seen_at": "ALTER TABLE assets ADD COLUMN last_seen_at DATETIME NULL",
                    "business_function": "ALTER TABLE assets ADD COLUMN business_function VARCHAR(160) NULL",
                    "location": "ALTER TABLE assets ADD COLUMN location VARCHAR(120) NULL",
                    "description": "ALTER TABLE assets ADD COLUMN description TEXT NULL",
                }
                for column, statement in asset_alters.items():
                    if column not in asset_columns:
                        connection.execute(text(statement))
                asset_indexes = {index["name"] for index in inspector.get_indexes("assets")}
                if "ix_assets_asset_name" not in asset_indexes:
                    connection.execute(text("CREATE INDEX ix_assets_asset_name ON assets (asset_name)"))
                if "ix_assets_status" not in asset_indexes:
                    connection.execute(text("CREATE INDEX ix_assets_status ON assets (status)"))
                if "ix_assets_last_seen_at" not in asset_indexes:
                    connection.execute(text("CREATE INDEX ix_assets_last_seen_at ON assets (last_seen_at)"))
                connection.execute(text("UPDATE assets SET asset_name = hostname WHERE asset_name IS NULL OR asset_name = ''"))
                connection.execute(text("UPDATE assets SET status = 'Unknown' WHERE status IS NULL OR status = ''"))
                connection.execute(text("UPDATE assets SET last_seen_at = COALESCE(last_seen_at, updated_at, created_at) WHERE last_seen_at IS NULL"))

            if not inspector.has_table("containment_actions"):
                connection.execute(text(
                    "CREATE TABLE containment_actions ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "containment_id VARCHAR(20) NULL, "
                    "case_id INT NOT NULL, "
                    "action_type VARCHAR(40) NOT NULL, "
                    "target VARCHAR(255) NOT NULL, "
                    "target_host VARCHAR(120) NULL, "
                    "status VARCHAR(30) NOT NULL DEFAULT 'PENDING_APPROVAL', "
                    "reason TEXT NULL, "
                    "notes TEXT NULL, "
                    "risk_level VARCHAR(20) NOT NULL DEFAULT 'Medium', "
                    "output TEXT NULL, "
                    "execution_result TEXT NULL, "
                    "execution_history TEXT NULL, "
                    "execution_provider VARCHAR(60) NOT NULL DEFAULT 'MANUAL', "
                    "approval_requirement VARCHAR(80) NOT NULL DEFAULT 'Lead approval required', "
                    "rollback_result TEXT NULL, "
                    "asset_id INT NULL, "
                    "rollback_supported BOOLEAN NOT NULL DEFAULT 0, "
                    "rollback_status VARCHAR(30) NULL, "
                    "requested_by_id INT NULL, "
                    "approved_by_id INT NULL, "
                    "rejected_by_id INT NULL, "
                    "executed_by_id INT NULL, "
                    "cancelled_by_id INT NULL, "
                    "rolled_back_by_id INT NULL, "
                    "created_at DATETIME NULL, "
                    "approved_at DATETIME NULL, "
                    "rejected_at DATETIME NULL, "
                    "started_at DATETIME NULL, "
                    "completed_at DATETIME NULL, "
                    "cancelled_at DATETIME NULL, "
                    "rolled_back_at DATETIME NULL, "
                    "INDEX ix_containment_actions_case_id (case_id), "
                    "UNIQUE INDEX ix_containment_actions_containment_id (containment_id), "
                    "INDEX ix_containment_actions_status (status), "
                    "INDEX ix_containment_actions_created_at (created_at), "
                    "FOREIGN KEY(case_id) REFERENCES cases (id), "
                    "FOREIGN KEY(requested_by_id) REFERENCES users (id), "
                    "FOREIGN KEY(approved_by_id) REFERENCES users (id)"
                    ")"
                ))
            elif inspector.has_table("containment_actions"):
                containment_columns = {column["name"] for column in inspector.get_columns("containment_actions")}
                containment_alters = {
                    "containment_id": "ALTER TABLE containment_actions ADD COLUMN containment_id VARCHAR(20) NULL",
                    "reason": "ALTER TABLE containment_actions ADD COLUMN reason TEXT NULL",
                    "risk_level": "ALTER TABLE containment_actions ADD COLUMN risk_level VARCHAR(20) NOT NULL DEFAULT 'Medium'",
                    "execution_result": "ALTER TABLE containment_actions ADD COLUMN execution_result TEXT NULL",
                    "execution_history": "ALTER TABLE containment_actions ADD COLUMN execution_history TEXT NULL",
                    "execution_provider": "ALTER TABLE containment_actions ADD COLUMN execution_provider VARCHAR(60) NOT NULL DEFAULT 'MANUAL'",
                    "approval_requirement": "ALTER TABLE containment_actions ADD COLUMN approval_requirement VARCHAR(80) NOT NULL DEFAULT 'Lead approval required'",
                    "rollback_result": "ALTER TABLE containment_actions ADD COLUMN rollback_result TEXT NULL",
                    "asset_id": "ALTER TABLE containment_actions ADD COLUMN asset_id INT NULL",
                    "rejected_by_id": "ALTER TABLE containment_actions ADD COLUMN rejected_by_id INT NULL",
                    "executed_by_id": "ALTER TABLE containment_actions ADD COLUMN executed_by_id INT NULL",
                    "cancelled_by_id": "ALTER TABLE containment_actions ADD COLUMN cancelled_by_id INT NULL",
                    "rolled_back_by_id": "ALTER TABLE containment_actions ADD COLUMN rolled_back_by_id INT NULL",
                    "approved_at": "ALTER TABLE containment_actions ADD COLUMN approved_at DATETIME NULL",
                    "rejected_at": "ALTER TABLE containment_actions ADD COLUMN rejected_at DATETIME NULL",
                    "cancelled_at": "ALTER TABLE containment_actions ADD COLUMN cancelled_at DATETIME NULL",
                    "rolled_back_at": "ALTER TABLE containment_actions ADD COLUMN rolled_back_at DATETIME NULL",
                }
                for column, statement in containment_alters.items():
                    if column not in containment_columns:
                        connection.execute(text(statement))
                containment_indexes = {index["name"] for index in inspector.get_indexes("containment_actions")}
                if "ix_containment_actions_asset_id" not in containment_indexes:
                    connection.execute(text("CREATE INDEX ix_containment_actions_asset_id ON containment_actions (asset_id)"))
                if "ix_containment_actions_containment_id" not in containment_indexes:
                    connection.execute(text("CREATE UNIQUE INDEX ix_containment_actions_containment_id ON containment_actions (containment_id)"))
                connection.execute(text("UPDATE containment_actions SET status = 'EXECUTED' WHERE status = 'SUCCESS'"))
                connection.execute(text("UPDATE containment_actions SET status = 'EXECUTING' WHERE status = 'RUNNING'"))
                connection.execute(text("UPDATE containment_actions SET reason = COALESCE(reason, notes, 'Legacy containment action')"))
                connection.execute(text("UPDATE containment_actions SET containment_id = CONCAT('CA-', LPAD(id, 6, '0')) WHERE containment_id IS NULL OR containment_id = ''"))
            if inspector.has_table("case_notes"):
                note_columns = {column["name"] for column in inspector.get_columns("case_notes")}
                note_alters = {
                    "updated_by_id": "ALTER TABLE case_notes ADD COLUMN updated_by_id INT NULL",
                    "updated_at": "ALTER TABLE case_notes ADD COLUMN updated_at DATETIME NULL",
                    "is_pinned": "ALTER TABLE case_notes ADD COLUMN is_pinned BOOLEAN NOT NULL DEFAULT 0",
                    "edit_history": "ALTER TABLE case_notes ADD COLUMN edit_history TEXT NULL",
                }
                for column, statement in note_alters.items():
                    if column not in note_columns:
                        connection.execute(text(statement))

            if inspector.has_table("tasks"):
                task_columns = {column["name"] for column in inspector.get_columns("tasks")}
                task_alters = {
                    "playbook_template_id": "ALTER TABLE tasks ADD COLUMN playbook_template_id INT NULL",
                    "source": "ALTER TABLE tasks ADD COLUMN source VARCHAR(30) NOT NULL DEFAULT 'Analyst'",
                    "playbook_name": "ALTER TABLE tasks ADD COLUMN playbook_name VARCHAR(120) NULL",
                    "created_by_id": "ALTER TABLE tasks ADD COLUMN created_by_id INT NULL",
                }
                for column, statement in task_alters.items():
                    if column not in task_columns:
                        connection.execute(text(statement))
                task_indexes = {index["name"] for index in inspector.get_indexes("tasks")}
                if "ix_tasks_playbook_template_id" not in task_indexes:
                    connection.execute(text("CREATE INDEX ix_tasks_playbook_template_id ON tasks (playbook_template_id)"))
                connection.execute(text("UPDATE tasks SET source = COALESCE(source, 'Analyst')"))
                connection.execute(text(
                    "UPDATE tasks SET source = 'Auto', playbook_name = COALESCE(playbook_name, 'Default Checklist') "
                    "WHERE created_by_id IS NULL AND title IN ("
                    "'Validate alert and scope affected assets', "
                    "'Collect triage evidence', "
                    "'Identify and record IOCs', "
                    "'Contain affected account or host', "
                    "'Document actions taken', "
                    "'Prepare closure summary'"
                    ")"
                ))

            if not inspector.has_table("playbook_templates"):
                connection.execute(text(
                    "CREATE TABLE playbook_templates ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "name VARCHAR(120) NOT NULL, "
                    "description TEXT NULL, "
                    "category VARCHAR(40) NOT NULL DEFAULT 'Generic', "
                    "match_type VARCHAR(30) NOT NULL DEFAULT 'GENERIC', "
                    "match_value VARCHAR(160) NOT NULL DEFAULT '*', "
                    "priority INT NOT NULL DEFAULT 100, "
                    "is_active BOOLEAN NOT NULL DEFAULT 1, "
                    "is_archived BOOLEAN NOT NULL DEFAULT 0, "
                    "version INT NOT NULL DEFAULT 1, "
                    "version_history TEXT NULL, "
                    "usage_count INT NOT NULL DEFAULT 0, "
                    "last_applied_at DATETIME NULL, "
                    "tasks_text TEXT NOT NULL, "
                    "created_by_id INT NULL, "
                    "updated_by_id INT NULL, "
                    "created_at DATETIME NULL, "
                    "updated_at DATETIME NULL, "
                    "INDEX ix_playbook_templates_match_type (match_type), "
                    "INDEX ix_playbook_templates_match_value (match_value), "
                    "INDEX ix_playbook_templates_category (category), "
                    "INDEX ix_playbook_templates_is_active (is_active), "
                    "INDEX ix_playbook_templates_is_archived (is_archived)"
                    ")"
                ))
            else:
                playbook_columns = {column["name"] for column in inspector.get_columns("playbook_templates")}
                if "category" not in playbook_columns:
                    connection.execute(text("ALTER TABLE playbook_templates ADD COLUMN category VARCHAR(40) NOT NULL DEFAULT 'Generic'"))
                playbook_alters = {
                    "is_archived": "ALTER TABLE playbook_templates ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0",
                    "version": "ALTER TABLE playbook_templates ADD COLUMN version INT NOT NULL DEFAULT 1",
                    "version_history": "ALTER TABLE playbook_templates ADD COLUMN version_history TEXT NULL",
                    "usage_count": "ALTER TABLE playbook_templates ADD COLUMN usage_count INT NOT NULL DEFAULT 0",
                    "last_applied_at": "ALTER TABLE playbook_templates ADD COLUMN last_applied_at DATETIME NULL",
                }
                for column_name, ddl in playbook_alters.items():
                    if column_name not in playbook_columns:
                        connection.execute(text(ddl))
                playbook_index_names = {index["name"] for index in inspector.get_indexes("playbook_templates")}
                if "ix_playbook_templates_category" not in playbook_index_names:
                    connection.execute(text("CREATE INDEX ix_playbook_templates_category ON playbook_templates (category)"))
                if "ix_playbook_templates_is_archived" not in playbook_index_names:
                    connection.execute(text("CREATE INDEX ix_playbook_templates_is_archived ON playbook_templates (is_archived)"))
                connection.execute(text("UPDATE playbook_templates SET is_archived = 0 WHERE is_archived IS NULL"))
                connection.execute(text("UPDATE playbook_templates SET version = 1 WHERE version IS NULL"))
                connection.execute(text("UPDATE playbook_templates SET usage_count = 0 WHERE usage_count IS NULL"))

            alert_alters = {
                "tracking_id": "ALTER TABLE alerts ADD COLUMN tracking_id VARCHAR(20) NULL",
                "title": "ALTER TABLE alerts ADD COLUMN title VARCHAR(180) NOT NULL DEFAULT 'Incoming security alert'",
                "description": "ALTER TABLE alerts ADD COLUMN description TEXT NULL",
                "severity": "ALTER TABLE alerts ADD COLUMN severity VARCHAR(20) NOT NULL DEFAULT 'Medium'",
                "status": "ALTER TABLE alerts ADD COLUMN status VARCHAR(40) NOT NULL DEFAULT 'Pending Review'",
                "event_id": "ALTER TABLE alerts ADD COLUMN event_id VARCHAR(160) NULL",
                "affected_host": "ALTER TABLE alerts ADD COLUMN affected_host VARCHAR(120) NULL",
                "affected_user": "ALTER TABLE alerts ADD COLUMN affected_user VARCHAR(120) NULL",
                "source_ip": "ALTER TABLE alerts ADD COLUMN source_ip VARCHAR(80) NULL",
                "destination_ip": "ALTER TABLE alerts ADD COLUMN destination_ip VARCHAR(80) NULL",
                "asset_id": "ALTER TABLE alerts ADD COLUMN asset_id INT NULL",
                "mitre_tactic": "ALTER TABLE alerts ADD COLUMN mitre_tactic VARCHAR(120) NULL",
                "mitre_technique": "ALTER TABLE alerts ADD COLUMN mitre_technique VARCHAR(120) NULL",
                "task_plan": "ALTER TABLE alerts ADD COLUMN task_plan TEXT NULL",
                "reviewed_by_id": "ALTER TABLE alerts ADD COLUMN reviewed_by_id INT NULL",
                "promoted_by_id": "ALTER TABLE alerts ADD COLUMN promoted_by_id INT NULL",
                "updated_at": "ALTER TABLE alerts ADD COLUMN updated_at DATETIME NULL",
            }
            for column, statement in alert_alters.items():
                if column not in alert_columns:
                    connection.execute(text(statement))
            index_names = {index["name"] for index in inspector.get_indexes("alerts")}
            if "ix_alerts_event_id" not in index_names:
                connection.execute(text("CREATE INDEX ix_alerts_event_id ON alerts (event_id)"))
            if "ix_alerts_tracking_id" not in index_names:
                connection.execute(text("CREATE UNIQUE INDEX ix_alerts_tracking_id ON alerts (tracking_id)"))
            case_index_names = {index["name"] for index in inspector.get_indexes("cases")}
            if "ix_cases_tracking_id" not in case_index_names:
                connection.execute(text("CREATE UNIQUE INDEX ix_cases_tracking_id ON cases (tracking_id)"))
            if "ix_cases_asset_id" not in case_index_names:
                connection.execute(text("CREATE INDEX ix_cases_asset_id ON cases (asset_id)"))
            if "ix_alerts_asset_id" not in index_names:
                connection.execute(text("CREATE INDEX ix_alerts_asset_id ON alerts (asset_id)"))
            connection.execute(text("ALTER TABLE alerts MODIFY case_id INT NULL"))
            connection.execute(text("UPDATE alerts SET updated_at = created_at WHERE updated_at IS NULL"))
            connection.execute(text("UPDATE alerts SET status = 'NEW' WHERE status IN ('New', 'Pending Review')"))
            connection.execute(text("UPDATE alerts SET status = 'PENDING_REVIEW' WHERE status = 'Submitted for Review'"))
            connection.execute(text("UPDATE alerts SET status = 'FALSE_POSITIVE' WHERE status = 'False Positive'"))
            connection.execute(text("UPDATE alerts SET status = 'PROMOTED' WHERE status = 'Promoted'"))
            connection.execute(text("UPDATE cases SET status = 'SUBMITTED_FOR_REVIEW' WHERE status IN ('New', 'Pending Review', 'Submitted for Review')"))
            connection.execute(text("UPDATE cases SET status = 'ASSIGNED' WHERE status = 'Assigned'"))
            connection.execute(text("UPDATE cases SET status = 'INVESTIGATING' WHERE status IN ('Investigating', 'Containment', 'Eradication', 'Recovery')"))
            connection.execute(text("UPDATE cases SET status = 'CLOSED' WHERE status IN ('Closed', 'False Positive')"))
            connection.execute(text(
                "INSERT IGNORE INTO case_assignments (case_id, user_id, assigned_at) "
                "SELECT id, assignee_id, updated_at FROM cases WHERE assignee_id IS NOT NULL"
            ))
            connection.execute(text("UPDATE users SET is_active = 1 WHERE is_active = 0"))
            connection.execute(text("UPDATE users SET session_active = 0"))
        from app.ioc_intel import canonical_ioc_type, normalize_ioc, sanitize_ioc_value
        from app.asset_matching import link_alert_asset, link_case_asset
        from app.models import Alert, Asset, AuditLog, Case, IOC, Notification
        from app.playbooks import seed_default_playbooks
        from app.utils import ensure_tracking_id, generate_tracking_id, normalize_tracking_id, tracking_label

        seed_default_playbooks()
        for model in (Alert, Case):
            for item in model.query.filter(model.tracking_id.like("RVN-%")).order_by(model.created_at.asc(), model.id.asc()).all():
                candidate = normalize_tracking_id(item.tracking_id)
                conflict = model.query.filter(model.id != item.id, model.tracking_id == candidate).first()
                item.tracking_id = generate_tracking_id(getattr(item, "created_at", None)) if conflict else candidate
                if isinstance(item, Case):
                    item.public_id = item.tracking_id
        for alert in Alert.query.filter(Alert.event_id.is_(None)).all():
            raw = alert.raw_json if isinstance(alert.raw_json, dict) else {}
            event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
            raw_alert = raw.get("raw_alert") if isinstance(raw.get("raw_alert"), dict) else {}
            event_id = event.get("id") or raw.get("event_id") or raw.get("id") or raw_alert.get("id")
            if event_id:
                alert.event_id = str(event_id)[:160]
        for alert in Alert.query.order_by(Alert.created_at.asc(), Alert.id.asc()).all():
            ensure_tracking_id(alert)
        for case in Case.query.order_by(Case.created_at.asc(), Case.id.asc()).all():
            linked_alert = Alert.query.filter_by(case_id=case.id).order_by(Alert.created_at.asc(), Alert.id.asc()).first()
            if linked_alert:
                case.tracking_id = tracking_label(linked_alert)
                case.public_id = case.tracking_id
            else:
                ensure_tracking_id(case)
        alert_refs = {str(alert.id): tracking_label(alert) for alert in Alert.query.all()}
        case_refs = {str(case.id): tracking_label(case) for case in Case.query.all()}

        def replace_tracking_refs(text):
            if not text:
                return text
            text = text.replace("RVN-", "AST-")
            text = re.sub(r"\bAlert #(\d+)\b", lambda match: f"Alert {alert_refs.get(match.group(1), f'AST-LEGACY-{int(match.group(1)):06d}')}", text)
            text = re.sub(r"\balert #(\d+)\b", lambda match: f"alert {alert_refs.get(match.group(1), f'AST-LEGACY-{int(match.group(1)):06d}')}", text)
            text = re.sub(r"\bCase #(\d+)\b", lambda match: f"Case {case_refs.get(match.group(1), f'AST-LEGACY-{int(match.group(1)):06d}')}", text)
            text = re.sub(r"\bcase #(\d+)\b", lambda match: f"case {case_refs.get(match.group(1), f'AST-LEGACY-{int(match.group(1)):06d}')}", text)
            text = text.replace("Alert Alert ", "Alert ").replace("Case Case ", "Case ")
            return text

        for row in AuditLog.query.filter(AuditLog.details.isnot(None)).all():
            row.details = replace_tracking_refs(row.details)
        for row in Notification.query.all():
            row.message = replace_tracking_refs(row.message)[:240]
        for ioc in IOC.query.all():
            ioc.type = canonical_ioc_type(ioc.type)
            clean_value = sanitize_ioc_value(ioc.type, ioc.value)
            if clean_value:
                ioc.value = clean_value
                ioc.normalized_value = normalize_ioc(ioc.type, clean_value)
            elif not ioc.normalized_value:
                ioc.normalized_value = ""
            if not ioc.first_seen_at:
                ioc.first_seen_at = ioc.added_at
            if not ioc.last_seen_at:
                ioc.last_seen_at = ioc.added_at
        if Asset.query.first():
            for alert in Alert.query.filter(Alert.asset_id.is_(None)).all():
                link_alert_asset(alert)
            for case in Case.query.filter(Case.asset_id.is_(None)).all():
                link_case_asset(case)
        db.session.commit()
        print("Database schema upgraded.")
