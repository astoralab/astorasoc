from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    pending_email = db.Column(db.String(120))
    email_verified_at = db.Column(db.DateTime(timezone=True))
    notification_preference = db.Column(db.String(30), default="EMAIL_IN_APP", nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Viewer")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    session_active = db.Column(db.Boolean, default=False, nullable=False)
    force_password_change = db.Column(db.Boolean, default=False, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    department = db.Column(db.String(120))
    job_title = db.Column(db.String(120))
    organization = db.Column(db.String(120))
    location = db.Column(db.String(120))
    bio = db.Column(db.Text)
    skills = db.Column(db.String(250))
    last_login_at = db.Column(db.DateTime(timezone=True))
    last_seen_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    assigned_cases = db.relationship("Case", foreign_keys="Case.assignee_id", back_populates="assignee")
    case_assignments = db.relationship("CaseAssignment", foreign_keys="CaseAssignment.user_id", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(120), index=True)
    hostname = db.Column(db.String(120), nullable=False, unique=True, index=True)
    ip_address = db.Column(db.String(80), index=True)
    owner = db.Column(db.String(120))
    owner_phone = db.Column(db.String(50))
    owner_email = db.Column(db.String(120))
    department = db.Column(db.String(120))
    operating_system = db.Column(db.String(120))
    asset_type = db.Column(db.String(80), default="Workstation", nullable=False)
    criticality = db.Column(db.String(20), default="Medium", nullable=False, index=True)
    status = db.Column(db.String(20), default="Unknown", nullable=False, index=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), index=True)
    business_function = db.Column(db.String(160))
    location = db.Column(db.String(120))
    description = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    created_by = db.relationship("User")
    alerts = db.relationship("Alert", back_populates="asset")
    cases = db.relationship("Case", back_populates="asset")


class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(20), unique=True, index=True)
    public_id = db.Column(db.String(40), unique=True, index=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="Medium", nullable=False)
    status = db.Column(db.String(40), default="SUBMITTED_FOR_REVIEW", nullable=False, index=True)
    source = db.Column(db.String(40), default="Manual", nullable=False)
    case_type = db.Column(db.String(80), index=True)
    incident_type = db.Column(db.String(80), index=True)
    business_impact = db.Column(db.String(20))
    root_cause = db.Column(db.Text)
    resolution_summary = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)
    validation_performed = db.Column(db.Text)
    closure_notes = db.Column(db.Text)
    cve_id = db.Column(db.String(80))
    cvss_score = db.Column(db.String(20))
    affected_software = db.Column(db.String(160))
    affected_version = db.Column(db.String(80))
    fixed_version = db.Column(db.String(80))
    patch_status = db.Column(db.String(80))
    remediation_owner = db.Column(db.String(120))
    rule_id = db.Column(db.String(120))
    mitre_tactic = db.Column(db.String(120))
    mitre_technique = db.Column(db.String(120))
    affected_host = db.Column(db.String(120))
    affected_user = db.Column(db.String(120))
    source_ip = db.Column(db.String(80))
    destination_ip = db.Column(db.String(80))
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"))
    closure_reason = db.Column(db.Text)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    closed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    due_at = db.Column(db.DateTime(timezone=True), index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    closed_at = db.Column(db.DateTime(timezone=True))

    assignee = db.relationship("User", foreign_keys=[assignee_id], back_populates="assigned_cases")
    assignments = db.relationship("CaseAssignment", back_populates="case", cascade="all, delete-orphan")
    assigned_users = db.relationship(
        "User",
        secondary="case_assignments",
        primaryjoin="Case.id==CaseAssignment.case_id",
        secondaryjoin="User.id==CaseAssignment.user_id",
        viewonly=True,
    )
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])
    closed_by = db.relationship("User", foreign_keys=[closed_by_id])
    asset = db.relationship("Asset", back_populates="cases")
    alerts = db.relationship("Alert", back_populates="case", cascade="all, delete-orphan")
    iocs = db.relationship("IOC", back_populates="case", cascade="all, delete-orphan", order_by="IOC.added_at.desc()")
    evidence = db.relationship("Evidence", back_populates="case", cascade="all, delete-orphan", order_by="Evidence.uploaded_at.desc()")
    timeline = db.relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan", order_by="TimelineEvent.created_at.desc()")
    notes = db.relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at.desc()")
    tasks = db.relationship("Task", back_populates="case", cascade="all, delete-orphan", order_by="Task.created_at.asc()")
    containment_actions = db.relationship("ContainmentAction", back_populates="case", cascade="all, delete-orphan", order_by="ContainmentAction.created_at.desc()")


class CaseAssignment(db.Model):
    __tablename__ = "case_assignments"
    __table_args__ = (db.PrimaryKeyConstraint("case_id", "user_id", name="pk_case_assignments"),)

    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    case = db.relationship("Case", back_populates="assignments")
    user = db.relationship("User", foreign_keys=[user_id], back_populates="case_assignments")
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id])


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(20), unique=True, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    title = db.Column(db.String(180), nullable=False, default="Incoming security alert")
    description = db.Column(db.Text, nullable=False, default="")
    severity = db.Column(db.String(20), default="Medium", nullable=False)
    status = db.Column(db.String(40), default="NEW", nullable=False, index=True)
    source = db.Column(db.String(40), nullable=False)
    event_id = db.Column(db.String(160), index=True)
    rule_id = db.Column(db.String(120))
    affected_host = db.Column(db.String(120))
    affected_user = db.Column(db.String(120))
    source_ip = db.Column(db.String(80))
    destination_ip = db.Column(db.String(80))
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"))
    mitre_tactic = db.Column(db.String(120))
    mitre_technique = db.Column(db.String(120))
    task_plan = db.Column(db.Text)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    promoted_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    raw_json = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    case = db.relationship("Case", back_populates="alerts")
    asset = db.relationship("Asset", back_populates="alerts")
    iocs = db.relationship("IOC", foreign_keys="IOC.alert_id", back_populates="alert", cascade="all, delete-orphan", order_by="IOC.added_at.desc()")
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])
    promoted_by = db.relationship("User", foreign_keys=[promoted_by_id])


class IOC(db.Model):
    __tablename__ = "iocs"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=True, index=True)
    type = db.Column(db.String(30), nullable=False)
    value = db.Column(db.String(500), nullable=False)
    normalized_value = db.Column(db.String(500), nullable=False, index=True)
    confidence = db.Column(db.String(20), default="Medium", nullable=False)
    source = db.Column(db.String(120))
    source_system = db.Column(db.String(80))
    source_alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=True)
    analyst_notes = db.Column(db.Text)
    tags = db.Column(db.String(250))
    added_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    added_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    first_seen_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    case = db.relationship("Case", back_populates="iocs")
    alert = db.relationship("Alert", foreign_keys=[alert_id], back_populates="iocs")
    source_alert = db.relationship("Alert", foreign_keys=[source_alert_id])
    added_by = db.relationship("User")


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    uploaded_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    case = db.relationship("Case", back_populates="evidence")
    uploaded_by = db.relationship("User")


class TimelineEvent(db.Model):
    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    event_type = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    case = db.relationship("Case", back_populates="timeline")
    actor = db.relationship("User")


class CaseNote(db.Model):
    __tablename__ = "case_notes"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    updated_at = db.Column(db.DateTime(timezone=True))
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)
    edit_history = db.Column(db.Text)
    case = db.relationship("Case", back_populates="notes")
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    playbook_template_id = db.Column(db.Integer, db.ForeignKey("playbook_templates.id"))
    title = db.Column(db.String(180), nullable=False)
    is_complete = db.Column(db.Boolean, default=False, nullable=False)
    source = db.Column(db.String(30), default="Analyst", nullable=False)
    playbook_name = db.Column(db.String(120))
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    completed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    completed_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    case = db.relationship("Case", back_populates="tasks")
    playbook_template = db.relationship("PlaybookTemplate")
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    completed_by = db.relationship("User", foreign_keys=[completed_by_id])


class PlaybookTemplate(db.Model):
    __tablename__ = "playbook_templates"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(40), default="Generic", nullable=False, index=True)
    match_type = db.Column(db.String(30), default="GENERIC", nullable=False, index=True)
    match_value = db.Column(db.String(160), default="*", nullable=False, index=True)
    priority = db.Column(db.Integer, default=100, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_archived = db.Column(db.Boolean, default=False, nullable=False, index=True)
    version = db.Column(db.Integer, default=1, nullable=False)
    version_history = db.Column(db.Text)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    last_applied_at = db.Column(db.DateTime(timezone=True))
    tasks_text = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    updated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])


class ContainmentAction(db.Model):
    __tablename__ = "containment_actions"

    id = db.Column(db.Integer, primary_key=True)
    containment_id = db.Column(db.String(20), unique=True, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    action_type = db.Column(db.String(40), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    target_host = db.Column(db.String(120))
    status = db.Column(db.String(30), default="PENDING_APPROVAL", nullable=False, index=True)
    reason = db.Column(db.Text)
    notes = db.Column(db.Text)
    risk_level = db.Column(db.String(20), default="Medium", nullable=False)
    output = db.Column(db.Text)
    execution_result = db.Column(db.Text)
    execution_history = db.Column(db.Text)
    execution_provider = db.Column(db.String(60), default="MANUAL", nullable=False)
    approval_requirement = db.Column(db.String(80), default="Lead approval required", nullable=False)
    rollback_result = db.Column(db.Text)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"))
    rollback_supported = db.Column(db.Boolean, default=False, nullable=False)
    rollback_status = db.Column(db.String(30))
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    approved_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    rejected_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    executed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    cancelled_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    rolled_back_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    approved_at = db.Column(db.DateTime(timezone=True))
    rejected_at = db.Column(db.DateTime(timezone=True))
    started_at = db.Column(db.DateTime(timezone=True))
    completed_at = db.Column(db.DateTime(timezone=True))
    cancelled_at = db.Column(db.DateTime(timezone=True))
    rolled_back_at = db.Column(db.DateTime(timezone=True))
    case = db.relationship("Case", back_populates="containment_actions")
    asset = db.relationship("Asset")
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    approved_by = db.relationship("User", foreign_keys=[approved_by_id])
    rejected_by = db.relationship("User", foreign_keys=[rejected_by_id])
    executed_by = db.relationship("User", foreign_keys=[executed_by_id])
    cancelled_by = db.relationship("User", foreign_keys=[cancelled_by_id])
    rolled_back_by = db.relationship("User", foreign_keys=[rolled_back_by_id])


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    generated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    filename = db.Column(db.String(255), nullable=False)
    enhanced_by_ai = db.Column(db.Boolean, default=False, nullable=False)
    approved_report = db.Column(db.Boolean, default=False, nullable=False)
    report_version = db.Column(db.String(40), default="1.0")
    generated_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(120), nullable=False, index=True)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(80))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    actor = db.relationship("User")


class AppSetting(db.Model):
    __tablename__ = "app_settings"

    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.Text)


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    category = db.Column(db.String(40), nullable=False, index=True)
    message = db.Column(db.String(240), nullable=False)
    target_url = db.Column(db.String(240))
    read_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    user = db.relationship("User")


class EmailDeliveryLog(db.Model):
    __tablename__ = "email_delivery_logs"

    id = db.Column(db.Integer, primary_key=True)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    recipient_email = db.Column(db.String(120), nullable=False, index=True)
    notification_type = db.Column(db.String(80), nullable=False, index=True)
    subject = db.Column(db.String(180), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="QUEUED", index=True)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    delivered_at = db.Column(db.DateTime(timezone=True))
    recipient = db.relationship("User")


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    body_encrypted = db.Column(db.Text)
    attachment_name = db.Column(db.String(255))
    attachment_path = db.Column(db.String(255))
    attachment_kind = db.Column(db.String(40))
    reply_to_id = db.Column(db.Integer, db.ForeignKey("chat_messages.id"))
    deleted_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    sender = db.relationship("User")
    reply_to = db.relationship("ChatMessage", remote_side=[id])
    reactions = db.relationship("ChatReaction", back_populates="message", cascade="all, delete-orphan")


class ChatReaction(db.Model):
    __tablename__ = "chat_reactions"
    __table_args__ = (db.UniqueConstraint("message_id", "user_id", "emoji", name="uq_chat_reaction_user_emoji"),)

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("chat_messages.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    emoji = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    message = db.relationship("ChatMessage", back_populates="reactions")
    user = db.relationship("User")
