from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import BooleanField, DateTimeLocalField, IntegerField, PasswordField, SelectField, SelectMultipleField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional

from app.ai_catalog import all_model_choices, provider_choices
from app.playbooks import CASE_TYPE_CHOICES, PLAYBOOK_CATEGORY_CHOICES

IMAGE_TYPES = ["jpg", "jpeg", "png", "webp"]
EVIDENCE_TYPES = ["pdf", "txt", "log", "csv", "json", "png", "jpg", "jpeg", "zip"]

INCIDENT_TYPE_CHOICES = [
    ("", "Auto / Not classified"),
    ("Vulnerability", "Vulnerability"),
    ("Malware", "Malware"),
    ("Phishing", "Phishing"),
    ("Credential Access", "Credential Access"),
    ("Threat Hunting", "Threat Hunting"),
    ("Compliance", "Compliance"),
    ("Insider Threat", "Insider Threat"),
    ("Data Exposure", "Data Exposure"),
    ("Other", "Other"),
]

BUSINESS_IMPACT_CHOICES = [
    ("", "Not assessed"),
    ("Low", "Low"),
    ("Medium", "Medium"),
    ("High", "High"),
    ("Critical", "Critical"),
]

PATCH_STATUS_CHOICES = [
    ("", "Not applicable"),
    ("Open", "Open"),
    ("Planned", "Planned"),
    ("In Progress", "In Progress"),
    ("Patched", "Patched"),
    ("Mitigated", "Mitigated"),
    ("Accepted Risk", "Accepted Risk"),
]


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[Optional()])
    password = PasswordField("New password", validators=[DataRequired(), Length(min=12)])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Change password")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    role = SelectField("Role", choices=[("Admin", "Admin"), ("Lead", "Lead"), ("Analyst", "Analyst"), ("Junior Analyst", "Junior Analyst"), ("Viewer", "Viewer")])
    password = PasswordField("Password", validators=[Optional(), Length(min=12)])
    submit = SubmitField("Save user")


class ProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField("Phone", validators=[Optional(), Length(max=50)])
    department = StringField("Department/team", validators=[Optional(), Length(max=120)])
    job_title = StringField("Job title", validators=[Optional(), Length(max=120)])
    organization = StringField("Organization", validators=[Optional(), Length(max=120)])
    profile_picture = FileField("Profile picture", validators=[Optional(), FileAllowed(IMAGE_TYPES)])
    submit = SubmitField("Save profile")


ASSET_OS_CHOICES = [
    ("Windows 11", "Windows 11"),
    ("Windows 10", "Windows 10"),
    ("Windows 8.1", "Windows 8.1"),
    ("Windows 7", "Windows 7"),
    ("Windows Server 2025", "Windows Server 2025"),
    ("Windows Server 2022", "Windows Server 2022"),
    ("Windows Server 2019", "Windows Server 2019"),
    ("Windows Server 2016", "Windows Server 2016"),
    ("Windows Server 2012 R2", "Windows Server 2012 R2"),
    ("Ubuntu 24.04 LTS", "Ubuntu 24.04 LTS"),
    ("Ubuntu 22.04 LTS", "Ubuntu 22.04 LTS"),
    ("Ubuntu 20.04 LTS", "Ubuntu 20.04 LTS"),
    ("Debian", "Debian"),
    ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux"),
    ("CentOS", "CentOS"),
    ("Rocky Linux", "Rocky Linux"),
    ("AlmaLinux", "AlmaLinux"),
    ("Fedora", "Fedora"),
    ("SUSE Linux Enterprise", "SUSE Linux Enterprise"),
    ("Kali Linux", "Kali Linux"),
    ("Amazon Linux", "Amazon Linux"),
    ("Oracle Linux", "Oracle Linux"),
    ("Arch Linux", "Arch Linux"),
    ("macOS", "macOS"),
    ("iOS", "iOS"),
    ("iPadOS", "iPadOS"),
    ("Android", "Android"),
    ("ChromeOS", "ChromeOS"),
    ("VMware ESXi", "VMware ESXi"),
    ("Proxmox VE", "Proxmox VE"),
    ("FreeBSD", "FreeBSD"),
    ("OpenBSD", "OpenBSD"),
    ("pfSense", "pfSense"),
    ("OPNsense", "OPNsense"),
    ("Cisco IOS", "Cisco IOS"),
    ("Cisco IOS XE", "Cisco IOS XE"),
    ("Cisco NX-OS", "Cisco NX-OS"),
    ("Cisco ASA", "Cisco ASA"),
    ("FortiOS", "FortiOS"),
    ("Palo Alto PAN-OS", "Palo Alto PAN-OS"),
    ("Juniper Junos", "Juniper Junos"),
    ("MikroTik RouterOS", "MikroTik RouterOS"),
    ("ArubaOS", "ArubaOS"),
    ("Check Point Gaia", "Check Point Gaia"),
    ("Sophos Firewall OS", "Sophos Firewall OS"),
    ("F5 BIG-IP", "F5 BIG-IP"),
    ("Azure Linux", "Azure Linux"),
    ("Google Container-Optimized OS", "Google Container-Optimized OS"),
    ("Container / Kubernetes Node", "Container / Kubernetes Node"),
    ("Appliance / Embedded OS", "Appliance / Embedded OS"),
    ("Unknown", "Unknown"),
    ("Other", "Other"),
]


ASSET_DEPARTMENT_CHOICES = [
    "Human Resources (HR)",
    "Finance",
    "Accounting",
    "Procurement",
    "Information and Communications Technology (ICT)",
    "Security Operations Center (SOC)",
    "Information Security",
    "Network Operations",
    "Infrastructure",
    "Cloud Operations",
    "Application Development",
    "Software Engineering",
    "DevOps",
    "Database Administration (DBA)",
    "Compliance",
    "Risk Management",
    "Internal Audit",
    "Legal",
    "Management",
    "Executive Management",
    "Operations",
    "Customer Support",
    "Sales",
    "Marketing",
    "Research & Development (R&D)",
    "Student Affairs",
    "Academic Affairs",
    "Registrar",
    "Library Services",
    "Facilities Management",
    "Administration",
    "Branch Office",
    "Data Center Operations",
    "Other",
]


ASSET_BUSINESS_FUNCTION_CHOICES = [
    "Authentication Service",
    "Identity Management",
    "Active Directory",
    "Domain Services",
    "Email Gateway",
    "Email Services",
    "Payroll System",
    "Human Resource Management",
    "Student Information System",
    "Learning Management System (LMS)",
    "Financial Management System",
    "Accounting System",
    "ERP System",
    "CRM System",
    "Database Service",
    "Web Application",
    "API Service",
    "File Storage Service",
    "Backup Service",
    "Monitoring Platform",
    "SIEM Platform",
    "SOC Platform",
    "Threat Intelligence Platform",
    "Vulnerability Management",
    "Patch Management",
    "Endpoint Protection",
    "Remote Access Service",
    "VPN Gateway",
    "Firewall Management",
    "DNS Service",
    "DHCP Service",
    "Proxy Service",
    "Certificate Authority",
    "Application Server",
    "Web Server",
    "Mail Server",
    "Database Server",
    "Virtualization Platform",
    "Cloud Management Platform",
    "Container Platform",
    "Source Code Repository",
    "CI/CD Pipeline",
    "Business Analytics",
    "Reporting Platform",
    "Document Management System",
    "Customer Portal",
    "Public Website",
    "Internal Portal",
    "Video Conferencing Service",
    "VoIP Service",
    "Research Platform",
    "Development Environment",
    "Testing Environment",
    "Production Environment",
    "Disaster Recovery Platform",
    "Backup Data Repository",
    "Other",
]


class AssetForm(FlaskForm):
    department_choices = ASSET_DEPARTMENT_CHOICES
    business_function_choices = ASSET_BUSINESS_FUNCTION_CHOICES

    asset_name = StringField("Asset Name", validators=[DataRequired(), Length(max=120)])
    hostname = StringField("Hostname", validators=[Optional(), Length(max=120)])
    ip_address = StringField("IP Address", validators=[DataRequired(), Length(max=80)])
    owner = StringField("Asset Owner", validators=[DataRequired(), Length(max=120)])
    owner_phone = StringField("Owner Phone", validators=[Optional(), Length(max=50)])
    owner_email = StringField("Owner Email", validators=[Optional(), Email(), Length(max=120)])
    department = StringField("Department", validators=[DataRequired(), Length(max=120)])
    operating_system = SelectField("Operating System", choices=ASSET_OS_CHOICES, validators=[DataRequired()])
    asset_type = SelectField(
        "Asset type",
        choices=[
            ("Workstation", "Workstation"),
            ("Server", "Server"),
            ("Domain Controller", "Domain Controller"),
            ("Database", "Database"),
            ("Firewall", "Firewall"),
            ("Switch", "Switch"),
            ("Router", "Router"),
            ("Cloud Instance", "Cloud Instance"),
            ("Application", "Application"),
            ("Email Server", "Email Server"),
            ("Web Server", "Web Server"),
            ("Other", "Other"),
        ],
        validators=[DataRequired()],
    )
    criticality = SelectField("Criticality", choices=[("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low")], validators=[DataRequired()])
    business_function = StringField("Business Function", validators=[Optional(), Length(max=160)])
    description = TextAreaField("Asset Description", validators=[Optional(), Length(max=1600)])
    location = StringField("Location", validators=[Optional(), Length(max=120)])
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=1200)])
    submit = SubmitField("Save asset")


class CaseForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=180)])
    description = TextAreaField("Description", validators=[DataRequired()])
    severity = SelectField("Severity", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")])
    status = SelectField(
        "Status",
        choices=[
            ("SUBMITTED_FOR_REVIEW", "Submitted for Review"),
            ("ASSIGNED", "Assigned"),
            ("INVESTIGATING", "Investigating"),
            ("CLOSED", "Closed"),
        ],
    )
    assignee_id = SelectField("Assignee", coerce=int, validators=[Optional()])
    source = SelectField(
        "Source",
        choices=[
            ("Manual", "Manual"),
            ("SIEM Webhook", "SIEM Webhook"),
            ("Wazuh", "Wazuh"),
            ("Splunk", "Splunk"),
            ("Microsoft Sentinel", "Microsoft Sentinel"),
            ("QRadar", "QRadar"),
            ("Elastic", "Elastic"),
            ("Security Onion", "Security Onion"),
            ("Shuffle", "Shuffle"),
            ("API", "API"),
        ],
    )
    incident_type = SelectField("Incident Type", choices=INCIDENT_TYPE_CHOICES, validators=[Optional()])
    business_impact = SelectField("Business Impact", choices=BUSINESS_IMPACT_CHOICES, validators=[Optional()])
    root_cause = TextAreaField("Root Cause", validators=[Optional(), Length(max=4000)])
    resolution_summary = TextAreaField("Resolution Summary", validators=[Optional(), Length(max=4000)])
    lessons_learned = TextAreaField("Lessons Learned", validators=[Optional(), Length(max=4000)])
    validation_performed = TextAreaField("Validation Performed", validators=[Optional(), Length(max=4000)])
    closure_notes = TextAreaField("Closure Notes", validators=[Optional(), Length(max=4000)])
    cve_id = StringField("CVE ID", validators=[Optional(), Length(max=80)])
    cvss_score = StringField("CVSS Score", validators=[Optional(), Length(max=20)])
    affected_software = StringField("Affected Software", validators=[Optional(), Length(max=160)])
    affected_version = StringField("Affected Version", validators=[Optional(), Length(max=80)])
    fixed_version = StringField("Fixed Version", validators=[Optional(), Length(max=80)])
    patch_status = SelectField("Patch Status", choices=PATCH_STATUS_CHOICES, validators=[Optional()])
    remediation_owner = StringField("Remediation Owner", validators=[Optional(), Length(max=120)])
    rule_id = StringField("Rule ID", validators=[Optional(), Length(max=120)])
    mitre_tactic = StringField("MITRE tactic", validators=[Optional(), Length(max=120)])
    mitre_technique = StringField("MITRE technique", validators=[Optional(), Length(max=120)])
    affected_host = StringField("Affected host", validators=[Optional(), Length(max=120)])
    affected_user = StringField("Affected user", validators=[Optional(), Length(max=120)])
    source_ip = StringField("Source IP", validators=[Optional(), Length(max=80)])
    destination_ip = StringField("Destination IP", validators=[Optional(), Length(max=80)])
    closure_reason = TextAreaField("Closure reason", validators=[Optional(), Length(max=1200)])
    submit = SubmitField("Save case")


class CaseResolutionForm(FlaskForm):
    business_impact = SelectField("Business Impact", choices=BUSINESS_IMPACT_CHOICES, validators=[Optional()])
    root_cause = TextAreaField("Root Cause", validators=[Optional(), Length(max=4000)])
    resolution_summary = TextAreaField("Resolution Summary", validators=[Optional(), Length(max=4000)])
    lessons_learned = TextAreaField("Lessons Learned", validators=[Optional(), Length(max=4000)])
    validation_performed = TextAreaField("Validation Performed", validators=[Optional(), Length(max=4000)])
    closure_notes = TextAreaField("Closure Notes", validators=[Optional(), Length(max=4000)])
    submit = SubmitField("Save resolution")


class ManualCaseForm(FlaskForm):
    title = StringField("Case Title", validators=[DataRequired(), Length(max=180)])
    case_type = SelectField("Case Type *", choices=CASE_TYPE_CHOICES, validators=[DataRequired()])
    severity = SelectField("Severity", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")])
    due_at = DateTimeLocalField("Due Date & Time *", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    asset_id = SelectField("Linked Asset *", coerce=int, validators=[DataRequired()])
    assignee_ids = SelectMultipleField("Assign Analyst *", coerce=int, validators=[DataRequired()])
    playbook_id = SelectField("Playbook", coerce=int, validators=[Optional()])
    description = TextAreaField("Case Summary *", validators=[DataRequired(), Length(max=4000)])
    submit = SubmitField("Create case")


class NoteForm(FlaskForm):
    body = TextAreaField("Note", validators=[DataRequired(), Length(max=4000)])
    submit = SubmitField("Add note")


class IOCForm(FlaskForm):
    type = SelectField("Type", choices=[("IP", "IP Address"), ("DOMAIN", "Domain"), ("HOST", "Hostname"), ("URL", "URL"), ("USER", "Username"), ("EMAIL", "Email"), ("PROCESS", "Process"), ("FILE", "File"), ("REGISTRY", "Registry Key"), ("HASH", "File Hash"), ("SERVICE", "Service")])
    value = StringField("Value", validators=[DataRequired(), Length(max=500)])
    confidence = SelectField("Confidence", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High")])
    source = StringField("Source", validators=[Optional(), Length(max=120)])
    tags = StringField("Tags", validators=[Optional(), Length(max=250)])
    analyst_notes = TextAreaField("Analyst notes", validators=[Optional(), Length(max=1200)])
    submit = SubmitField("Add IOC")


class EvidenceForm(FlaskForm):
    file = FileField("Evidence file", validators=[DataRequired(), FileAllowed(EVIDENCE_TYPES)])
    submit = SubmitField("Upload evidence")


class TaskForm(FlaskForm):
    title = StringField("Task", validators=[DataRequired(), Length(max=180)])
    submit = SubmitField("Add task")


class PlaybookTemplateForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=120)])
    category = SelectField("Playbook Category", choices=PLAYBOOK_CATEGORY_CHOICES, default="Generic", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Optional(), Length(max=1200)])
    match_type = SelectField(
        "Match type",
        choices=[
            ("RULE_ID", "SIEM Rule ID"),
            ("CATEGORY", "Source Category"),
            ("MITRE_TACTIC", "MITRE Tactic"),
            ("ALERT_TYPE", "Alert Type"),
            ("CASE_TYPE", "Case Type"),
            ("GENERIC", "Generic Fallback"),
        ],
    )
    match_value = StringField("Match value", validators=[Optional(), Length(max=160)])
    priority = IntegerField("Priority", validators=[DataRequired(), NumberRange(min=1, max=999)], default=100)
    is_active = BooleanField("Active", default=True)
    tasks_text = TextAreaField("Investigation steps", validators=[DataRequired(), Length(max=6000)])
    submit = SubmitField("Save playbook")


class PlaybookImportForm(FlaskForm):
    playbook_file = FileField("Import playbook JSON", validators=[DataRequired(), FileAllowed(["json"])])
    submit = SubmitField("Import playbook")


class ContainmentActionForm(FlaskForm):
    action_type = SelectField(
        "Action",
        choices=[
            ("BLOCK_IP", "Block IP"),
            ("DISABLE_USER", "Disable User"),
            ("KILL_PROCESS", "Kill Process"),
            ("ISOLATE_HOST", "Isolate Host"),
            ("ADD_FIREWALL_RULE", "Add Firewall Rule"),
            ("QUARANTINE_FILE", "Quarantine File"),
            ("CUSTOM_SCRIPT", "Custom Script"),
        ],
    )
    target = StringField("Target", validators=[DataRequired(), Length(max=255)])
    target_host = StringField("Target host", validators=[Optional(), Length(max=120)])
    risk_level = SelectField("Risk level", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")])
    approval_requirement = SelectField(
        "Approval requirement",
        choices=[
            ("Lead approval required", "Lead approval required"),
            ("Admin approval required", "Admin approval required"),
            ("Emergency lead/admin approval", "Emergency lead/admin approval"),
        ],
    )
    reason = TextAreaField("Reason", validators=[DataRequired(), Length(max=1200)])
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=1200)])
    submit = SubmitField("Request action")


class SettingsForm(FlaskForm):
    report_template = FileField("Report template", validators=[Optional(), FileAllowed(["docx"])])
    webhook_api_key = StringField("Webhook API key", validators=[Optional(), Length(min=16, max=200)])
    ai_enabled = BooleanField("Enable AI-powered report generation")
    ai_provider = SelectField(
        "AI Provider",
        choices=provider_choices(),
    )
    ai_model = SelectField("AI Model", choices=all_model_choices())
    ai_api_key = PasswordField("AI API Key", validators=[Optional(), Length(max=500)])
    ai_endpoint = StringField("Custom AI Endpoint", validators=[Optional(), Length(max=300)])
    session_timeout_minutes = IntegerField("Session timeout (minutes)", validators=[DataRequired(), NumberRange(min=5, max=1440)])
    login_logout_retention_days = IntegerField("Login/logout retention (days)", validators=[DataRequired(), NumberRange(min=1, max=3650)])
    failed_login_retention_days = IntegerField("Failed login retention (days)", validators=[DataRequired(), NumberRange(min=1, max=3650)])
    case_admin_security_retention_days = IntegerField("Case/Admin/Security log retention (days)", validators=[DataRequired(), NumberRange(min=1, max=3650)])
    archive_retention_years = IntegerField("Archive retention (years)", validators=[DataRequired(), NumberRange(min=1, max=25)])
    enable_auto_archive = BooleanField("Enable auto archive")
    enable_auto_delete = BooleanField("Enable auto delete")
    submit = SubmitField("Save settings")


class EmailSettingsForm(FlaskForm):
    smtp_host = StringField("SMTP Host", validators=[Optional(), Length(max=160)])
    smtp_port = IntegerField("SMTP Port", validators=[Optional(), NumberRange(min=1, max=65535)])
    smtp_username = StringField("SMTP Username", validators=[Optional(), Length(max=180)])
    smtp_password = PasswordField("SMTP Password", validators=[Optional(), Length(max=255)])
    use_tls = BooleanField("Use STARTTLS")
    use_ssl = BooleanField("Use SSL")
    from_name = StringField("From Name", validators=[Optional(), Length(max=120)])
    from_email = StringField("From Email", validators=[Optional(), Email(), Length(max=120)])
    test_email = StringField("Test Email", validators=[Optional(), Email(), Length(max=120)])
    submit = SubmitField("Save email settings")
