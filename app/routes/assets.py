import ipaddress
import os
import re
import subprocess
import zipfile
from io import BytesIO
from datetime import timedelta, timezone

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user
from sqlalchemy import func, or_
from sqlalchemy.orm import selectinload

from app import db
from app.asset_matching import relink_assets_for
from app.decorators import roles_required
from app.docx_reports import DOCUMENT_XML_TEMPLATE, ROOT_RELS, STYLES_XML, content_types_xml, document_rels_xml, footer, kv_table, paragraph, section, subtitle, table, title
from app.forms import ASSET_BUSINESS_FUNCTION_CHOICES, ASSET_DEPARTMENT_CHOICES, AssetForm
from app.models import Alert, Asset, Case, IOC, utcnow
from app.utils import audit, format_short_datetime, relative_time, setting, tracking_label
from app.workflow import CASE_CLOSED, alert_statuses, case_statuses

assets_bp = Blueprint("assets", __name__)

CRITICALITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
OPEN_ALERT_STATUSES = ["NEW", "PENDING_REVIEW"]
OPEN_CASE_STATUSES = ["ASSIGNED", "INVESTIGATING", "SUBMITTED_FOR_REVIEW"]
ONLINE_WINDOW = timedelta(minutes=15)
OFFLINE_AFTER = timedelta(hours=24)


@assets_bp.route("/assets")
@roles_required("Admin", "Lead", "Analyst")
def assets():
    refresh_all_asset_presence()
    search = request.args.get("q", "").strip()
    filters = {
        "criticality": request.args.get("criticality", "").strip(),
        "os": request.args.get("os", "").strip(),
        "department": request.args.get("department", "").strip(),
        "status": request.args.get("status", "").strip(),
        "asset_type": request.args.get("asset_type", "").strip(),
    }
    query = Asset.query.options(selectinload(Asset.alerts), selectinload(Asset.cases))
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Asset.asset_name.ilike(like), Asset.hostname.ilike(like), Asset.ip_address.ilike(like), Asset.owner.ilike(like), Asset.department.ilike(like)))
    if filters["criticality"]:
        query = query.filter(Asset.criticality == filters["criticality"])
    if filters["os"]:
        query = query.filter(Asset.operating_system == filters["os"])
    if filters["department"]:
        query = query.filter(Asset.department == filters["department"])
    if filters["status"]:
        query = query.filter(Asset.status == filters["status"])
    if filters["asset_type"]:
        query = query.filter(Asset.asset_type == filters["asset_type"])
    items = query.all()
    items.sort(key=lambda item: (CRITICALITY_ORDER.get(item.criticality, 9), -(asset_risk_score(item)["score"]), item.asset_name or item.hostname))
    return render_template(
        "assets/list.html",
        assets=items,
        search=search,
        filters=filters,
        filter_options=asset_filter_options(),
        asset_risk_score=asset_risk_score,
        department_short_label=department_short_label,
        relative_time=relative_time,
    )


@assets_bp.route("/assets/download")
@roles_required("Admin", "Lead", "Analyst")
def download_assets():
    refresh_all_asset_presence()
    items = Asset.query.options(selectinload(Asset.alerts), selectinload(Asset.cases)).all()
    items.sort(key=lambda item: (CRITICALITY_ORDER.get(item.criticality, 9), -(asset_risk_score(item)["score"]), item.asset_name or item.hostname))
    buffer = build_asset_inventory_docx(items, report_template_path())
    audit("asset_inventory_downloaded", f"Downloaded asset inventory report. Count={len(items)}.", current_user.id)
    db.session.commit()
    return send_file(
        buffer,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=f"astorasoc-assets-{utcnow():%Y%m%d-%H%M}.docx",
    )


@assets_bp.route("/assets/<int:asset_id>")
@roles_required("Admin", "Lead", "Analyst")
def asset_detail(asset_id):
    asset = Asset.query.options(selectinload(Asset.alerts), selectinload(Asset.cases)).get_or_404(asset_id)
    refresh_asset_presence(asset, probe=True)
    db.session.commit()
    related_alerts = Alert.query.filter_by(asset_id=asset.id).order_by(Alert.created_at.desc()).limit(20).all()
    related_cases = Case.query.filter_by(asset_id=asset.id).order_by(Case.updated_at.desc()).limit(20).all()
    related_iocs = asset_iocs(asset, limit=30)
    timeline_rows = asset_timeline(asset, related_alerts, related_cases, related_iocs)
    return render_template(
        "assets/detail.html",
        asset=asset,
        related_alerts=related_alerts,
        related_cases=related_cases,
        related_iocs=related_iocs,
        timeline_rows=timeline_rows,
        risk=asset_risk_score(asset),
        relative_time=relative_time,
        tracking_label=tracking_label,
    )


@assets_bp.route("/assets/new", methods=["GET", "POST"])
@roles_required("Admin")
def new_asset():
    form = AssetForm()
    if form.validate_on_submit():
        asset = Asset(created_by_id=current_user.id)
        apply_asset_form(asset, form, is_new=True)
        db.session.add(asset)
        db.session.flush()
        counts = relink_assets_for(asset)
        refresh_asset_presence(asset, probe=True)
        audit("asset_created", f"Asset {asset.asset_name or asset.hostname} created and linked to {counts['alerts']} alerts / {counts['cases']} cases.", current_user.id)
        db.session.commit()
        flash("Asset created and matching alerts/cases linked.", "success")
        return redirect(url_for("assets.asset_detail", asset_id=asset.id))
    return render_template("assets/form.html", form=form, title="New Asset")


@assets_bp.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@roles_required("Admin")
def edit_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    form = AssetForm(obj=asset)
    ensure_os_choice(form, asset.operating_system)
    if form.validate_on_submit():
        before = {
            "owner": asset.owner,
            "criticality": asset.criticality,
            "status": asset.status,
        }
        apply_asset_form(asset, form)
        counts = relink_assets_for(asset)
        refresh_asset_presence(asset, probe=True)
        audit("asset_updated", f"Asset {asset.asset_name or asset.hostname} updated and linked to {counts['alerts']} alerts / {counts['cases']} cases.", current_user.id)
        log_asset_field_changes(asset, before)
        db.session.commit()
        flash("Asset updated and matching alerts/cases linked.", "success")
        return redirect(url_for("assets.asset_detail", asset_id=asset.id))
    return render_template("assets/form.html", form=form, title=f"Edit Asset {asset.asset_name or asset.hostname}")


@assets_bp.route("/assets/<int:asset_id>/delete", methods=["POST"])
@roles_required("Admin")
def delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    name = asset.asset_name or asset.hostname
    Alert.query.filter_by(asset_id=asset.id).update({"asset_id": None})
    Case.query.filter_by(asset_id=asset.id).update({"asset_id": None})
    db.session.delete(asset)
    audit("asset_deleted", f"Asset {name} deleted.", current_user.id)
    db.session.commit()
    flash("Asset deleted.", "success")
    return redirect(url_for("assets.assets"))


@assets_bp.route("/api/assets/detect-os", methods=["POST"])
@roles_required("Admin")
def detect_asset_os():
    payload = request.get_json(silent=True) or {}
    result = detect_os_from_ip(payload.get("ip_address", ""))
    return jsonify(result), 400 if result.get("error") else 200


@assets_bp.route("/api/assets/<int:asset_id>/status", methods=["POST"])
@roles_required("Admin", "Lead", "Analyst")
def asset_status_probe(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    before = asset.status
    refresh_asset_presence(asset, probe=True)
    if before != asset.status:
        audit("asset_status_changed", f"Asset {asset.asset_name or asset.hostname} status changed from {before or 'Unknown'} to {asset.status or 'Unknown'}.", current_user.id)
    db.session.commit()
    return jsonify({"status": asset.status or "Unknown", "last_seen": relative_time(asset.last_seen_at) if asset.last_seen_at else ""})


def detect_os_from_ip(ip_value):
    ip_text = str(ip_value or "").strip()
    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return {"detected": False, "error": "Enter a valid IP address before detecting OS."}

    known = lookup_known_os_by_ip(ip_text)
    if known:
        return {
            "detected": True,
            "os": known["os"],
            "family": known["family"],
            "confidence": known["confidence"],
            "message": known["message"],
            "manual_available": True,
        }

    ping = run_ping(ip_text)
    if ping.get("error"):
        return {"detected": False, "os": "", "message": ping["error"], "manual_available": True}

    ttl_match = re.search(r"\bttl[=\s:]+(\d{1,3})\b", ping.get("output", ""), re.IGNORECASE)
    if not ttl_match:
        return {"detected": False, "os": "", "message": "Host responded, but OS fingerprint was not available. Choose manually.", "manual_available": True}

    ttl = int(ttl_match.group(1))
    inferred = infer_os_from_ttl(ttl)
    return {
        "detected": inferred["os"] != "",
        "os": inferred["os"],
        "family": inferred["family"],
        "ttl": ttl,
        "confidence": inferred["confidence"],
        "message": inferred["message"],
        "manual_available": True,
    }


def run_ping(ip_text):
    commands = [
        ["ping", "-c", "1", "-W", "1", ip_text],
        ["ping", "-n", "1", "-w", "1000", ip_text],
    ]
    last_error = "OS detection could not reach the host. Choose manually."
    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
        except FileNotFoundError:
            return {"error": "Ping is not available in this environment. Choose manually."}
        except subprocess.TimeoutExpired:
            last_error = "OS detection timed out. Choose manually."
            continue
        output = f"{completed.stdout}\n{completed.stderr}"
        if completed.returncode == 0 or re.search(r"\bttl[=\s:]+\d{1,3}\b", output, re.IGNORECASE):
            return {"output": output}
        if output.strip():
            last_error = "Host did not respond to OS detection. Choose manually."
    return {"error": last_error}


def infer_os_from_ttl(ttl):
    if ttl >= 240:
        return {"os": "Appliance / Embedded OS", "family": "Network appliance", "confidence": "Medium", "message": "Detected likely network appliance from ICMP TTL."}
    if 110 <= ttl <= 140:
        return {"os": "Windows 11", "family": "Windows", "confidence": "Medium", "message": "Detected likely Windows endpoint from ICMP TTL."}
    if 45 <= ttl <= 75:
        return {"os": "Ubuntu 24.04 LTS", "family": "Linux/Unix", "confidence": "Medium", "message": "Detected likely Linux/Unix host from ICMP TTL."}
    return {"os": "", "family": "Unknown", "confidence": "Low", "message": "OS family could not be inferred from ICMP TTL. Choose manually."}


def lookup_known_os_by_ip(ip_text):
    asset = (
        Asset.query.filter(Asset.ip_address == ip_text, Asset.operating_system.isnot(None), Asset.operating_system != "")
        .order_by(Asset.updated_at.desc())
        .first()
    )
    if asset and asset.operating_system != "Unknown":
        return {"os": asset.operating_system, "family": os_family(asset.operating_system), "confidence": "High", "message": "Matched OS from existing asset inventory."}

    alerts = (
        Alert.query.filter(or_(Alert.source_ip == ip_text, Alert.destination_ip == ip_text))
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )
    for alert in alerts:
        os_value = extract_os_from_payload(alert.raw_json)
        if os_value:
            return {"os": os_value, "family": os_family(os_value), "confidence": "Medium", "message": "Matched OS from stored alert payload."}
    return None


def extract_os_from_payload(value, depth=0):
    if depth > 5:
        return None
    os_keys = {"os", "osname", "os_name", "operatingsystem", "operating_system", "platform"}
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z0-9_]", "", str(key).lower())
            if normalized_key in os_keys and isinstance(item, str):
                mapped = map_os_name(item)
                if mapped:
                    return mapped
            nested = extract_os_from_payload(item, depth + 1)
            if nested:
                return nested
    elif isinstance(value, list):
        for item in value[:20]:
            nested = extract_os_from_payload(item, depth + 1)
            if nested:
                return nested
    return None


def map_os_name(value):
    text = str(value or "").strip()
    lowered = text.lower()
    if not text or lowered in {"unknown", "n/a", "na", "none", "not available"}:
        return None
    if "windows server 2025" in lowered:
        return "Windows Server 2025"
    if "windows server 2022" in lowered:
        return "Windows Server 2022"
    if "windows server 2019" in lowered:
        return "Windows Server 2019"
    if "windows server 2016" in lowered:
        return "Windows Server 2016"
    if "windows server" in lowered:
        return "Windows Server 2022"
    if "windows 11" in lowered:
        return "Windows 11"
    if "windows 10" in lowered:
        return "Windows 10"
    if "windows" in lowered:
        return "Windows 11"
    if "ubuntu 24" in lowered:
        return "Ubuntu 24.04 LTS"
    if "ubuntu 22" in lowered:
        return "Ubuntu 22.04 LTS"
    if "ubuntu 20" in lowered:
        return "Ubuntu 20.04 LTS"
    if "ubuntu" in lowered:
        return "Ubuntu 24.04 LTS"
    if "debian" in lowered:
        return "Debian"
    if "red hat" in lowered or "rhel" in lowered:
        return "Red Hat Enterprise Linux"
    if "centos" in lowered:
        return "CentOS"
    if "rocky" in lowered:
        return "Rocky Linux"
    if "almalinux" in lowered:
        return "AlmaLinux"
    if "fedora" in lowered:
        return "Fedora"
    if "suse" in lowered:
        return "SUSE Linux Enterprise"
    if "kali" in lowered:
        return "Kali Linux"
    if "amazon linux" in lowered:
        return "Amazon Linux"
    if "oracle linux" in lowered:
        return "Oracle Linux"
    if "arch" in lowered:
        return "Arch Linux"
    if "linux" in lowered:
        return "Ubuntu 24.04 LTS"
    if "macos" in lowered or "mac os" in lowered:
        return "macOS"
    if "android" in lowered:
        return "Android"
    if "chromeos" in lowered or "chrome os" in lowered:
        return "ChromeOS"
    if "esxi" in lowered:
        return "VMware ESXi"
    if "fortios" in lowered or "fortigate" in lowered:
        return "FortiOS"
    if "pan-os" in lowered or "palo alto" in lowered:
        return "Palo Alto PAN-OS"
    if "junos" in lowered:
        return "Juniper Junos"
    if "routeros" in lowered or "mikrotik" in lowered:
        return "MikroTik RouterOS"
    if "cisco" in lowered:
        return "Cisco IOS"
    return None


def os_family(os_value):
    lowered = str(os_value or "").lower()
    if "windows" in lowered:
        return "Windows"
    if any(token in lowered for token in ["ubuntu", "debian", "linux", "centos", "fedora", "suse", "freebsd", "openbsd"]):
        return "Linux/Unix"
    if any(token in lowered for token in ["cisco", "fortios", "pan-os", "junos", "routeros", "firewall", "appliance"]):
        return "Network appliance"
    if any(token in lowered for token in ["macos", "ios", "android", "chromeos"]):
        return "Endpoint"
    return "Unknown"


def report_template_path():
    stored = setting("report_template_file")
    if stored and stored.lower().endswith(".docx"):
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], "report_templates", stored)
        if os.path.exists(path):
            return path
    default_path = os.path.join(current_app.root_path, "static", "templates", "default-report-template.docx")
    return default_path if os.path.exists(default_path) else None


def build_asset_inventory_docx(items, template_path=None):
    body = asset_inventory_body(items)
    if template_path and os.path.exists(template_path):
        try:
            return append_body_to_docx_template(template_path, body)
        except Exception:
            current_app.logger.exception("Failed to use asset inventory DOCX template; falling back to default export.")
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", content_types_xml([]))
        docx.writestr("_rels/.rels", ROOT_RELS)
        docx.writestr("word/_rels/document.xml.rels", document_rels_xml([]))
        docx.writestr("word/styles.xml", STYLES_XML)
        docx.writestr("word/document.xml", DOCUMENT_XML_TEMPLATE.format(body=body))
    output.seek(0)
    return output


def append_body_to_docx_template(path, body):
    output = BytesIO()
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename == "word/document.xml":
                text = data.decode("utf-8")
                marker = "<w:sectPr"
                index = text.rfind(marker)
                if index != -1:
                    text = text[:index] + body + text[index:]
                else:
                    text = text.replace("</w:body>", body + "</w:body>")
                data = text.encode("utf-8")
            target.writestr(item, data)
    output.seek(0)
    return output


def asset_inventory_body(items):
    generated_at = format_short_datetime(utcnow())
    generated_by = getattr(current_user, "full_name", None) or getattr(current_user, "username", None) or "AstoraSOC"
    high_risk = [asset for asset in items if asset_risk_score(asset)["score"] >= 50]
    critical_assets = [asset for asset in items if asset.criticality == "Critical"]
    open_alerts = sum(len([alert for alert in asset.alerts if alert.status in OPEN_ALERT_STATUSES]) for asset in items)
    open_cases = sum(len([case for case in asset.cases if case.status in OPEN_CASE_STATUSES]) for asset in items)
    blocks = [
        title("AstoraSOC Asset Inventory"),
        subtitle("Security Asset Intelligence Export"),
        kv_table([
            ("Generated", generated_at),
            ("Generated By", generated_by),
            ("Total Assets", str(len(items))),
            ("Critical Assets", str(len(critical_assets))),
            ("High/Critical Risk Assets", str(len(high_risk))),
            ("Open Linked Alerts", str(open_alerts)),
            ("Open Linked Cases", str(open_cases)),
        ]),
        section("Asset Inventory"),
        table(
            ["Asset", "Criticality", "IP", "Owner", "Department", "OS", "Status", "Risk", "Alerts", "Cases"],
            [asset_inventory_row(asset) for asset in items],
            [1300, 850, 1000, 1150, 1050, 1150, 850, 1150, 850, 850],
        ),
    ]
    if high_risk:
        blocks.extend([
            section("High Risk Assets"),
            table(
                ["Asset", "Risk", "Criticality", "Open Alerts", "Open Cases", "Business Function"],
                [high_risk_asset_row(asset) for asset in high_risk],
                [1600, 1200, 1000, 1000, 1000, 3560],
            ),
        ])
    blocks.append(footer("Generated by AstoraSOC SOC & Incident Response Platform"))
    return "".join(blocks)


def asset_inventory_row(asset):
    risk = asset_risk_score(asset)
    return [
        clean_report_value(asset.asset_name or asset.hostname),
        clean_report_value(asset.criticality),
        clean_report_value(asset.ip_address),
        clean_report_value(asset.owner),
        clean_report_value(asset.department),
        clean_report_value(asset.operating_system),
        clean_report_value(asset.status),
        f"{risk['score']}/100 {risk['label']}",
        str(len(asset.alerts)),
        str(len(asset.cases)),
    ]


def high_risk_asset_row(asset):
    risk = asset_risk_score(asset)
    return [
        clean_report_value(asset.asset_name or asset.hostname),
        f"{risk['score']}/100 {risk['label']}",
        clean_report_value(asset.criticality),
        str(len([alert for alert in asset.alerts if alert.status in OPEN_ALERT_STATUSES])),
        str(len([case for case in asset.cases if case.status in OPEN_CASE_STATUSES])),
        clean_report_value(asset.business_function),
    ]


def clean_report_value(value):
    return str(value).strip() if value not in (None, "") else "-"


def apply_asset_form(asset, form, is_new=False):
    for field in ["asset_name", "hostname", "ip_address", "owner", "owner_phone", "owner_email", "department", "operating_system", "asset_type", "criticality", "business_function", "description", "location", "notes"]:
        value = getattr(form, field).data
        setattr(asset, field, value.strip() if isinstance(value, str) else value)
    asset.department = normalize_asset_metadata(asset.department, ASSET_DEPARTMENT_CHOICES, DEPARTMENT_ALIASES)
    asset.business_function = normalize_asset_metadata(asset.business_function, ASSET_BUSINESS_FUNCTION_CHOICES, BUSINESS_FUNCTION_ALIASES)
    if is_new and not asset.status:
        asset.status = "Unknown"


DEPARTMENT_ALIASES = {
    "hr": "Human Resources (HR)",
    "ict": "Information and Communications Technology (ICT)",
    "it": "Information and Communications Technology (ICT)",
    "soc": "Security Operations Center (SOC)",
    "dba": "Database Administration (DBA)",
    "r&d": "Research & Development (R&D)",
    "rnd": "Research & Development (R&D)",
}


BUSINESS_FUNCTION_ALIASES = {
    "ad": "Active Directory",
    "iam": "Identity Management",
    "lms": "Learning Management System (LMS)",
    "siem": "SIEM Platform",
    "soc": "SOC Platform",
    "vpn": "VPN Gateway",
    "dns": "DNS Service",
    "dhcp": "DHCP Service",
    "ca": "Certificate Authority",
    "cicd": "CI/CD Pipeline",
    "ci/cd": "CI/CD Pipeline",
}


def normalize_asset_metadata(value, choices, aliases=None):
    normalized = re.sub(r"\s+", " ", str(value or "")).strip()
    if not normalized:
        return normalized
    aliases = aliases or {}
    lowered = normalized.lower()
    if lowered in aliases:
        return aliases[lowered]
    canonical = {choice.lower(): choice for choice in choices}
    return canonical.get(lowered, normalized)


DEPARTMENT_SHORT_LABELS = {
    "Human Resources (HR)": "HR",
    "Information and Communications Technology (ICT)": "ICT",
    "Security Operations Center (SOC)": "SOC",
    "Executive Management": "Management",
    "Research & Development (R&D)": "R&D",
    "Database Administration (DBA)": "DBA",
    "Data Center Operations": "Data Center",
    "Network Operations": "Network Ops",
    "Cloud Operations": "Cloud Ops",
    "Application Development": "App Dev",
    "Software Engineering": "Engineering",
    "Risk Management": "Risk",
    "Internal Audit": "Audit",
    "Customer Support": "Support",
    "Student Affairs": "Students",
    "Academic Affairs": "Academic",
    "Library Services": "Library",
    "Facilities Management": "Facilities",
}


def department_short_label(value):
    if not value:
        return "Not Available"
    return DEPARTMENT_SHORT_LABELS.get(value, value.replace(" and ", " & "))


def refresh_asset_presence(asset, probe=False):
    latest_alert = Alert.query.filter_by(asset_id=asset.id).order_by(Alert.created_at.desc()).first()
    candidates = [normalize_presence_time(asset.last_seen_at)]
    if latest_alert:
        candidates.append(normalize_presence_time(latest_alert.created_at))
    latest = max([item for item in candidates if item], default=None)
    current_seen = normalize_presence_time(asset.last_seen_at)
    if latest and (not current_seen or latest > current_seen):
        asset.last_seen_at = latest
    telemetry_status = inferred_asset_status(asset.last_seen_at)
    if probe:
        reachability = detect_asset_reachability(asset.ip_address)
        if reachability == "Online":
            asset.status = "Online"
            asset.last_seen_at = utcnow()
            return
        if reachability == "Offline":
            asset.status = "Offline"
            return
        asset.status = telemetry_status
        return
    if telemetry_status == "Online":
        asset.status = "Online"
        return
    if not probe:
        if telemetry_status == "Unknown" and asset.status in {"Online", "Offline"}:
            return
        asset.status = telemetry_status
        return
    asset.status = telemetry_status


def detect_asset_reachability(ip_value):
    ip_text = str(ip_value or "").strip()
    if not ip_text:
        return "Unknown"
    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return "Unknown"
    result = run_ping(ip_text)
    return "Online" if not result.get("error") else "Offline"


def inferred_asset_status(last_seen_at):
    if not last_seen_at:
        return "Unknown"
    last_seen_at = normalize_presence_time(last_seen_at)
    age = utcnow() - last_seen_at
    if age <= ONLINE_WINDOW:
        return "Online"
    if age >= OFFLINE_AFTER:
        return "Offline"
    return "Unknown"


def refresh_all_asset_presence():
    changed = False
    for asset in Asset.query.options(selectinload(Asset.alerts), selectinload(Asset.cases)).all():
        before = (asset.status, asset.last_seen_at)
        refresh_asset_presence(asset, probe=False)
        if before != (asset.status, asset.last_seen_at):
            changed = True
    if changed:
        db.session.commit()


def normalize_presence_time(value):
    if not value:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def ensure_os_choice(form, value):
    if not value:
        return
    current_values = {choice[0] for choice in form.operating_system.choices}
    if value not in current_values:
        form.operating_system.choices = [(value, value)] + list(form.operating_system.choices)


def log_asset_field_changes(asset, before):
    if before["owner"] != asset.owner:
        audit("asset_owner_changed", f"Asset {asset.asset_name or asset.hostname} owner changed from {before['owner'] or 'Unassigned'} to {asset.owner or 'Unassigned'}.", current_user.id)
    if before["criticality"] != asset.criticality:
        audit("asset_criticality_changed", f"Asset {asset.asset_name or asset.hostname} criticality changed from {before['criticality']} to {asset.criticality}.", current_user.id)
    if before["status"] != asset.status:
        audit("asset_status_changed", f"Asset {asset.asset_name or asset.hostname} status changed from {before['status']} to {asset.status}.", current_user.id)


def asset_filter_options():
    def distinct(column):
        return [row[0] for row in db.session.query(column).filter(column.isnot(None), column != "").distinct().order_by(column.asc()).all()]

    departments = distinct(Asset.department)
    return {
        "criticality": ["Critical", "High", "Medium", "Low"],
        "status": ["Online", "Offline", "Unknown"],
        "department": [{"value": item, "label": department_short_label(item)} for item in departments],
        "os": distinct(Asset.operating_system),
        "asset_type": distinct(Asset.asset_type),
    }


def asset_iocs(asset, limit=None):
    alert_ids = [alert.id for alert in asset.alerts]
    case_ids = [case.id for case in asset.cases]
    if not alert_ids and not case_ids:
        return []
    query = IOC.query
    checks = []
    if alert_ids:
        checks.append(IOC.alert_id.in_(alert_ids))
    if case_ids:
        checks.append(IOC.case_id.in_(case_ids))
    rows = query.filter(or_(*checks)).order_by(IOC.last_seen_at.desc(), IOC.added_at.desc())
    if limit:
        rows = rows.limit(limit)
    seen = set()
    unique = []
    for ioc in rows.all():
        key = (ioc.type, ioc.normalized_value or ioc.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    return unique


def asset_risk_score(asset):
    active_alerts = sum(1 for alert in asset.alerts if alert.status in OPEN_ALERT_STATUSES or alert.status in alert_statuses("NEW"))
    elevated_alerts = sum(1 for alert in asset.alerts if (alert.status in OPEN_ALERT_STATUSES or alert.status in alert_statuses("NEW")) and alert.severity in {"High", "Critical"})
    open_cases = sum(1 for case in asset.cases if case.status in OPEN_CASE_STATUSES or (case.status not in case_statuses(CASE_CLOSED) and case.status != "False Positive"))
    ioc_count = len(asset_iocs(asset))
    failed_actions = sum(1 for case in asset.cases for action in getattr(case, "containment_actions", []) if action.status == "FAILED")
    recent_cutoff = utcnow() - timedelta(days=7)
    recent_events = sum(1 for alert in asset.alerts if normalize_presence_time(alert.created_at) and normalize_presence_time(alert.created_at) >= recent_cutoff)
    active_signals = active_alerts + open_cases + ioc_count + failed_actions + recent_events
    if not active_signals:
        score = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}.get(asset.criticality, 5)
    else:
        criticality_modifier = {"Critical": 8, "High": 6, "Medium": 3, "Low": 1}.get(asset.criticality, 3)
        score = min(
            100,
            criticality_modifier
            + min(active_alerts * 12, 30)
            + min(elevated_alerts * 8, 20)
            + min(open_cases * 18, 36)
            + min(ioc_count * 4, 16)
            + min(failed_actions * 15, 20)
            + min(recent_events * 3, 12),
        )
    if score >= 75:
        label, tone = "Critical Risk", "critical"
    elif score >= 50:
        label, tone = "High Risk", "high"
    elif score >= 25:
        label, tone = "Medium Risk", "medium"
    else:
        label, tone = "Low Risk", "low"
    return {"score": score, "label": label, "tone": tone, "active_alerts": active_alerts, "open_cases": open_cases, "ioc_count": ioc_count, "failed_actions": failed_actions, "recent_events": recent_events}


def asset_timeline(asset, alerts, cases, iocs):
    rows = [
        {"time": asset.created_at, "kind": "Asset Created", "details": f"{asset.asset_name or asset.hostname} was added to inventory."},
        {"time": asset.updated_at, "kind": "Asset Updated", "details": "Asset profile was last updated."},
    ]
    rows.extend({"time": alert.created_at, "kind": "Alert Received", "details": f"{alert.tracking_id or alert.event_id or alert.id} / {alert.title}"} for alert in alerts[:8])
    rows.extend({"time": case.created_at, "kind": "Case Linked", "details": f"{tracking_label(case)} / {case.title}"} for case in cases[:8])
    rows.extend({"time": ioc.added_at, "kind": "IOC Added", "details": f"{ioc.type}: {ioc.value}"} for ioc in iocs[:8])
    return sorted([row for row in rows if row["time"]], key=lambda row: row["time"], reverse=True)[:18]
