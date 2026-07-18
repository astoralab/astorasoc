from datetime import timezone

from sqlalchemy import func, or_

from app import db
from app.alert_normalizer import normalize_alert
from app.models import Asset, utcnow


def normalize_asset_key(value):
    return (value or "").strip().lower()


def find_matching_asset(*values):
    candidates = [value for value in (normalize_asset_key(item) for item in values) if value]
    if not candidates:
        return None
    return (
        Asset.query.filter(
            or_(
                func.lower(Asset.hostname).in_(candidates),
                func.lower(Asset.asset_name).in_(candidates),
                func.lower(Asset.ip_address).in_(candidates),
            )
        )
        .order_by(Asset.criticality.asc(), Asset.hostname.asc())
        .first()
    )


def find_matching_asset_by_identity(*values):
    candidates = [value for value in (normalize_asset_key(item) for item in values) if value]
    if not candidates:
        return None
    return (
        Asset.query.filter(or_(func.lower(Asset.hostname).in_(candidates), func.lower(Asset.asset_name).in_(candidates)))
        .order_by(Asset.criticality.asc(), Asset.hostname.asc())
        .first()
    )


def find_matching_asset_by_ip(*values):
    candidates = [value for value in (normalize_asset_key(item) for item in values) if value]
    if not candidates:
        return None
    return (
        Asset.query.filter(func.lower(Asset.ip_address).in_(candidates))
        .order_by(Asset.criticality.asc(), Asset.hostname.asc())
        .first()
    )


def link_alert_asset(alert):
    normalized = alert.raw_json.get("normalized", {}) if isinstance(alert.raw_json, dict) else {}
    if not normalized and isinstance(alert.raw_json, dict):
        normalized = normalize_alert(alert.raw_json)
    asset = find_matching_asset_by_identity(
        normalized.get("host"),
        normalized.get("hostname"),
        normalized.get("agent_name"),
        alert.affected_host,
        normalized.get("asset_identifier"),
    )
    if not asset:
        asset = find_matching_asset_by_ip(
            alert.source_ip,
            alert.destination_ip,
            normalized.get("source_ip"),
            normalized.get("destination_ip"),
            normalized.get("agent_ip"),
            normalized.get("host_ip"),
        )
    if asset:
        alert.asset_id = asset.id
        touch_asset(asset, alert.created_at)
    return asset


def link_case_asset(case):
    asset = find_matching_asset(case.affected_host, case.source_ip, case.destination_ip)
    if asset:
        case.asset_id = asset.id
        touch_asset(asset, case.updated_at or case.created_at)
        for alert in case.alerts:
            if not alert.asset_id:
                alert.asset_id = asset.id
    return asset


def relink_assets_for(asset):
    host = normalize_asset_key(asset.hostname)
    name = normalize_asset_key(asset.asset_name)
    ip = normalize_asset_key(asset.ip_address)
    if not host and not name and not ip:
        return {"alerts": 0, "cases": 0}

    def matches(model):
        checks = []
        if host:
            checks.append(func.lower(model.affected_host) == host)
        if name:
            checks.append(func.lower(model.affected_host) == name)
        if ip:
            checks.extend([func.lower(model.source_ip) == ip, func.lower(model.destination_ip) == ip])
        return or_(*checks)

    from app.models import Alert, Case

    alerts = Alert.query.filter(matches(Alert)).all()
    cases = Case.query.filter(matches(Case)).all()
    for alert in alerts:
        alert.asset_id = asset.id
    for case in cases:
        case.asset_id = asset.id
    latest_times = [item.created_at for item in alerts if item.created_at] + [item.updated_at or item.created_at for item in cases if item.updated_at or item.created_at]
    if latest_times:
        touch_asset(asset, max(latest_times))
    db.session.flush()
    return {"alerts": len(alerts), "cases": len(cases)}


def touch_asset(asset, seen_at=None):
    seen_at = normalize_seen_at(seen_at or utcnow())
    current_seen = normalize_seen_at(asset.last_seen_at)
    if not current_seen or seen_at > current_seen:
        asset.last_seen_at = seen_at
    asset.status = "Online"


def normalize_seen_at(value):
    if not value:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
