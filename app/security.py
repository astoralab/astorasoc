import ipaddress
import re

from flask import current_app, request
from werkzeug.utils import secure_filename


DOCKER_BRIDGE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "172.17.0.0/16",
        "172.18.0.0/16",
        "172.19.0.0/16",
    )
)
CLIENT_IP_HEADERS = (
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Forwarded-For",
    "Forwarded",
    "X-Real-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "Fly-Client-IP",
)


def allowed_file(filename, allowed_extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def get_client_ip():
    for header in CLIENT_IP_HEADERS:
        value = request.headers.get(header, "")
        if header == "X-Forwarded-For":
            candidate = forwarded_ip(value)
        elif header == "Forwarded":
            candidate = forwarded_ip(forwarded_header_for_values(value))
        else:
            candidate = normalize_ip(value)
        if is_real_client_ip(candidate):
            return candidate

    remote = normalize_ip(request.remote_addr)
    if is_real_client_ip(remote):
        return remote
    return "Real IP unavailable - configure proxy headers"


def client_ip():
    return get_client_ip()


def forwarded_ip(value):
    candidates = [normalize_ip(item) for item in (value or "").split(",")]
    candidates = [candidate for candidate in candidates if candidate]
    real_candidates = [candidate for candidate in candidates if is_real_client_ip(candidate)]
    return real_candidates[0] if real_candidates else None


def forwarded_header_for_values(value):
    matches = re.findall(r"(?:^|[;,])\s*for=(\"?)([^\";,]+)\1", value or "", flags=re.IGNORECASE)
    return ",".join(match[1] for match in matches)


def normalize_ip(value):
    text = (value or "").strip().strip('"').strip("'")
    if not text or text.lower() in {"unknown", "null", "none"}:
        return None
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:
        text = text.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_real_client_ip(value):
    if not value or is_docker_bridge_ip(value):
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


def is_docker_bridge_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in DOCKER_BRIDGE_NETWORKS)


def safe_original_name(filename):
    return secure_filename(filename or "upload.bin")


def security_cookie_config(app):
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("REMEMBER_COOKIE_HTTPONLY", True)
    app.config.setdefault("REMEMBER_COOKIE_SAMESITE", "Lax")
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        app.config["REMEMBER_COOKIE_SECURE"] = True
