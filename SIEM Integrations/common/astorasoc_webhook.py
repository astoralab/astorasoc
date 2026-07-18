#!/usr/bin/env python3
"""Shared dependency-free webhook helpers for AstoraSOC SIEM integrations."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_LOG_PATH = "astorasoc-integration.log"
USER_AGENT = "AstoraSOC-SIEM-Integration/1.0"


class IntegrationError(Exception):
    """Expected integration failure with a clean operator-facing message."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_log(provider: str, level: str, message: str, **fields: Any) -> None:
    record = {
        "timestamp": utc_now(),
        "integration": "astorasoc",
        "provider": provider,
        "level": level,
        "message": message,
    }
    record.update({key: value for key, value in fields.items() if value is not None})
    line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n"
    log_path = os.environ.get("ASTORASOC_INTEGRATION_LOG", DEFAULT_LOG_PATH)
    try:
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, line.encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except OSError:
        sys.stderr.write(line)


def load_json(path: str) -> Dict[str, Any]:
    try:
        if path == "-":
            payload = json.load(sys.stdin)
        else:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
    except FileNotFoundError as exc:
        raise IntegrationError(f"Input JSON file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IntegrationError(f"Input is not valid JSON: {path}") from exc
    except OSError as exc:
        raise IntegrationError(f"Unable to read input JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise IntegrationError("Input JSON must be an object.")
    return payload


def safe_get(source: Dict[str, Any], dotted_path: str) -> Any:
    current: Any = source
    for key in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_value(source: Dict[str, Any], paths: Iterable[str]) -> Optional[str]:
    for path in paths:
        value = safe_get(source, path)
        if isinstance(value, list):
            value = value[0] if value else None
        if value not in (None, ""):
            return str(value)
    return None


def normalize_severity(value: Any) -> str:
    if value in (None, ""):
        return "Medium"
    text = str(value).strip()
    try:
        numeric = int(float(text))
    except ValueError:
        lowered = text.lower()
        if lowered in {"critical", "fatal", "severe"}:
            return "Critical"
        if lowered in {"high", "major"}:
            return "High"
        if lowered in {"medium", "moderate", "warning"}:
            return "Medium"
        if lowered in {"low", "info", "informational"}:
            return "Low"
        return "Medium"
    if numeric > 20:
        if numeric >= 90:
            return "Critical"
        if numeric >= 70:
            return "High"
        if numeric >= 40:
            return "Medium"
        return "Low"
    if numeric >= 12:
        return "Critical"
    if numeric >= 8:
        return "High"
    if numeric >= 4:
        return "Medium"
    return "Low"


def build_payload(provider: str, raw: Dict[str, Any], aliases: Dict[str, Iterable[str]]) -> Dict[str, Any]:
    event_id = first_value(raw, aliases.get("event_id", ())) or first_value(raw, ("id", "event.id", "_id"))
    title = first_value(raw, aliases.get("title", ())) or f"{provider} security alert"
    timestamp = first_value(raw, aliases.get("timestamp", ())) or utc_now()
    return {
        "schema_version": "1.0",
        "integration": provider,
        "source": provider,
        "event": {
            "provider": provider.lower().replace(" ", "_"),
            "id": event_id,
            "timestamp": timestamp,
            "category": first_value(raw, aliases.get("category", ())) or "security_alert",
        },
        "title": title[:180],
        "description": (first_value(raw, aliases.get("description", ())) or title)[:4000],
        "severity": normalize_severity(first_value(raw, aliases.get("severity", ()))),
        "rule_id": first_value(raw, aliases.get("rule_id", ())),
        "affected_host": first_value(raw, aliases.get("affected_host", ())),
        "affected_user": first_value(raw, aliases.get("affected_user", ())),
        "source_ip": first_value(raw, aliases.get("source_ip", ())),
        "destination_ip": first_value(raw, aliases.get("destination_ip", ())),
        "mitre_tactic": first_value(raw, aliases.get("mitre_tactic", ())),
        "mitre_technique": first_value(raw, aliases.get("mitre_technique", ())),
        "raw_alert": raw,
    }


def validate_url(url: str) -> str:
    if not url:
        raise IntegrationError("Missing AstoraSOC webhook URL.")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise IntegrationError("AstoraSOC webhook URL must be an absolute http(s) URL.")
    return url


def validate_api_key(api_key: str) -> str:
    if not api_key or len(api_key.strip()) < 16:
        raise IntegrationError("Missing or unsafe AstoraSOC webhook API key.")
    return api_key.strip()


def post_json(url: str, api_key: str, payload: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key,
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(4096).decode("utf-8", "replace")
            status = int(response.getcode())
    except urllib.error.HTTPError as exc:
        response_body = exc.read(4096).decode("utf-8", "replace")
        raise IntegrationError(f"AstoraSOC webhook returned HTTP {exc.code}: {response_body[:500]}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise IntegrationError(f"Unable to reach AstoraSOC webhook: {reason}") from exc
    except socket.timeout as exc:
        raise IntegrationError(f"AstoraSOC webhook request timed out after {timeout}s.") from exc
    if status < 200 or status >= 300:
        raise IntegrationError(f"AstoraSOC webhook returned HTTP {status}: {response_body[:500]}")
    try:
        parsed = json.loads(response_body) if response_body else {}
    except json.JSONDecodeError:
        parsed = {"raw_response": response_body}
    return {"status": status, "response": parsed}


def run_provider_bridge(provider: str, aliases: Dict[str, Iterable[str]], argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=f"Forward {provider} alerts to AstoraSOC.")
    parser.add_argument("input", nargs="?", default="-", help="Alert JSON path, or '-' for stdin.")
    parser.add_argument("api_key", nargs="?", help="AstoraSOC webhook API key. Can also be ASTORASOC_API_KEY.")
    parser.add_argument("webhook_url", nargs="?", help="AstoraSOC webhook URL. Can also be ASTORASOC_WEBHOOK_URL.")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("ASTORASOC_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)))
    parser.add_argument("--dry-run", action="store_true", help="Print normalized payload without sending it.")
    args, extra = parser.parse_known_args(list(argv if argv is not None else sys.argv[1:]))
    if extra:
        write_log(provider, "debug", "Ignored extra SIEM arguments.", extra_args=" ".join(extra[:8]))

    api_key = validate_api_key(args.api_key or os.environ.get("ASTORASOC_API_KEY", ""))
    webhook_url = validate_url(args.webhook_url or os.environ.get("ASTORASOC_WEBHOOK_URL", ""))
    timeout = max(1, min(int(args.timeout), 60))
    payload = build_payload(provider, load_json(args.input), aliases)

    if args.dry_run:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n")
        write_log(provider, "info", "Dry run completed.", event_id=payload["event"].get("id"))
        return 0

    result = post_json(webhook_url, api_key, payload, timeout)
    response = result.get("response") if isinstance(result.get("response"), dict) else {}
    write_log(
        provider,
        "info",
        "Alert forwarded to AstoraSOC.",
        event_id=payload["event"].get("id"),
        http_status=result.get("status"),
        astorasoc_alert_id=response.get("alert_id"),
        duplicate=response.get("duplicate"),
    )
    return 0
