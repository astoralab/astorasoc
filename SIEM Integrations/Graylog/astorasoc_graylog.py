#!/usr/bin/env python3
"""Graylog event notification bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("event.id", "event_definition_id", "id"),
    "timestamp": ("event.timestamp", "timestamp"),
    "title": ("event.message", "event_definition_title", "title"),
    "description": ("event.message", "backlog.0.message", "description"),
    "severity": ("event.priority", "event.severity", "priority"),
    "rule_id": ("event_definition_id", "event.key_tuple.rule_id"),
    "affected_host": ("event.source", "backlog.0.source", "host"),
    "affected_user": ("event.fields.user", "username", "user"),
    "source_ip": ("event.fields.src_ip", "source_ip", "src_ip"),
    "destination_ip": ("event.fields.dst_ip", "destination_ip", "dst_ip"),
    "mitre_tactic": ("event.fields.mitre_tactic",),
    "mitre_technique": ("event.fields.mitre_technique",),
    "category": ("event_definition_type", "event.fields.category"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Graylog", ALIASES))
    except IntegrationError as exc:
        write_log("Graylog", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Graylog", "critical", "Unhandled AstoraSOC Graylog integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
