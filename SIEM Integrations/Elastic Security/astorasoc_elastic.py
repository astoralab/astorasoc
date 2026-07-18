#!/usr/bin/env python3
"""Elastic Security connector bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("kibana.alert.uuid", "_id", "event.id"),
    "timestamp": ("@timestamp", "kibana.alert.start", "event.created"),
    "title": ("kibana.alert.rule.name", "rule.name", "message"),
    "description": ("message", "event.original", "kibana.alert.reason"),
    "severity": ("kibana.alert.severity", "event.severity", "rule.severity"),
    "rule_id": ("kibana.alert.rule.uuid", "rule.id"),
    "affected_host": ("host.name", "agent.name", "observer.hostname"),
    "affected_user": ("user.name", "source.user.name", "destination.user.name"),
    "source_ip": ("source.ip", "client.ip"),
    "destination_ip": ("destination.ip", "server.ip"),
    "mitre_tactic": ("kibana.alert.rule.threat.tactic.name", "threat.tactic.name"),
    "mitre_technique": ("kibana.alert.rule.threat.technique.name", "threat.technique.name"),
    "category": ("event.category", "event.dataset"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Elastic Security", ALIASES))
    except IntegrationError as exc:
        write_log("Elastic Security", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Elastic Security", "critical", "Unhandled AstoraSOC Elastic integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
