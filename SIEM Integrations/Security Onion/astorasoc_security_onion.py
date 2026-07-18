#!/usr/bin/env python3
"""Security Onion alert bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("event.id", "_id", "alert.id"),
    "timestamp": ("@timestamp", "timestamp", "event.created"),
    "title": ("rule.name", "alert.signature", "message"),
    "description": ("message", "event.original", "alert.metadata"),
    "severity": ("event.severity", "alert.severity", "rule.severity"),
    "rule_id": ("rule.id", "alert.signature_id"),
    "affected_host": ("host.name", "agent.name", "observer.name"),
    "affected_user": ("user.name", "source.user.name"),
    "source_ip": ("source.ip", "src_ip"),
    "destination_ip": ("destination.ip", "dest_ip"),
    "mitre_tactic": ("threat.tactic.name", "rule.threat.tactic.name"),
    "mitre_technique": ("threat.technique.name", "rule.threat.technique.name"),
    "category": ("event.category", "event.module", "event.dataset"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Security Onion", ALIASES))
    except IntegrationError as exc:
        write_log("Security Onion", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Security Onion", "critical", "Unhandled AstoraSOC Security Onion integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
