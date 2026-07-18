#!/usr/bin/env python3
"""Wazuh custom integration bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("id", "event_id", "rule.id"),
    "timestamp": ("timestamp",),
    "title": ("title", "rule.description", "alert_title"),
    "description": ("full_log", "rule.description", "title"),
    "severity": ("rule.level", "severity", "data.severity"),
    "rule_id": ("rule.id", "rule_id"),
    "affected_host": ("agent.name", "data.host", "affected_host"),
    "affected_user": ("data.srcuser", "data.user", "username"),
    "source_ip": ("data.srcip", "source_ip", "srcip"),
    "destination_ip": ("data.dstip", "destination_ip", "dstip"),
    "mitre_tactic": ("rule.mitre.tactic", "rule.mitre.tactics", "data.mitre.tactic"),
    "mitre_technique": ("rule.mitre.technique", "rule.mitre.techniques", "data.mitre.technique"),
    "category": ("rule.groups", "decoder.name"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Wazuh", ALIASES))
    except IntegrationError as exc:
        write_log("Wazuh", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Wazuh", "critical", "Unhandled AstoraSOC Wazuh integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
