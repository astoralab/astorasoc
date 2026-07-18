#!/usr/bin/env python3
"""AlienVault OSSIM alarm bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("alarm_id", "event_id", "uuid", "id"),
    "timestamp": ("timestamp", "date", "created"),
    "title": ("alarm_name", "plugin_sid_name", "name", "title"),
    "description": ("description", "message", "raw_log"),
    "severity": ("risk", "priority", "severity"),
    "rule_id": ("plugin_sid", "plugin_id", "rule_id"),
    "affected_host": ("dst_hostname", "hostname", "asset"),
    "affected_user": ("username", "user"),
    "source_ip": ("src_ip", "source_ip"),
    "destination_ip": ("dst_ip", "destination_ip"),
    "mitre_tactic": ("mitre_tactic",),
    "mitre_technique": ("mitre_technique",),
    "category": ("category", "taxonomy"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("AlienVault OSSIM", ALIASES))
    except IntegrationError as exc:
        write_log("AlienVault OSSIM", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("AlienVault OSSIM", "critical", "Unhandled AstoraSOC OSSIM integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
