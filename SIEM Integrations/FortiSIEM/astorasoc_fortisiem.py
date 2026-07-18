#!/usr/bin/env python3
"""FortiSIEM incident bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("incidentId", "eventId", "id"),
    "timestamp": ("firstSeen", "lastSeen", "timestamp"),
    "title": ("incidentName", "ruleName", "name"),
    "description": ("incidentDetail", "description", "rawEventMsg"),
    "severity": ("severity", "incidentSeverity", "riskScore"),
    "rule_id": ("ruleId", "incidentType"),
    "affected_host": ("targetHostName", "hostName", "deviceName"),
    "affected_user": ("user", "userName"),
    "source_ip": ("srcIpAddr", "sourceIp", "src_ip"),
    "destination_ip": ("destIpAddr", "destinationIp", "dst_ip"),
    "mitre_tactic": ("mitreTactic",),
    "mitre_technique": ("mitreTechnique",),
    "category": ("eventType", "incidentCategory"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("FortiSIEM", ALIASES))
    except IntegrationError as exc:
        write_log("FortiSIEM", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("FortiSIEM", "critical", "Unhandled AstoraSOC FortiSIEM integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
