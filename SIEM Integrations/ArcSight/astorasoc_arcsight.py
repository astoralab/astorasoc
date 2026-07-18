#!/usr/bin/env python3
"""ArcSight ESM notification bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("eventId", "baseEventId", "id"),
    "timestamp": ("startTime", "deviceReceiptTime", "endTime"),
    "title": ("name", "ruleName", "message"),
    "description": ("message", "deviceCustomString1", "description"),
    "severity": ("severity", "priority", "agentSeverity"),
    "rule_id": ("ruleId", "correlationEventId", "deviceEventClassId"),
    "affected_host": ("destinationHostName", "deviceHostName", "hostName"),
    "affected_user": ("destinationUserName", "sourceUserName", "userName"),
    "source_ip": ("sourceAddress", "sourceTranslatedAddress"),
    "destination_ip": ("destinationAddress", "destinationTranslatedAddress"),
    "mitre_tactic": ("mitreTactic",),
    "mitre_technique": ("mitreTechnique",),
    "category": ("categoryOutcome", "categoryBehavior", "categoryDeviceGroup"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("ArcSight", ALIASES))
    except IntegrationError as exc:
        write_log("ArcSight", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("ArcSight", "critical", "Unhandled AstoraSOC ArcSight integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
