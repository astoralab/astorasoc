#!/usr/bin/env python3
"""LogRhythm alarm bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("alarmId", "AlarmID", "eventId", "id"),
    "timestamp": ("alarmDate", "eventDate", "timestamp"),
    "title": ("alarmName", "name", "ruleName"),
    "description": ("summary", "description", "message"),
    "severity": ("risk", "priority", "severity"),
    "rule_id": ("ruleId", "knowledgeBaseId", "alarmRuleId"),
    "affected_host": ("hostName", "impactedHost", "destinationHost"),
    "affected_user": ("userName", "account", "login"),
    "source_ip": ("sourceIp", "srcIp"),
    "destination_ip": ("destinationIp", "dstIp"),
    "mitre_tactic": ("mitreTactic",),
    "mitre_technique": ("mitreTechnique",),
    "category": ("classification", "category"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("LogRhythm", ALIASES))
    except IntegrationError as exc:
        write_log("LogRhythm", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("LogRhythm", "critical", "Unhandled AstoraSOC LogRhythm integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
