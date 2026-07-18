#!/usr/bin/env python3
"""Google SecOps / Chronicle detection bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("detection.id", "id", "ruleId"),
    "timestamp": ("detectionTime", "eventTimestamp", "timestamp"),
    "title": ("ruleName", "detection.ruleName", "alertName"),
    "description": ("summary", "description", "event.metadata.description"),
    "severity": ("severity", "riskScore", "priority"),
    "rule_id": ("ruleId", "rule.id"),
    "affected_host": ("principal.hostname", "target.hostname", "hostname"),
    "affected_user": ("principal.user.userid", "target.user.userid", "username"),
    "source_ip": ("principal.ip", "src_ip", "source_ip"),
    "destination_ip": ("target.ip", "dest_ip", "destination_ip"),
    "mitre_tactic": ("mitreTactic", "rule.mitreTactic"),
    "mitre_technique": ("mitreTechnique", "rule.mitreTechnique"),
    "category": ("metadata.event_type", "eventType"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Chronicle", ALIASES))
    except IntegrationError as exc:
        write_log("Chronicle", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Chronicle", "critical", "Unhandled AstoraSOC Chronicle integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
