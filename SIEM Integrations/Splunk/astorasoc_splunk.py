#!/usr/bin/env python3
"""Splunk alert action bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("sid", "rid", "result._cd", "result.event_id", "event_id"),
    "timestamp": ("result._time", "_time", "timestamp"),
    "title": ("search_name", "result.signature", "result.rule_name", "title"),
    "description": ("result._raw", "result.description", "description"),
    "severity": ("result.severity", "result.risk_score", "severity"),
    "rule_id": ("result.rule_id", "result.signature_id", "search_name"),
    "affected_host": ("result.dest", "result.host", "result.computer", "host"),
    "affected_user": ("result.user", "result.src_user", "result.Account_Name"),
    "source_ip": ("result.src_ip", "result.src", "src_ip"),
    "destination_ip": ("result.dest_ip", "result.dest", "dest_ip"),
    "mitre_tactic": ("result.mitre_tactic", "result.annotations.mitre_attack.mitre_tactic"),
    "mitre_technique": ("result.mitre_technique", "result.annotations.mitre_attack.mitre_technique"),
    "category": ("result.category", "result.sourcetype"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Splunk", ALIASES))
    except IntegrationError as exc:
        write_log("Splunk", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Splunk", "critical", "Unhandled AstoraSOC Splunk integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
