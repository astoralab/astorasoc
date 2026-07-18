#!/usr/bin/env python3
"""Microsoft Sentinel Logic App bridge for AstoraSOC."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from astorasoc_webhook import IntegrationError, run_provider_bridge, write_log


ALIASES = {
    "event_id": ("IncidentNumber", "incidentNumber", "id", "properties.incidentNumber"),
    "timestamp": ("CreatedTimeUtc", "createdTimeUtc", "properties.createdTimeUtc"),
    "title": ("Title", "title", "properties.title", "AlertName"),
    "description": ("Description", "description", "properties.description"),
    "severity": ("Severity", "severity", "properties.severity"),
    "rule_id": ("AlertRuleId", "properties.alertRuleId", "AnalyticsRuleId"),
    "affected_host": ("CompromisedEntity", "Entities.HostName", "HostName"),
    "affected_user": ("Account", "UserPrincipalName", "Entities.AccountName"),
    "source_ip": ("SourceIP", "IPAddress", "Entities.Address"),
    "destination_ip": ("DestinationIP", "DestinationIPAddress"),
    "mitre_tactic": ("Tactics", "properties.tactics"),
    "mitre_technique": ("Techniques", "properties.techniques"),
    "category": ("ProviderName", "ProductName"),
}


if __name__ == "__main__":
    try:
        raise SystemExit(run_provider_bridge("Microsoft Sentinel", ALIASES))
    except IntegrationError as exc:
        write_log("Microsoft Sentinel", "error", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        write_log("Microsoft Sentinel", "critical", "Unhandled AstoraSOC Sentinel integration failure.", error=str(exc), traceback=traceback.format_exc(limit=6))
        raise SystemExit(2)
