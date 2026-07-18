# AstoraSOC SIEM Integrations

AstoraSOC accepts security detections from SIEM, SOAR, EDR, NDR, and custom monitoring tools through the same protected webhook:

```text
POST /api/webhook/alert
Header: X-API-Key: <AstoraSOC webhook API key>
Content-Type: application/json
```

This folder contains lightweight, production-oriented bridge scripts for common platforms. The scripts use only Python built-in libraries, so they work in locked-down servers, appliances, and containers without installing `requests` or other packages.

## Included Connectors

| Platform | Folder | Typical method |
| --- | --- | --- |
| Wazuh | `Wazuh` | Custom integration script |
| Splunk / Splunk ES | `Splunk` | Alert action, scripted alert, or webhook relay |
| Microsoft Sentinel | `Microsoft Sentinel` | Logic App / automation rule |
| Elastic Security | `Elastic Security` | Rule action / webhook connector relay |
| LogRhythm | `LogRhythm` | Alarm action or SmartResponse relay |
| ArcSight | `ArcSight` | ESM notification or script action |
| AlienVault OSSIM | `AlienVault OSSIM` | Alarm action / script relay |
| Chronicle / Google SecOps | `Chronicle` | Detection export / SOAR relay |
| FortiSIEM | `FortiSIEM` | Incident notification action |
| Graylog | `Graylog` | Event notification HTTP/script action |
| Security Onion | `Security Onion` | ElastAlert/Sigma/action relay |

## Standard Payload

All bridge scripts normalize source events into this AstoraSOC-friendly shape:

```json
{
  "schema_version": "1.0",
  "integration": "Splunk",
  "source": "Splunk",
  "event": {
    "provider": "splunk",
    "id": "unique-event-id",
    "timestamp": "2026-06-11T10:30:00Z",
    "category": "security_alert"
  },
  "title": "Suspicious authentication activity",
  "description": "Human-readable alert detail or raw event summary",
  "severity": "High",
  "rule_id": "rule-123",
  "affected_host": "host01",
  "affected_user": "user@example.com",
  "source_ip": "10.0.0.15",
  "destination_ip": "10.0.0.20",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "Account Manipulation",
  "raw_alert": {}
}
```

Missing fields are allowed. AstoraSOC will display unavailable values cleanly instead of inventing data.

## Security Checklist

1. Generate the webhook API key in AstoraSOC Admin Settings.
2. Store the key in the SIEM secret manager, environment variable, or restricted config file.
3. Never hardcode the key in a dashboard, report, or public script.
4. Restrict outbound access from the SIEM to the AstoraSOC host and port.
5. Prefer HTTPS in production.
6. Keep the raw alert in `raw_alert` for forensic review.
7. Test with `--dry-run` before enabling production forwarding.
8. Monitor each SIEM's action logs and `astorasoc-integration.log`.

## Common Environment Variables

```bash
export ASTORASOC_API_KEY="replace-with-generated-key"
export ASTORASOC_WEBHOOK_URL="https://astorasoc.example.com/api/webhook/alert"
export ASTORASOC_TIMEOUT="10"
export ASTORASOC_INTEGRATION_LOG="/var/log/astorasoc-integration.log"
```

Every provider script can also receive positional arguments:

```bash
python astorasoc_<provider>.py alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
```

Use stdin when a platform can pipe JSON:

```bash
cat alert.json | python astorasoc_<provider>.py - "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
```

## Validation Test

From any integration host:

```bash
python astorasoc_<provider>.py sample-alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL" --dry-run
python astorasoc_<provider>.py sample-alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
```

Expected result:

- HTTP `201` from AstoraSOC.
- Alert appears in the Alerts page.
- Duplicate event IDs are not repeatedly inserted.
- `raw_alert` remains available in alert details.

## Provider Notes

Each provider folder contains:

- A dependency-free Python bridge script.
- A step-by-step README.
- Field mapping notes for that SIEM.

If a SIEM can send webhooks directly, you may skip the Python script and POST the standard payload to AstoraSOC. Use the scripts when the source cannot shape payloads cleanly or when you want local logging and normalization.
