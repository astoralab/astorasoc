# FortiSIEM to AstoraSOC

Use this integration for FortiSIEM incidents and notification actions.

## Files

- `astorasoc_fortisiem.py` - FortiSIEM incident bridge.

## Steps

1. Create a FortiSIEM incident notification policy.
2. Export incident fields to JSON through a script or HTTP relay.
3. Copy `astorasoc_fortisiem.py` and `../common` to the relay host.
4. Run:

   ```bash
   python3 astorasoc_fortisiem.py fortisiem-incident.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

5. Verify AstoraSOC receives the incident under Alerts.

## Field Mapping

Common FortiSIEM fields: `incidentId`, `incidentName`, `incidentSeverity`, `ruleId`, `srcIpAddr`, `destIpAddr`, `targetHostName`, `user`, `rawEventMsg`.
