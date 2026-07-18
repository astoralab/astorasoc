# Microsoft Sentinel to AstoraSOC

Use this integration with Sentinel automation rules and Logic Apps.

## Files

- `astorasoc_sentinel.py` - optional relay script when a Logic App calls a bridge host.

## Recommended Method: Logic App Webhook

1. Generate the AstoraSOC webhook API key in Admin Settings.
2. Create a Sentinel automation rule for incident creation or alert creation.
3. Attach a Logic App playbook.
4. In the Logic App, add an HTTP action:

   ```text
   Method: POST
   URI: https://astorasoc.example.com/api/webhook/alert
   Header: X-API-Key: <AstoraSOC key>
   Header: Content-Type: application/json
   ```

5. Map Sentinel incident fields into the AstoraSOC standard payload.
6. Include the original Sentinel incident JSON as `raw_alert`.
7. Save, run a test incident, and verify AstoraSOC receives it.

## Bridge Script Option

Use `astorasoc_sentinel.py` when Sentinel sends to an intermediate Linux host or automation worker.

```bash
python3 astorasoc_sentinel.py sentinel-incident.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
```

## Field Mapping

Common Sentinel fields: `IncidentNumber`, `Title`, `Description`, `Severity`, `CreatedTimeUtc`, `AlertRuleId`, `Tactics`, `Techniques`, `CompromisedEntity`, `Entities`.
