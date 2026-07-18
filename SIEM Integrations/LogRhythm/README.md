# LogRhythm to AstoraSOC

Use this integration for LogRhythm alarms or SmartResponse workflows.

## Files

- `astorasoc_logrhythm.py` - alarm JSON bridge.

## Steps

1. Create or select a LogRhythm alarm rule.
2. Configure an alarm action or SmartResponse to export alarm fields as JSON.
3. Place `astorasoc_logrhythm.py` and `../common` on the action host.
4. Store `ASTORASOC_API_KEY` and `ASTORASOC_WEBHOOK_URL` securely.
5. Execute:

   ```bash
   python3 astorasoc_logrhythm.py logrhythm-alarm.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

6. Verify the alert in AstoraSOC and review the preserved `raw_alert`.

## Field Mapping

Common LogRhythm fields: `alarmId`, `alarmName`, `alarmDate`, `risk`, `priority`, `ruleId`, `hostName`, `userName`, `sourceIp`, `destinationIp`.
