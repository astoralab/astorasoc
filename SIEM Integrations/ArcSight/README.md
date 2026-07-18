# ArcSight to AstoraSOC

Use this integration with ArcSight ESM notifications, command actions, or SOAR relay.

## Files

- `astorasoc_arcsight.py` - ArcSight event JSON bridge.

## Steps

1. Create an ArcSight notification or rule action for high-value correlated events.
2. Export event fields as JSON to a script action host.
3. Copy `astorasoc_arcsight.py` and `../common` to that host.
4. Configure secure environment variables:

   ```bash
   export ASTORASOC_API_KEY="replace-with-key"
   export ASTORASOC_WEBHOOK_URL="https://astorasoc.example.com/api/webhook/alert"
   ```

5. Run the bridge:

   ```bash
   python3 astorasoc_arcsight.py arcsight-event.json
   ```

6. Confirm AstoraSOC receives the normalized event.

## Field Mapping

Common ArcSight fields: `eventId`, `name`, `message`, `severity`, `priority`, `ruleId`, `sourceAddress`, `destinationAddress`, `sourceUserName`, `destinationUserName`.
