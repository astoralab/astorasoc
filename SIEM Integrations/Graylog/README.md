# Graylog to AstoraSOC

Use this integration with Graylog event notifications.

## Files

- `astorasoc_graylog.py` - Graylog event bridge.

## Recommended Method: Event Notification

1. Create an Event Definition in Graylog.
2. Add an HTTP notification or script notification.
3. If using HTTP, POST the AstoraSOC standard payload directly with `X-API-Key`.
4. If using the script, pass Graylog event JSON to:

   ```bash
   python3 astorasoc_graylog.py graylog-event.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

5. Verify the event appears in AstoraSOC.

## Field Mapping

Common Graylog fields: `event.id`, `event.timestamp`, `event.message`, `event.priority`, `event.source`, `event.fields.*`, `backlog.0.message`.
