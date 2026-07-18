# Splunk to AstoraSOC

Use this integration for Splunk Enterprise or Splunk Enterprise Security notable events.

## Files

- `astorasoc_splunk.py` - scripted alert bridge.

## Recommended Method: Scripted Alert Action

1. Copy `astorasoc_splunk.py` and the `../common` folder to a Splunk search head app directory, for example:

   ```text
   $SPLUNK_HOME/etc/apps/astorasoc/bin/
   ```

2. Store `ASTORASOC_API_KEY` and `ASTORASOC_WEBHOOK_URL` in a restricted environment or scripted alert wrapper.

3. Create a saved search or correlation search that returns useful fields:

   ```spl
   index=* (risk_score>=70 OR severity=high)
   | table _time host user src_ip dest_ip signature signature_id severity _raw
   ```

4. Configure an alert action that writes the result JSON and calls:

   ```bash
   python3 astorasoc_splunk.py result.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

5. Confirm the alert appears in AstoraSOC Alerts.

## Direct Webhook Alternative

If your Splunk version can send custom webhook payloads, POST the standard AstoraSOC payload directly and include `X-API-Key`.

## Field Mapping

Splunk fields commonly mapped: `_time`, `_raw`, `host`, `user`, `src_ip`, `dest_ip`, `signature`, `signature_id`, `risk_score`, `severity`, and MITRE annotation fields.
