# AlienVault OSSIM to AstoraSOC

Use this integration for OSSIM alarms and correlated events.

## Files

- `astorasoc_ossim.py` - OSSIM alarm bridge.

## Steps

1. Configure an OSSIM alarm action or external script action.
2. Export alarm fields as JSON, including source IP, destination IP, plugin SID, risk, asset, user, and raw log when available.
3. Copy `astorasoc_ossim.py` and `../common` to the action host.
4. Set the AstoraSOC key and webhook URL.
5. Run:

   ```bash
   python3 astorasoc_ossim.py ossim-alarm.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

6. Verify the alert appears in AstoraSOC.

## Field Mapping

Common OSSIM fields: `alarm_id`, `plugin_sid`, `plugin_sid_name`, `risk`, `src_ip`, `dst_ip`, `username`, `asset`, `raw_log`.
