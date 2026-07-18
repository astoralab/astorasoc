# Chronicle / Google SecOps to AstoraSOC

Use this integration for Chronicle detections, Google SecOps cases, or SOAR relay workflows.

## Files

- `astorasoc_chronicle.py` - Chronicle detection bridge.

## Steps

1. Create a Chronicle detection export, webhook workflow, or SOAR playbook action.
2. Send detection JSON to a bridge host or directly to AstoraSOC.
3. If using the bridge, copy `astorasoc_chronicle.py` and `../common`.
4. Run:

   ```bash
   python3 astorasoc_chronicle.py chronicle-detection.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

5. Confirm AstoraSOC shows the alert and preserves the raw detection.

## Field Mapping

Common Chronicle fields: `detection.id`, `ruleName`, `ruleId`, `detectionTime`, `severity`, `principal.*`, `target.*`, `metadata.event_type`, MITRE fields.
