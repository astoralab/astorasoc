# Security Onion to AstoraSOC

Use this integration with Security Onion alerts, Elastic-backed detections, Suricata, Zeek, Sigma, or ElastAlert-style workflows.

## Files

- `astorasoc_security_onion.py` - Security Onion alert bridge.

## Steps

1. Identify the Security Onion alert source you want to forward, such as Suricata, Zeek, Sigma, or Elastic detection rules.
2. Configure a webhook/action relay or export the alert JSON to a script host.
3. Copy `astorasoc_security_onion.py` and `../common` to the host.
4. Run:

   ```bash
   python3 astorasoc_security_onion.py security-onion-alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
   ```

5. Confirm AstoraSOC receives the detection and preserves `raw_alert`.

## Field Mapping

Common Security Onion fields: `@timestamp`, `event.id`, `rule.name`, `alert.signature`, `event.severity`, `host.name`, `source.ip`, `destination.ip`, `user.name`, `event.original`.
